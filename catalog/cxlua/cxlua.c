/* cxlua: Lua 5.4 behind the common launcher (SPEC-v2 15.4).
 *
 * The program sees the standard libraries; io.read / io.lines / io.stdin are redirected
 * to the framed stdin text; arg = {[0]="<code>", ...argv}; package.path points at /lib
 * when a job fs is mounted (no C modules). Uncaught error: message + "stack traceback:"
 * on stdout, exit 1. os.exit(n) exits with n.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "launcher.h"

static cx_input in;

/* Lua side of the stdin redirection: a reader object over one string. */
static const char prelude[] =
    "local data, pos = ..., 1\n"
    "local R = {}\n"
    "R.__index = R\n"
    "local function readfmt(fmt)\n"
    "  if pos > #data then if fmt == 'a' or fmt == '*a' then return '' end return nil end\n"
    "  if type(fmt) == 'number' then\n"
    "    local s = data:sub(pos, pos + fmt - 1); pos = pos + fmt; return s\n"
    "  end\n"
    "  fmt = tostring(fmt):gsub('^%*', '')\n"
    "  if fmt == 'a' then local s = data:sub(pos); pos = #data + 1; return s end\n"
    "  if fmt == 'n' then\n"
    "    local s, e, num = data:find('^%s*([%+%-]?%d+%.?%d*[eE]?[%+%-]?%d*)', pos)\n"
    "    if not s then return nil end\n"
    "    pos = e + 1; return tonumber(num)\n"
    "  end\n"
    "  local nl = data:find('\\n', pos, true)\n"
    "  local line\n"
    "  if nl then line = data:sub(pos, nl - 1); pos = nl + 1 else line = data:sub(pos); pos = #data + 1 end\n"
    "  if fmt == 'L' then return line .. (nl and '\\n' or '') end\n"
    "  return line\n"
    "end\n"
    "function R:read(...)\n"
    "  local n = select('#', ...)\n"
    "  if n == 0 then return readfmt('l') end\n"
    "  local out = {}\n"
    "  for i = 1, n do out[i] = readfmt((select(i, ...))) end\n"
    "  return table.unpack(out, 1, n)\n"
    "end\n"
    "function R:lines(fmt) return function() return readfmt(fmt or 'l') end end\n"
    "function R:close() return true end\n"
    "function R:seek() return pos - 1 end\n"
    "function R:setvbuf() return true end\n"
    "local stdin = setmetatable({}, R)\n"
    "local olines = io.lines\n"
    "io.stdin = stdin\n"
    "io.read = function(...) return stdin:read(...) end\n"
    "io.lines = function(f, ...) if f == nil then return stdin:lines(...) end return olines(f, ...) end\n"
    "local oinput = io.input\n"
    "io.input = function(f) if f == nil then return stdin end return oinput(f) end\n";

static int traceback(lua_State *L)
{
	const char *msg = lua_tostring(L, 1);
	if (!msg && !lua_isnoneornil(L, 1)) {
		if (luaL_callmeta(L, 1, "__tostring") && lua_type(L, -1) == LUA_TSTRING)
			return 1;
		msg = lua_pushfstring(L, "(error object is a %s value)", luaL_typename(L, 1));
	}
	luaL_traceback(L, L, msg, 1);
	return 1;
}

static void report(lua_State *L)
{
	const char *msg = lua_tostring(L, -1);
	fputs(msg ? msg : "(unknown error)", stdout);
	fputc('\n', stdout);
	lua_pop(L, 1);
}

int main(void)
{
	static char obuf[1 << 16];
	setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
	if (cx_read_input(&in))
		return 1;
	lua_State *L = luaL_newstate();
	if (!L) {
		fputs("err state\n", stdout);
		return 1;
	}
	luaL_openlibs(L);

	/* arg table */
	lua_createtable(L, in.argc, 1);
	lua_pushstring(L, CX_SCRIPT_NAME);
	lua_rawseti(L, -2, 0);
	for (int i = 0; i < in.argc; i++) {
		lua_pushstring(L, in.argv[i]);
		lua_rawseti(L, -2, i + 1);
	}
	lua_setglobal(L, "arg");

	/* module search path: only the job fs */
	lua_getglobal(L, "package");
	lua_pushstring(L, cx_lib_present() ? CX_LIB_DIR "/?.lua;" CX_LIB_DIR "/?/init.lua" : "");
	lua_setfield(L, -2, "path");
	lua_pushstring(L, "");
	lua_setfield(L, -2, "cpath");
	lua_pop(L, 1);

	if (luaL_loadbuffer(L, prelude, sizeof prelude - 1, "=cx") != LUA_OK) {
		report(L);
		return 1;
	}
	lua_pushlstring(L, in.in, in.in_len);
	if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
		report(L);
		return 1;
	}

	lua_pushcfunction(L, traceback);
	int base = lua_gettop(L);
	int rc = 0;
	if (luaL_loadbuffer(L, in.code, in.code_len, "=" CX_SCRIPT_NAME) != LUA_OK) {
		report(L); /* syntax error: "<code>:LINE: message" */
		rc = 1;
	} else {
		for (int i = 0; i < in.argc; i++)
			lua_pushstring(L, in.argv[i]);
		if (lua_pcall(L, in.argc, 0, base) != LUA_OK) {
			report(L);
			rc = 1;
		}
	}
	fflush(stdout);
	lua_close(L);
	cx_free_input(&in);
	return rc;
}
