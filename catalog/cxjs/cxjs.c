/* cxjs: quickjs-ng behind the common launcher (SPEC-v2 15.4).
 *
 * Globals offered to the program: print(...), console.{log,info,debug,warn,error}(...)
 * (all on stdout), stdin (string), readline() (next stdin line or null), scriptArgs
 * (["<code>", ...argv]), exit(code). ES modules: `import` resolves under /lib when a job
 * fs is mounted. Uncaught error: "Uncaught <error>" + stack on stdout, exit 1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quickjs.h"
#include "launcher.h"

static cx_input in;
static size_t stdin_pos;

/* Unhandled promise rejections, reported at exit like an uncaught error. */
typedef struct rej {
	JSValue promise, reason;
	struct rej *next;
} rej;
static rej *rejections;

static void track_rejection(JSContext *ctx, JSValueConst promise, JSValueConst reason, bool is_handled, void *opaque)
{
	(void)opaque;
	void *key = JS_VALUE_GET_PTR(promise);
	for (rej **pp = &rejections; *pp; pp = &(*pp)->next) {
		if (JS_VALUE_GET_PTR((*pp)->promise) == key) {
			if (is_handled) {
				rej *r = *pp;
				*pp = r->next;
				JS_FreeValue(ctx, r->promise);
				JS_FreeValue(ctx, r->reason);
				free(r);
			}
			return;
		}
	}
	if (is_handled)
		return;
	rej *r = malloc(sizeof *r);
	if (!r)
		return;
	r->promise = JS_DupValue(ctx, promise);
	r->reason = JS_DupValue(ctx, reason);
	r->next = rejections;
	rejections = r;
}

/* Module heuristic: a line that starts with an import/export declaration. The engine's
 * JS_DetectModule accepts almost any script, and module semantics (strict mode) would
 * change sloppy programs, so the syntax must be visible in the source. */
static int looks_like_module(const char *s, size_t n)
{
	size_t i = 0;
	while (i < n) {
		while (i < n && (s[i] == ' ' || s[i] == '\t'))
			i++;
		if (n - i >= 6 && strncmp(s + i, "import", 6) == 0) {
			char c = i + 6 < n ? s[i + 6] : '\n';
			if (c == ' ' || c == '{' || c == '*' || c == '"' || c == '\'' || c == '\t')
				return 1;
		}
		if (n - i >= 6 && strncmp(s + i, "export", 6) == 0) {
			char c = i + 6 < n ? s[i + 6] : '\n';
			if (c == ' ' || c == '{' || c == '*' || c == '\t')
				return 1;
		}
		while (i < n && s[i] != '\n')
			i++;
		i++;
	}
	return 0;
}

static void dump_value(JSContext *ctx, JSValueConst v)
{
	const char *s = JS_ToCString(ctx, v);
	if (s) {
		fputs(s, stdout);
		JS_FreeCString(ctx, s);
	} else {
		fputs("[exception]", stdout);
	}
}

/* Compact traceback: the error's string form, then its stack (already indented). */
static void dump_error(JSContext *ctx)
{
	JSValue e = JS_GetException(ctx);
	fputs("Uncaught ", stdout);
	dump_value(ctx, e);
	fputc('\n', stdout);
	if (JS_IsError(e)) {
		JSValue st = JS_GetPropertyStr(ctx, e, "stack");
		if (!JS_IsUndefined(st) && !JS_IsException(st)) {
			const char *s = JS_ToCString(ctx, st);
			if (s && *s) {
				fputs(s, stdout);
				if (s[strlen(s) - 1] != '\n')
					fputc('\n', stdout);
			}
			if (s)
				JS_FreeCString(ctx, s);
		}
		JS_FreeValue(ctx, st);
	}
	JS_FreeValue(ctx, e);
}

static JSValue js_print(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
	(void)this_val;
	for (int i = 0; i < argc; i++) {
		if (i)
			fputc(' ', stdout);
		dump_value(ctx, argv[i]);
	}
	fputc('\n', stdout);
	return JS_UNDEFINED;
}

static JSValue js_readline(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
	(void)this_val;
	(void)argc;
	(void)argv;
	if (stdin_pos >= in.in_len)
		return JS_NULL;
	const char *p = in.in + stdin_pos;
	const char *nl = memchr(p, '\n', in.in_len - stdin_pos);
	size_t n = nl ? (size_t)(nl - p) : in.in_len - stdin_pos;
	stdin_pos += n + (nl ? 1 : 0);
	if (n && p[n - 1] == '\r')
		n--;
	return JS_NewStringLen(ctx, p, n);
}

static JSValue js_exit(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
	(void)this_val;
	int32_t code = 0;
	if (argc > 0 && JS_ToInt32(ctx, &code, argv[0]))
		code = 1;
	cx_exit(code);
	return JS_UNDEFINED;
}

static JSModuleDef *module_loader(JSContext *ctx, const char *name, void *opaque)
{
	(void)opaque;
	char path[1024];
	if (name[0] == '/')
		snprintf(path, sizeof path, "%s", name);
	else
		snprintf(path, sizeof path, "%s/%s", CX_LIB_DIR, name);
	size_t len;
	char *buf = cx_read_file(path, &len);
	if (!buf) {
		JS_ThrowReferenceError(ctx, "could not load module '%s' (import root is %s)", name, CX_LIB_DIR);
		return NULL;
	}
	JSValue v = JS_Eval(ctx, buf, len, name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
	free(buf);
	if (JS_IsException(v))
		return NULL;
	JSModuleDef *m = JS_VALUE_GET_PTR(v);
	JS_FreeValue(ctx, v);
	return m;
}

static void install_globals(JSContext *ctx)
{
	JSValue g = JS_GetGlobalObject(ctx);
	JSValue print = JS_NewCFunction(ctx, js_print, "print", 1);
	JS_SetPropertyStr(ctx, g, "print", JS_DupValue(ctx, print));
	JSValue console = JS_NewObject(ctx);
	static const char *const names[] = {"log", "info", "debug", "warn", "error", "trace"};
	for (size_t i = 0; i < sizeof names / sizeof *names; i++)
		JS_SetPropertyStr(ctx, console, names[i], JS_DupValue(ctx, print));
	JS_FreeValue(ctx, print);
	JS_SetPropertyStr(ctx, g, "console", console);
	JS_SetPropertyStr(ctx, g, "readline", JS_NewCFunction(ctx, js_readline, "readline", 0));
	JS_SetPropertyStr(ctx, g, "exit", JS_NewCFunction(ctx, js_exit, "exit", 1));
	JS_SetPropertyStr(ctx, g, "stdin", JS_NewStringLen(ctx, in.in, in.in_len));
	JSValue args = JS_NewArray(ctx);
	JS_SetPropertyUint32(ctx, args, 0, JS_NewString(ctx, CX_SCRIPT_NAME));
	for (int i = 0; i < in.argc; i++)
		JS_SetPropertyUint32(ctx, args, (uint32_t)i + 1, JS_NewString(ctx, in.argv[i]));
	JS_SetPropertyStr(ctx, g, "scriptArgs", args);
	JS_FreeValue(ctx, g);
}

int main(void)
{
	static char obuf[1 << 16];
	setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
	if (cx_read_input(&in))
		return 1;
	JSRuntime *rt = JS_NewRuntime();
	if (!rt) {
		fputs("err runtime\n", stdout);
		return 1;
	}
	JS_SetMaxStackSize(rt, 1 << 20);
	JS_SetModuleLoaderFunc(rt, NULL, module_loader, NULL);
	JS_SetHostPromiseRejectionTracker(rt, track_rejection, NULL);
	JSContext *ctx = JS_NewContext(rt);
	if (!ctx) {
		fputs("err context\n", stdout);
		return 1;
	}
	install_globals(ctx);

	int rc = 0;
	JSValue r;
	if (looks_like_module(in.code, in.code_len) && JS_DetectModule(in.code, in.code_len)) {
		/* module: compile, run, then settle its promise through the job queue */
		r = JS_Eval(ctx, in.code, in.code_len, CX_SCRIPT_NAME, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
		if (!JS_IsException(r))
			r = JS_EvalFunction(ctx, r);
	} else {
		r = JS_Eval(ctx, in.code, in.code_len, CX_SCRIPT_NAME, JS_EVAL_TYPE_GLOBAL);
	}
	if (JS_IsException(r)) {
		dump_error(ctx);
		rc = 1;
	}
	for (;;) { /* drain promise jobs so async code completes */
		JSContext *c1;
		int st = JS_ExecutePendingJob(rt, &c1);
		if (st < 0) {
			dump_error(c1);
			rc = 1;
		}
		if (st <= 0)
			break;
	}
	if (!rc && JS_PromiseState(ctx, r) == JS_PROMISE_REJECTED) { /* module body threw */
		JS_Throw(ctx, JS_PromiseResult(ctx, r));
		dump_error(ctx);
		rc = 1;
	}
	if (!JS_IsException(r))
		JS_FreeValue(ctx, r);
	if (!rc && rejections) {
		/* the oldest first: the list is LIFO */
		rej *list = NULL;
		while (rejections) {
			rej *x = rejections;
			rejections = x->next;
			x->next = list;
			list = x;
		}
		rejections = list;
		for (rej *x = rejections; x; x = x->next) {
			fputs("Uncaught (in promise) ", stdout);
			dump_value(ctx, x->reason);
			fputc('\n', stdout);
		}
		rc = 1;
	}
	for (rej *x = rejections; x;) {
		rej *n = x->next;
		JS_FreeValue(ctx, x->promise);
		JS_FreeValue(ctx, x->reason);
		free(x);
		x = n;
	}
	fflush(stdout);
	JS_FreeContext(ctx);
	JS_FreeRuntime(rt);
	cx_free_input(&in);
	return rc;
}
