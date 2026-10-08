/* cxpy: CPython 3.13 (wasm32-wasi, stdlib packed with wasi-vfs) behind the common
 * launcher (SPEC-v2 15.4). Determinism knobs: use_hash_seed=1, hash_seed=0, isolated=1,
 * site_import=0, buffered_stdio=0, no environment, no bytecode writes, utf-8 mode.
 * Module search path: /lib (job fs, when mounted) then the packed stdlib.
 * bootstrap.py (embedded at build time as bootstrap.inc) does the rest.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "launcher.h"

/* Stdlib locations inside the module (wasi-vfs); a native test build overrides this. */
#ifndef CX_STDLIB_PATHS
#define CX_STDLIB_PATHS L"/usr/local/lib/python3.13"
#endif

static const wchar_t *const stdlib_paths[] = {CX_STDLIB_PATHS};

static const char bootstrap[] =
#include "bootstrap.inc"
    ;

static int die(const char *what, PyStatus st)
{
	fputs("err python init: ", stdout);
	fputs(what, stdout);
	if (st.err_msg) {
		fputs(": ", stdout);
		fputs(st.err_msg, stdout);
	}
	fputc('\n', stdout);
	fflush(stdout);
	return 1;
}

int main(void)
{
	cx_input in;
	if (cx_read_input(&in))
		return 1;

	PyPreConfig pre;
	PyPreConfig_InitIsolatedConfig(&pre);
	pre.utf8_mode = 1;
	pre.use_environment = 0;
	PyStatus st = Py_PreInitialize(&pre);
	if (PyStatus_Exception(st))
		return die("preinit", st);

	PyConfig cfg;
	PyConfig_InitIsolatedConfig(&cfg);
	cfg.isolated = 1;
	cfg.use_environment = 0;
	cfg.site_import = 0;
	cfg.use_hash_seed = 1;
	cfg.hash_seed = 0;
	cfg.buffered_stdio = 0;
	cfg.write_bytecode = 0;
	cfg.parse_argv = 0;
	cfg.install_signal_handlers = 0;
	cfg.user_site_directory = 0;
	cfg.faulthandler = 0;
	cfg.pathconfig_warnings = 0;
#if PY_VERSION_HEX >= 0x030B0000
	cfg.safe_path = 1;
#endif
	cfg.module_search_paths_set = 1;
	st = PyWideStringList_Append(&cfg.module_search_paths, L"" CX_LIB_DIR);
	for (size_t i = 0; i < sizeof stdlib_paths / sizeof *stdlib_paths && !PyStatus_Exception(st); i++)
		st = PyWideStringList_Append(&cfg.module_search_paths, stdlib_paths[i]);
	if (!PyStatus_Exception(st))
		st = PyConfig_SetBytesString(&cfg, &cfg.program_name, "cxpy");
	if (!PyStatus_Exception(st))
		st = PyConfig_SetBytesString(&cfg, &cfg.stdio_encoding, "utf-8");
	if (!PyStatus_Exception(st))
		st = PyConfig_SetBytesString(&cfg, &cfg.stdio_errors, "surrogateescape");
	if (PyStatus_Exception(st)) {
		PyConfig_Clear(&cfg);
		return die("config", st);
	}
	st = Py_InitializeFromConfig(&cfg);
	PyConfig_Clear(&cfg);
	if (PyStatus_Exception(st))
		return die("initialize", st);

	int rc = 1;
	PyObject *g = PyDict_New();
	PyObject *code = PyUnicode_DecodeUTF8(in.code, (Py_ssize_t)in.code_len, "surrogateescape");
	PyObject *sin = PyBytes_FromStringAndSize(in.in, (Py_ssize_t)in.in_len);
	PyObject *argv = PyList_New(in.argc);
	if (!g || !code || !sin || !argv)
		goto fatal;
	for (int i = 0; i < in.argc; i++) {
		PyObject *a = PyUnicode_DecodeUTF8(in.argv[i], (Py_ssize_t)strlen(in.argv[i]), "surrogateescape");
		if (!a)
			goto fatal;
		PyList_SET_ITEM(argv, i, a);
	}
	if (PyDict_SetItemString(g, "__builtins__", PyEval_GetBuiltins()) || PyDict_SetItemString(g, "__cx_code", code) ||
	    PyDict_SetItemString(g, "__cx_stdin", sin) || PyDict_SetItemString(g, "__cx_argv", argv))
		goto fatal;
	PyObject *r = PyRun_String(bootstrap, Py_file_input, g, g);
	if (!r) {
		/* the bootstrap itself failed (should not happen): show why on stdout */
		PyObject *t, *v, *tb;
		PyErr_Fetch(&t, &v, &tb);
		PyObject *s = v ? PyObject_Str(v) : NULL;
		fputs("err bootstrap: ", stdout);
		fputs(s && PyUnicode_Check(s) ? PyUnicode_AsUTF8(s) : "unknown", stdout);
		fputc('\n', stdout);
		Py_XDECREF(s);
		Py_XDECREF(t);
		Py_XDECREF(v);
		Py_XDECREF(tb);
		goto out;
	}
	Py_DECREF(r);
	PyObject *rco = PyDict_GetItemString(g, "__cx_rc");
	rc = rco && PyLong_Check(rco) ? (int)PyLong_AsLong(rco) : 1;
	goto out;
fatal:
	fputs("err launcher: out of memory\n", stdout);
out:
	Py_XDECREF(g);
	Py_XDECREF(code);
	Py_XDECREF(sin);
	Py_XDECREF(argv);
	fflush(stdout);
	Py_FinalizeEx();
	cx_free_input(&in);
	return rc;
}
