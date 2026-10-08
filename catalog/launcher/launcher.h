/* Common launcher framing for the catalog interpreters (SPEC-v2 15.4).
 *
 * The job input (fd 0) is either
 *   {"code": "...", "stdin": "...", "argv": ["..."]}   (first non-blank byte is '{')
 * or
 *   <code> NUL <stdin>                                  (no NUL: everything is code)
 * A '{' input that is not a valid framing object falls back to the NUL split so a
 * program that happens to start with a brace still runs.
 *
 * Interpreters print uncaught errors as a compact traceback on STDOUT and exit 1
 * (stderr is discarded by the sandbox). Nothing here is imported by Go code.
 */
#ifndef CX_LAUNCHER_H
#define CX_LAUNCHER_H

#include <stddef.h>

#define CX_INPUT_MAX (32u << 20) /* bytes of fd 0 accepted (jobs inputs are <= 16 MiB) */
#define CX_ARGV_MAX 256
#define CX_SCRIPT_NAME "<code>"
#define CX_LIB_DIR "/lib" /* job fs root (REV3 zip mount); import root when present */

typedef struct {
	char *code;
	size_t code_len;
	char *in; /* program stdin */
	size_t in_len;
	char *argv[CX_ARGV_MAX]; /* program arguments, argv[0] excluded */
	int argc;
	char *raw; /* backing buffer (owned) */
	size_t raw_len;
	int json; /* 1 when the JSON framing was used */
} cx_input;

/* Reads fd 0 fully and splits it. Returns 0, or -1 after printing `err ...` on stdout. */
int cx_read_input(cx_input *in);
void cx_free_input(cx_input *in);

/* 1 when CX_LIB_DIR exists (a job fs was mounted). */
int cx_lib_present(void);

/* Reads a whole file (for module loaders); NULL when missing. Caller frees. */
char *cx_read_file(const char *path, size_t *len);

/* Flushes stdout and exits; the one exit path interpreters use after output. */
void cx_exit(int code);

#endif
