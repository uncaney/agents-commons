/* Weak stubs for libc entry points Lua's os/io libraries reference but wasi-libc does not
 * provide (no processes, no temp files). Weak: if the sysroot does define one, libc wins.
 * Compiled only into the wasm32-wasi build (native test builds do not need it). */
#ifdef __wasi__
#include <errno.h>
#include <stddef.h>
#include <stdio.h>

__attribute__((weak)) int system(const char *cmd)
{
	(void)cmd;
	errno = ENOSYS;
	return -1;
}

__attribute__((weak)) char *tmpnam(char *s)
{
	(void)s;
	return NULL;
}

__attribute__((weak)) FILE *tmpfile(void)
{
	errno = ENOSYS;
	return NULL;
}
#else
typedef int cx_wasi_stubs_unused;
#endif
