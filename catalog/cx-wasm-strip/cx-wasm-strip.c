/* cx-wasm-strip: drops every custom section (names, producers, debug info) from a wasm
 * module read on stdin and writes the result on stdout. Same effect as wabt's wasm-strip,
 * written as a 60-line section walker so it has no library dependency; the Dockerfile builds
 * it in the wabt image for one pipeline. Errors go to stdout as `err ...`, exit 1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IN (64u << 20)

static int leb(const unsigned char *p, size_t n, size_t *pos, unsigned long long *v)
{
	unsigned shift = 0;
	*v = 0;
	while (*pos < n && shift < 64) {
		unsigned char b = p[(*pos)++];
		*v |= (unsigned long long)(b & 0x7f) << shift;
		if (!(b & 0x80))
			return 0;
		shift += 7;
	}
	return -1;
}

static int die(const char *msg)
{
	printf("err %s\n", msg);
	return 1;
}

int main(void)
{
	size_t cap = 1 << 16, n = 0;
	unsigned char *buf = malloc(cap);
	if (!buf)
		return die("out of memory");
	for (;;) {
		if (n == cap) {
			if (cap >= MAX_IN)
				return die("input over 64 MiB");
			cap *= 2;
			unsigned char *nb = realloc(buf, cap);
			if (!nb)
				return die("out of memory");
			buf = nb;
		}
		size_t r = fread(buf + n, 1, cap - n, stdin);
		if (r == 0)
			break;
		n += r;
	}
	if (n < 8 || memcmp(buf, "\0asm", 4) != 0)
		return die("not a wasm module (bad magic)");
	if (memcmp(buf + 4, "\1\0\0\0", 4) != 0)
		return die("unsupported wasm version");
	fwrite(buf, 1, 8, stdout);
	size_t pos = 8;
	while (pos < n) {
		size_t start = pos;
		unsigned char id = buf[pos++];
		unsigned long long size;
		if (leb(buf, n, &pos, &size) || size > n - pos)
			return die("truncated section");
		size_t end = pos + (size_t)size;
		if (id != 0)
			fwrite(buf + start, 1, end - start, stdout);
		pos = end;
	}
	fflush(stdout);
	free(buf);
	return 0;
}
