/* See launcher.h. C99, no dependencies beyond libc; compiled into every interpreter module. */
#include "launcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void fail(const char *msg)
{
	fputs("err framing: ", stdout);
	fputs(msg, stdout);
	fputc('\n', stdout);
	fflush(stdout);
}

void cx_exit(int code)
{
	fflush(stdout);
	exit(code);
}

char *cx_read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return NULL;
	size_t cap = 1 << 16, n = 0;
	char *buf = malloc(cap + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	for (;;) {
		if (n == cap) {
			if (cap >= CX_INPUT_MAX) {
				free(buf);
				fclose(f);
				return NULL;
			}
			cap *= 2;
			char *nb = realloc(buf, cap + 1);
			if (!nb) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = nb;
		}
		size_t r = fread(buf + n, 1, cap - n, f);
		n += r;
		if (r == 0)
			break;
	}
	fclose(f);
	buf[n] = 0;
	if (len)
		*len = n;
	return buf;
}

int cx_lib_present(void)
{
	struct stat st;
	return stat(CX_LIB_DIR, &st) == 0 && S_ISDIR(st.st_mode);
}

/* --- minimal JSON reader: one object, string members code/stdin, string array argv --- */

typedef struct {
	const char *p, *end;
} js;

static void ws(js *s)
{
	while (s->p < s->end && (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r'))
		s->p++;
}

static int hex4(const char *p, unsigned *v)
{
	*v = 0;
	for (int i = 0; i < 4; i++) {
		char c = p[i];
		*v <<= 4;
		if (c >= '0' && c <= '9')
			*v |= (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			*v |= (unsigned)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			*v |= (unsigned)(c - 'A' + 10);
		else
			return -1;
	}
	return 0;
}

static size_t utf8(char *o, unsigned cp)
{
	if (cp < 0x80) {
		o[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		o[0] = (char)(0xC0 | (cp >> 6));
		o[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp < 0x10000) {
		o[0] = (char)(0xE0 | (cp >> 12));
		o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		o[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	o[0] = (char)(0xF0 | (cp >> 18));
	o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
	o[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
	o[3] = (char)(0x80 | (cp & 0x3F));
	return 4;
}

/* Parses a JSON string at s->p (on the opening quote). Decoded UTF-8 is written into a
 * fresh buffer (*out, *len); returns 0 or -1. The decoded form is never longer than the
 * encoded one, so the buffer is sized from the source span. */
static int str(js *s, char **out, size_t *len)
{
	if (s->p >= s->end || *s->p != '"')
		return -1;
	const char *q = s->p + 1;
	/* find the end quote to size the buffer */
	const char *e = q;
	while (e < s->end && *e != '"') {
		if (*e == '\\')
			e++;
		e++;
	}
	if (e >= s->end)
		return -1;
	char *o = malloc((size_t)(e - q) + 1), *w = o;
	if (!o)
		return -1;
	while (q < e) {
		unsigned char c = (unsigned char)*q++;
		if (c < 0x20)
			goto bad;
		if (c != '\\') {
			*w++ = (char)c;
			continue;
		}
		if (q >= e)
			goto bad;
		c = (unsigned char)*q++;
		switch (c) {
		case '"': *w++ = '"'; break;
		case '\\': *w++ = '\\'; break;
		case '/': *w++ = '/'; break;
		case 'b': *w++ = '\b'; break;
		case 'f': *w++ = '\f'; break;
		case 'n': *w++ = '\n'; break;
		case 'r': *w++ = '\r'; break;
		case 't': *w++ = '\t'; break;
		case 'u': {
			unsigned cp;
			if (e - q < 4 || hex4(q, &cp))
				goto bad;
			q += 4;
			if (cp >= 0xD800 && cp <= 0xDBFF) { /* high surrogate: need \uDC00-\uDFFF */
				unsigned lo;
				if (e - q < 6 || q[0] != '\\' || q[1] != 'u' || hex4(q + 2, &lo) || lo < 0xDC00 || lo > 0xDFFF)
					goto bad;
				q += 6;
				cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
			} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
				goto bad;
			}
			w += utf8(w, cp);
			break;
		}
		default:
			goto bad;
		}
	}
	*w = 0;
	*out = o;
	*len = (size_t)(w - o);
	s->p = e + 1;
	return 0;
bad:
	free(o);
	return -1;
}

/* Skips any JSON value (used for unknown members). */
static int skip(js *s)
{
	ws(s);
	if (s->p >= s->end)
		return -1;
	char c = *s->p;
	if (c == '"') {
		char *tmp;
		size_t n;
		if (str(s, &tmp, &n))
			return -1;
		free(tmp);
		return 0;
	}
	if (c == '{' || c == '[') {
		char close = c == '{' ? '}' : ']';
		s->p++;
		ws(s);
		if (s->p < s->end && *s->p == close) {
			s->p++;
			return 0;
		}
		for (;;) {
			if (c == '{') {
				ws(s);
				char *k;
				size_t n;
				if (str(s, &k, &n))
					return -1;
				free(k);
				ws(s);
				if (s->p >= s->end || *s->p++ != ':')
					return -1;
			}
			if (skip(s))
				return -1;
			ws(s);
			if (s->p >= s->end)
				return -1;
			if (*s->p == ',') {
				s->p++;
				continue;
			}
			if (*s->p == close) {
				s->p++;
				return 0;
			}
			return -1;
		}
	}
	/* literal or number: consume until a delimiter */
	const char *b = s->p;
	while (s->p < s->end && !strchr(",}] \t\r\n", *s->p))
		s->p++;
	return s->p > b ? 0 : -1;
}

/* Parses the framing object. On success fills in->code/in/argv (fresh buffers) and
 * returns 0; returns -1 on any syntax or type error without touching `in`. */
static int parse_framing(const char *buf, size_t len, cx_input *in)
{
	js s = {buf, buf + len};
	char *code = NULL, *stdin_s = NULL;
	size_t code_n = 0, stdin_n = 0;
	char *argv[CX_ARGV_MAX];
	int argc = 0, have_code = 0;
	ws(&s);
	if (s.p >= s.end || *s.p != '{')
		return -1;
	s.p++;
	ws(&s);
	if (s.p < s.end && *s.p == '}')
		goto done_obj;
	for (;;) {
		ws(&s);
		char *key;
		size_t kn;
		if (str(&s, &key, &kn))
			goto bad;
		ws(&s);
		if (s.p >= s.end || *s.p++ != ':') {
			free(key);
			goto bad;
		}
		ws(&s);
		if (strcmp(key, "code") == 0) {
			free(key);
			if (code)
				goto bad;
			if (str(&s, &code, &code_n))
				goto bad;
			have_code = 1;
		} else if (strcmp(key, "stdin") == 0) {
			free(key);
			if (stdin_s)
				goto bad;
			if (s.p < s.end && strncmp(s.p, "null", 4) == 0) {
				s.p += 4;
			} else if (str(&s, &stdin_s, &stdin_n)) {
				goto bad;
			}
		} else if (strcmp(key, "argv") == 0) {
			free(key);
			if (s.p < s.end && strncmp(s.p, "null", 4) == 0) {
				s.p += 4;
			} else {
				if (s.p >= s.end || *s.p++ != '[')
					goto bad;
				ws(&s);
				if (s.p < s.end && *s.p == ']') {
					s.p++;
				} else {
					for (;;) {
						ws(&s);
						char *a;
						size_t an;
						if (argc >= CX_ARGV_MAX || str(&s, &a, &an))
							goto bad;
						argv[argc++] = a;
						ws(&s);
						if (s.p >= s.end)
							goto bad;
						if (*s.p == ',') {
							s.p++;
							continue;
						}
						if (*s.p == ']') {
							s.p++;
							break;
						}
						goto bad;
					}
				}
			}
		} else {
			free(key);
			if (skip(&s))
				goto bad;
		}
		ws(&s);
		if (s.p >= s.end)
			goto bad;
		if (*s.p == ',') {
			s.p++;
			continue;
		}
		if (*s.p == '}')
			break;
		goto bad;
	}
done_obj:
	s.p++;
	ws(&s);
	if (s.p != s.end || !have_code)
		goto bad;
	in->code = code;
	in->code_len = code_n;
	if (!stdin_s) {
		stdin_s = calloc(1, 1);
		stdin_n = 0;
	}
	in->in = stdin_s;
	in->in_len = stdin_n;
	memcpy(in->argv, argv, sizeof(char *) * (size_t)argc);
	in->argc = argc;
	in->json = 1;
	return 0;
bad:
	free(code);
	free(stdin_s);
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	return -1;
}

int cx_read_input(cx_input *in)
{
	memset(in, 0, sizeof *in);
	size_t cap = 1 << 16, n = 0;
	char *buf = malloc(cap + 1);
	if (!buf) {
		fail("out of memory");
		return -1;
	}
	for (;;) {
		if (n == cap) {
			if (cap >= CX_INPUT_MAX) {
				free(buf);
				fail("input over 32 MiB");
				return -1;
			}
			cap *= 2;
			char *nb = realloc(buf, cap + 1);
			if (!nb) {
				free(buf);
				fail("out of memory");
				return -1;
			}
			buf = nb;
		}
		size_t r = fread(buf + n, 1, cap - n, stdin);
		n += r;
		if (r == 0)
			break;
	}
	buf[n] = 0;
	in->raw = buf;
	in->raw_len = n;

	size_t i = 0;
	while (i < n && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r'))
		i++;
	if (i < n && buf[i] == '{' && parse_framing(buf, n, in) == 0)
		return 0;

	/* NUL split: code before the first NUL, stdin after it. */
	char *nul = memchr(buf, 0, n);
	if (nul) {
		in->code = buf;
		in->code_len = (size_t)(nul - buf);
		in->in = nul + 1;
		in->in_len = n - in->code_len - 1;
	} else {
		in->code = buf;
		in->code_len = n;
		in->in = buf + n; /* points at the terminating NUL */
		in->in_len = 0;
	}
	return 0;
}

void cx_free_input(cx_input *in)
{
	if (in->json) {
		free(in->code);
		free(in->in);
		for (int i = 0; i < in->argc; i++)
			free(in->argv[i]);
	}
	free(in->raw);
	memset(in, 0, sizeof *in);
}
