/* util.c - see util.h. */

#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------------------------------------------------------------- memory */

void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("mash: fatal: ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    abort();
}

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory (malloc %zu)", n);
    return p;
}

void *xcalloc(size_t nmemb, size_t size) {
    void *p = calloc(nmemb ? nmemb : 1, size ? size : 1);
    if (!p) die("out of memory (calloc %zu*%zu)", nmemb, size);
    return p;
}

void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory (realloc %zu)", n);
    return q;
}

char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *r = xmalloc(n + 1);
    memcpy(r, s, n + 1);
    return r;
}

char *xstrndup(const char *s, size_t n) {
    if (!s) return NULL;
    size_t m = strnlen(s, n);
    char *r = xmalloc(m + 1);
    memcpy(r, s, m);
    r[m] = '\0';
    return r;
}

/* --------------------------------------------------------------- strbuf */

void strbuf_init(strbuf_t *b) { b->data = NULL; b->len = b->cap = 0; }

void strbuf_free(strbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

void strbuf_reset(strbuf_t *b) {
    b->len = 0;
    if (b->data) b->data[0] = '\0';
}

void strbuf_reserve(strbuf_t *b, size_t extra) {
    if (b->cap - b->len >= extra + 1) return;
    size_t want = b->len + extra + 1;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < want) cap *= 2;
    b->data = xrealloc(b->data, cap);
    b->cap = cap;
}

void strbuf_push(strbuf_t *b, char c) {
    strbuf_reserve(b, 1);
    b->data[b->len++] = c;
    b->data[b->len]   = '\0';
}

void strbuf_append(strbuf_t *b, const char *s, size_t n) {
    strbuf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

void strbuf_appendz(strbuf_t *b, const char *s) {
    if (s) strbuf_append(b, s, strlen(s));
}

void strbuf_vappendf(strbuf_t *b, const char *fmt, va_list ap) {
    va_list copy;
    va_copy(copy, ap);
    int n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (n < 0) return;
    strbuf_reserve(b, (size_t)n);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
    b->len += (size_t)n;
}

void strbuf_appendf(strbuf_t *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    strbuf_vappendf(b, fmt, ap);
    va_end(ap);
}

char *strbuf_detach(strbuf_t *b, size_t *len_out) {
    if (!b->data) {
        if (len_out) *len_out = 0;
        char *empty = xmalloc(1);
        empty[0] = '\0';
        return empty;
    }
    char *p = b->data;
    if (len_out) *len_out = b->len;
    b->data = NULL;
    b->len = b->cap = 0;
    return p;
}

/* --------------------------------------------------------------- strings */

bool str_eq(const char *a, const char *b) {
    if (a == b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

bool str_starts_with(const char *s, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

bool str_ends_with(const char *s, const char *suffix) {
    size_t ns = strlen(s), nf = strlen(suffix);
    if (nf > ns) return false;
    return memcmp(s + ns - nf, suffix, nf) == 0;
}

char *str_join(const char *sep, char *const *parts, size_t n) {
    strbuf_t b; strbuf_init(&b);
    size_t sl = sep ? strlen(sep) : 0;
    for (size_t i = 0; i < n; i++) {
        if (i && sl) strbuf_append(&b, sep, sl);
        if (parts[i]) strbuf_appendz(&b, parts[i]);
    }
    return strbuf_detach(&b, NULL);
}

char **str_split_ifs(const char *s, const char *ifs, size_t *out_n) {
    if (!ifs || !*ifs) ifs = " \t\n";
    size_t cap = 8, n = 0;
    char **arr = xcalloc(cap, sizeof(*arr));
    const char *p = s;
    while (*p) {
        while (*p && strchr(ifs, *p)) p++;
        if (!*p) break;
        const char *start = p;
        while (*p && !strchr(ifs, *p)) p++;
        if (n + 1 >= cap) { cap *= 2; arr = xrealloc(arr, cap * sizeof(*arr)); }
        arr[n++] = xstrndup(start, (size_t)(p - start));
    }
    arr[n] = NULL;
    if (out_n) *out_n = n;
    return arr;
}

/* ----------------------------------------------------------------- fd io */

int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}
