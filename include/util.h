/* util.h - foundational utilities for mash.
 *
 * Growable byte buffer, death-on-OOM allocators, string helpers,
 * and a couple of tiny convenience wrappers. Nothing here depends on any
 * other mash module so it can be used everywhere.
 */
#ifndef MASH_UTIL_H
#define MASH_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ---------------------------------------------------------------- memory */

void *xmalloc(size_t n);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* Fatal error - print to stderr (unmasked; reserved for bugs / OOM) and
 * abort(3). Do not use in the normal error path; see mash_err instead. */
void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

/* --------------------------------------------------------------- strbuf */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} strbuf_t;

void strbuf_init(strbuf_t *b);
void strbuf_free(strbuf_t *b);
void strbuf_reset(strbuf_t *b);
void strbuf_reserve(strbuf_t *b, size_t extra);
void strbuf_push(strbuf_t *b, char c);
void strbuf_append(strbuf_t *b, const char *s, size_t n);
void strbuf_appendz(strbuf_t *b, const char *s);
void strbuf_appendf(strbuf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void strbuf_vappendf(strbuf_t *b, const char *fmt, va_list ap);
/* Transfer ownership of the buffer contents to the caller. After this call
 * the strbuf is empty and the returned pointer must be freed by the caller. */
char *strbuf_detach(strbuf_t *b, size_t *len_out);

/* --------------------------------------------------------------- strings */

bool str_eq(const char *a, const char *b);
bool str_starts_with(const char *s, const char *prefix);
bool str_ends_with(const char *s, const char *suffix);
char *str_join(const char *sep, char *const *parts, size_t n);

/* Split a NUL-terminated string into a NULL-terminated array using IFS.
 * Caller frees both the array and each element. */
char **str_split_ifs(const char *s, const char *ifs, size_t *out_n);

/* ----------------------------------------------------------------- fd io */

/* Write buf/len completely, retrying on short writes and EINTR.
 * Returns 0 on success, -1 on error. */
int write_all(int fd, const void *buf, size_t len);

/* -------------------------------------------------------------- counters */

static inline size_t max_sz(size_t a, size_t b) { return a > b ? a : b; }
static inline size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }

#endif /* MASH_UTIL_H */
