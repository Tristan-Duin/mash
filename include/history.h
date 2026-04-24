/* history.h - masked command history.
 *
 * Ring buffer of up to HISTORY_MAX entries. Every persisted byte runs
 * through the mask engine so raw tokens pasted into the prompt are
 * redacted before they ever touch the on-disk history file. On load we
 * also pass the bytes through the mask (defense in depth).
 */
#ifndef MASH_HISTORY_H
#define MASH_HISTORY_H

#include <stddef.h>

struct mask_engine_t;

#define HISTORY_MAX 10000

typedef struct history_t {
    char   *entries[HISTORY_MAX];
    size_t  head;           /* next write slot */
    size_t  count;          /* number of valid entries (<= HISTORY_MAX) */
    char   *path;           /* persist file (may be NULL) */
    struct mask_engine_t *mask;
} history_t;

typedef void (*history_iter_cb)(int idx, const char *line, void *ud);

history_t *history_new(struct mask_engine_t *mask);
void       history_free(history_t *h);

void       history_set_path(history_t *h, const char *path);
int        history_load(history_t *h);
int        history_save(history_t *h);

void       history_add(history_t *h, const char *line);
void       history_clear(history_t *h);
size_t     history_count(const history_t *h);
const char *history_at(const history_t *h, size_t idx);

/* Iterate last N entries (N < 0 means all). Line passed to cb is
 * mask-applied (but is already masked on add; safe for defense). */
void       history_iter(history_t *h, int n, history_iter_cb cb, void *ud);

#endif /* MASH_HISTORY_H */
