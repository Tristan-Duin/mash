/* history.c - masked command history. */

#include "history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mask.h"
#include "util.h"

static char *mask_copy(struct mask_engine_t *m, const char *s) {
    if (!m || !s) return xstrdup(s ? s : "");
    char *out = NULL;
    size_t n = 0;
    mask_apply(m, s, strlen(s), &out, &n);
    return out;
}

history_t *history_new(struct mask_engine_t *m) {
    history_t *h = xcalloc(1, sizeof(*h));
    h->mask = m;
    return h;
}

void history_free(history_t *h) {
    if (!h) return;
    for (size_t i = 0; i < HISTORY_MAX; i++) free(h->entries[i]);
    free(h->path);
    free(h);
}

void history_set_path(history_t *h, const char *path) {
    free(h->path);
    h->path = path ? xstrdup(path) : NULL;
}

size_t history_count(const history_t *h) { return h->count; }

const char *history_at(const history_t *h, size_t idx) {
    if (idx >= h->count) return NULL;
    size_t start = (h->head + HISTORY_MAX - h->count) % HISTORY_MAX;
    return h->entries[(start + idx) % HISTORY_MAX];
}

void history_add(history_t *h, const char *line) {
    if (!line || !*line) return;
    char *masked = mask_copy(h->mask, line);
    free(h->entries[h->head]);
    h->entries[h->head] = masked;
    h->head = (h->head + 1) % HISTORY_MAX;
    if (h->count < HISTORY_MAX) h->count++;
}

void history_clear(history_t *h) {
    for (size_t i = 0; i < HISTORY_MAX; i++) { free(h->entries[i]); h->entries[i] = NULL; }
    h->head = h->count = 0;
}

int history_load(history_t *h) {
    if (!h->path) return 0;
    FILE *f = fopen(h->path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) != -1) {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        history_add(h, line);
    }
    free(line);
    fclose(f);
    return 0;
}

int history_save(history_t *h) {
    if (!h->path) return 0;
    FILE *f = fopen(h->path, "w");
    if (!f) return -1;
    for (size_t i = 0; i < h->count; i++) {
        const char *s = history_at(h, i);
        if (!s) continue;
        /* If the write fails (e.g. ENOSPC, EIO) bail out so we don't
         * silently produce a truncated history file. */
        if (fprintf(f, "%s\n", s) < 0) {
            fclose(f);
            return -1;
        }
    }
    /* fclose flushes any remaining buffered data; report write errors
     * surfaced only at flush time. */
    if (fclose(f) != 0) return -1;
    return 0;
}

void history_iter(history_t *h, int n, history_iter_cb cb, void *ud) {
    if (!cb || h->count == 0) return;
    size_t start = 0;
    if (n > 0 && (size_t)n < h->count) start = h->count - (size_t)n;
    for (size_t i = start; i < h->count; i++) {
        cb((int)(i + 1), history_at(h, i), ud);
    }
}
