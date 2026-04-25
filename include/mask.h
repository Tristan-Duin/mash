/* mask.h - the PII detection and redaction engine.
 *
 * An ordered list of rules; each rule is a compiled POSIX ERE with a
 * replacement template and a category label. Three operating modes:
 *
 *   mask_apply()            - one-shot on a complete buffer
 *   mask_stream_push()      - streaming: called by fd pumps
 *   mask_stream_finish()    - flush any buffered tail
 *
 * Rules are seeded at shell startup from:
 *   1. Hard-coded universal patterns (emails, IPs, MACs, tokens, ...).
 *   2. Runtime-derived literals (USER, HOME, hostname, UID, interfaces, ...).
 *   3. Optional user config (~/.config/mash/mask.conf or via the `mask` builtin).
 *
 * The engine is read-only after mash_mask_init_defaults completes (subsequent
 * `mask` builtin edits take a mutex), and is therefore safe to call from
 * multiple pump threads concurrently on the read path.
 */
#ifndef MASH_MASK_H
#define MASH_MASK_H

#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stddef.h>

#include "util.h"

typedef enum {
    MASK_CAT_USER = 0,
    MASK_CAT_HOST,
    MASK_CAT_HOME,
    MASK_CAT_UID,
    MASK_CAT_IPV4,
    MASK_CAT_IPV6,
    MASK_CAT_MAC,
    MASK_CAT_EMAIL,
    MASK_CAT_PHONE,
    MASK_CAT_SSN,
    MASK_CAT_CREDITCARD,
    MASK_CAT_UUID,
    MASK_CAT_JWT,
    MASK_CAT_AWS_KEY,
    MASK_CAT_GH_TOKEN,
    MASK_CAT_GENERIC_TOKEN,
    MASK_CAT_PRIVATE_KEY,
    MASK_CAT_PATH,
    MASK_CAT_IBAN,
    MASK_CAT_HEX_SECRET,
    MASK_CAT_CUSTOM,
    MASK_CAT__COUNT
} mask_cat_t;

const char *mask_cat_name(mask_cat_t c);

/* Single rule. Compiled once; reused many times. The `literal` field is
 * non-NULL when the rule was built from mask_add_literal(), so `mask show`
 * can display the originating string (itself redacted). */
typedef struct mask_rule_t {
    mask_cat_t          category;
    char               *pattern_src;  /* original pattern text */
    regex_t             re;           /* compiled */
    char               *replacement;  /* replacement template */
    char               *literal;      /* non-NULL if derived from a literal */
    bool                disabled;
    struct mask_rule_t *next;
} mask_rule_t;

/* Engine. Protect additions/removals with `lock`; the hot-path reader
 * (mask_apply / mask_stream_push) also takes lock briefly. Since rules are
 * effectively immutable after startup the contention is negligible.
 *
 * The `locked` flag implements a one-way lockdown: once set (via
 * `mask_engine_lock`, the `mask lock` builtin, or `--mask-lock`), removing
 * or disabling rules is refused and `set -o nomask-cmdsub` will be
 * rejected. Adding new rules and re-enabling disabled ones is still
 * allowed because both strengthen redaction. */
typedef struct mask_engine_t {
    mask_rule_t     *rules;
    size_t           rule_count;
    pthread_mutex_t  lock;
    bool             locked;
} mask_engine_t;

/* --------------------------------------------------------------- lifecycle */

mask_engine_t *mask_engine_new(void);
void           mask_engine_free(mask_engine_t *e);

/* Seed with the hard-coded + runtime-derived rules. Safe to call once. */
void           mash_mask_init_defaults(mask_engine_t *e);

/* Load user-supplied rules from a file (one per line; `#` comments). */
int            mash_mask_load_file(mask_engine_t *e, const char *path);

/* ------------------------------------------------------------------- rules */

/* Add a compiled pattern. Returns 0 on success. */
int  mask_add_pattern(mask_engine_t *e, mask_cat_t cat,
                      const char *pattern, const char *replacement);

/* Add a fixed literal. The literal is regex-escaped internally. Safe for
 * arbitrary bytes. */
int  mask_add_literal(mask_engine_t *e, mask_cat_t cat,
                      const char *literal);

/* Disable / enable / remove by 0-based index (order stable). When the
 * engine is locked, mask_remove() and mask_set_disabled(.., true) return
 * -1 without modifying state; re-enabling (false) is always allowed. */
int  mask_set_disabled(mask_engine_t *e, size_t idx, bool disabled);
int  mask_remove(mask_engine_t *e, size_t idx);

/* One-way lockdown. After mask_engine_lock() returns the engine refuses
 * any operation that would weaken redaction. There is no unlock. */
void mask_engine_lock(mask_engine_t *e);
bool mask_engine_is_locked(mask_engine_t *e);

/* Walk all rules; cb returns false to stop. */
void mask_foreach(mask_engine_t *e,
                  bool (*cb)(const mask_rule_t *, size_t idx, void *), void *ud);

/* ------------------------------------------------------------- application */

/* Synchronous redaction. Always succeeds; caller frees *out. */
void mask_apply(mask_engine_t *e,
                const char *in, size_t in_len,
                char **out, size_t *out_len);

/* ----------------------------------------------------------- streaming api */

/* Streaming state.
 *
 * The engine holds bytes back until they can be safely masked as a unit:
 *   - text mode: flush on the last newline so multi-line patterns
 *     (e.g. PEM private key blocks) match across line boundaries.
 *     If a -----BEGIN ... PRIVATE KEY----- marker is seen without its
 *     matching -----END the buffer keeps growing up to a hard cap so
 *     the multi-line redaction rule fires atomically.
 *   - binary mode: retain a small overlap tail so cross-chunk matches
 *     succeed; force-flush past the hard cap.
 *   - in either mode, when force-flushing we leave a small tail behind
 *     so word-boundary patterns that straddle the boundary still match
 *     on the next push. */
typedef struct {
    mask_engine_t *engine;
    strbuf_t       pending;          /* unflushed tail */
    size_t         max_line;         /* soft cap before force-flush */
    size_t         block_max;        /* hard cap on retained bytes */
    size_t         overlap_tail;     /* bytes kept across force-flushes */
    bool           binary_detected;  /* set once if >1% NULs seen */
    size_t         bytes_total;
    size_t         bytes_null;
} mask_stream_t;

void mask_stream_init(mask_stream_t *ms, mask_engine_t *e);
void mask_stream_free(mask_stream_t *ms);

/* Process a chunk; appends masked output to `out`. */
void mask_stream_push(mask_stream_t *ms,
                      const char *buf, size_t len,
                      strbuf_t *out);

/* Drain remaining buffered bytes. After this, the stream is ready for reuse
 * via a fresh push or may be freed. */
void mask_stream_finish(mask_stream_t *ms, strbuf_t *out);

/* Emit anything in the buffer that is *safe* to emit immediately - i.e.
 * everything unless an open multi-line secret block (a -----BEGIN... line
 * with no -----END... yet) would be split. Used by pump threads as an
 * idle-window flush so interactive TUIs (vim, less, ...) don't appear to
 * hang waiting for a \n that never comes. */
void mask_stream_idle_flush(mask_stream_t *ms, strbuf_t *out);

#endif /* MASH_MASK_H */
