/* mask.c - masking engine.
 *
 * Rule storage is a singly linked list in insertion order. Application runs
 * rules sequentially, each one scanning the whole buffer for matches; a
 * replacement is emitted in category form «CATEGORY» unless the rule carries
 * a custom template. Rule ordering matters: more specific rules first
 * (e.g. private key blocks before generic hex secrets).
 *
 * The streaming variant flushes on the *last* newline rather than each one,
 * so multi-line rules (notably the BEGIN..END PEM redactor) match across
 * lines. While a `-----BEGIN ... PRIVATE KEY-----` marker has no matching
 * `-----END` we hold the buffer (up to a hard cap) so the closing line can
 * arrive before any of the body is emitted. When forced to flush a giant
 * no-newline buffer we keep a small overlap tail so word-boundary patterns
 * straddling the boundary remain matchable on the next push. In binary
 * mode the same overlap technique catches matches across chunk boundaries.
 */

#include "mask.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Streaming bounds. Selected so a typical PEM private-key block (~4 KB)
 * easily fits, while a runaway producer can never blow up shell memory.
 *
 * MASK_STREAM_OVERLAP must comfortably exceed the longest secret a rule
 * may match. JWTs and PEM bodies are the long-tail cases (a few KB), so
 * 8 KB gives headroom. Smaller overlap (e.g. 256 B) was *not* enough
 * because a force-flush happening mid-secret would emit the secret's
 * head unmasked while only the suffix remained in pending. */
#define MASK_STREAM_LINE_SOFT  (64 * 1024)        /* force-flush past this if no NL */
#define MASK_STREAM_BLOCK_MAX  (16 * 1024 * 1024) /* hard cap regardless of state */
#define MASK_STREAM_OVERLAP    (8 * 1024)         /* retained tail for boundary matches */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
# include <net/if.h>
# if defined(__linux__)
#  include <netpacket/packet.h>
# else
#  include <net/if_dl.h>
# endif
#endif

/* ---------------------------------------------------------------- helpers */

static const char *CAT_NAMES[MASK_CAT__COUNT] = {
    [MASK_CAT_USER]          = "USER",
    [MASK_CAT_HOST]          = "HOST",
    [MASK_CAT_HOME]          = "HOME",
    [MASK_CAT_UID]           = "UID",
    [MASK_CAT_IPV4]          = "IPV4",
    [MASK_CAT_IPV6]          = "IPV6",
    [MASK_CAT_MAC]           = "MAC",
    [MASK_CAT_EMAIL]         = "EMAIL",
    [MASK_CAT_PHONE]         = "PHONE",
    [MASK_CAT_SSN]           = "SSN",
    [MASK_CAT_CREDITCARD]    = "CC",
    [MASK_CAT_UUID]          = "UUID",
    [MASK_CAT_JWT]           = "JWT",
    [MASK_CAT_AWS_KEY]       = "AWS",
    [MASK_CAT_GH_TOKEN]      = "GH_TOKEN",
    [MASK_CAT_GENERIC_TOKEN] = "TOKEN",
    [MASK_CAT_PRIVATE_KEY]   = "PRIVATE_KEY",
    [MASK_CAT_PATH]          = "PATH",
    [MASK_CAT_IBAN]          = "IBAN",
    [MASK_CAT_HEX_SECRET]    = "SECRET",
    [MASK_CAT_CUSTOM]        = "CUSTOM",
};

const char *mask_cat_name(mask_cat_t c) {
    if ((size_t)c >= MASK_CAT__COUNT) return "?";
    return CAT_NAMES[c] ? CAT_NAMES[c] : "?";
}

/* Escape a literal for inclusion in a POSIX ERE. */
static char *regex_escape(const char *s) {
    strbuf_t b; strbuf_init(&b);
    for (const char *p = s; *p; p++) {
        if (strchr(".*+?()[]{}|^$\\/", *p)) strbuf_push(&b, '\\');
        strbuf_push(&b, *p);
    }
    return strbuf_detach(&b, NULL);
}

/* ------------------------------------------------------------ engine core */

mask_engine_t *mask_engine_new(void) {
    mask_engine_t *e = xcalloc(1, sizeof(*e));
    pthread_mutex_init(&e->lock, NULL);
    return e;
}

static void rule_free(mask_rule_t *r) {
    if (!r) return;
    regfree(&r->re);
    free(r->pattern_src);
    free(r->replacement);
    free(r->literal);
    free(r);
}

void mask_engine_free(mask_engine_t *e) {
    if (!e) return;
    mask_rule_t *r = e->rules;
    while (r) {
        mask_rule_t *n = r->next;
        rule_free(r);
        r = n;
    }
    pthread_mutex_destroy(&e->lock);
    free(e);
}

static int add_rule_locked(mask_engine_t *e, mask_rule_t *r) {
    /* Append to preserve insertion order. */
    mask_rule_t **cur = &e->rules;
    while (*cur) cur = &(*cur)->next;
    *cur = r;
    e->rule_count++;
    return 0;
}

int mask_add_pattern(mask_engine_t *e, mask_cat_t cat,
                     const char *pattern, const char *replacement) {
    if (!e || !pattern) return -1;
    mask_rule_t *r = xcalloc(1, sizeof(*r));
    r->category    = cat;
    r->pattern_src = xstrdup(pattern);

    int rc = regcomp(&r->re, pattern, REG_EXTENDED);
    if (rc != 0) {
        char regbuf[256];
        regerror(rc, &r->re, regbuf, sizeof(regbuf));
        /* The pattern may have been derived from a sensitive literal
         * (mask_add_literal escapes the value verbatim). Mask the
         * diagnostic through whatever rules are already loaded so a
         * typo in `mask literal EMAIL alice@example.com` doesn't
         * echo the secret to the raw stderr. If no rules exist yet
         * (very early init), elide the pattern entirely. */
        char raw[1024];
        int  rlen = snprintf(raw, sizeof(raw),
                             "mash: regex compile failed for \"%s\": %s\n",
                             pattern, regbuf);
        if (rlen < 0) rlen = 0;
        if ((size_t)rlen > sizeof(raw)) rlen = (int)sizeof(raw);
        if (e->rules) {
            char  *masked = NULL;
            size_t mlen   = 0;
            mask_apply(e, raw, (size_t)rlen, &masked, &mlen);
            (void)write_all(STDERR_FILENO,
                            masked ? masked : raw,
                            masked ? mlen   : (size_t)rlen);
            free(masked);
        } else {
            const char *fallback =
                "mash: regex compile failed (pattern elided)\n";
            (void)write_all(STDERR_FILENO, fallback, strlen(fallback));
        }
        free(r->pattern_src);
        free(r);
        return -1;
    }

    if (replacement && *replacement) {
        r->replacement = xstrdup(replacement);
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "\xC2\xAB%s\xC2\xBB", mask_cat_name(cat));
        r->replacement = xstrdup(buf);
    }

    pthread_mutex_lock(&e->lock);
    add_rule_locked(e, r);
    pthread_mutex_unlock(&e->lock);
    return 0;
}

int mask_add_literal(mask_engine_t *e, mask_cat_t cat, const char *literal) {
    if (!e || !literal || !*literal) return -1;
    /* Skip values that would over-match. */
    if (strlen(literal) < 2) return -1;
    /* Trivial identifiers like "root" / "0" are still escaped but those
     * small values are likely to over-match - skip the shortest ones. */
    if (strlen(literal) < 3 && !isalpha((unsigned char)literal[0])) return -1;

    char *esc = regex_escape(literal);
    int rc = mask_add_pattern(e, cat, esc, NULL);
    if (rc == 0) {
        /* Record the literal on the just-added (last) rule. */
        pthread_mutex_lock(&e->lock);
        mask_rule_t *last = e->rules;
        while (last && last->next) last = last->next;
        if (last) last->literal = xstrdup(literal);
        pthread_mutex_unlock(&e->lock);
    }
    free(esc);
    return rc;
}

int mask_set_disabled(mask_engine_t *e, size_t idx, bool disabled) {
    if (!e) return -1;
    pthread_mutex_lock(&e->lock);
    /* Disabling weakens redaction; refuse if locked. Re-enabling is OK. */
    if (disabled && e->locked) {
        pthread_mutex_unlock(&e->lock);
        errno = EPERM;
        return -1;
    }
    mask_rule_t *r = e->rules;
    size_t i = 0;
    while (r && i < idx) { r = r->next; i++; }
    int rc = -1;
    if (r) { r->disabled = disabled; rc = 0; }
    pthread_mutex_unlock(&e->lock);
    return rc;
}

int mask_remove(mask_engine_t *e, size_t idx) {
    if (!e) return -1;
    pthread_mutex_lock(&e->lock);
    if (e->locked) {
        pthread_mutex_unlock(&e->lock);
        errno = EPERM;
        return -1;
    }
    mask_rule_t **cur = &e->rules;
    size_t i = 0;
    while (*cur && i < idx) { cur = &(*cur)->next; i++; }
    int rc = -1;
    if (*cur) {
        mask_rule_t *r = *cur;
        *cur = r->next;
        rule_free(r);
        e->rule_count--;
        rc = 0;
    }
    pthread_mutex_unlock(&e->lock);
    return rc;
}

void mask_engine_lock(mask_engine_t *e) {
    if (!e) return;
    pthread_mutex_lock(&e->lock);
    e->locked = true;
    pthread_mutex_unlock(&e->lock);
}

bool mask_engine_is_locked(mask_engine_t *e) {
    if (!e) return false;
    pthread_mutex_lock(&e->lock);
    bool v = e->locked;
    pthread_mutex_unlock(&e->lock);
    return v;
}

void mask_foreach(mask_engine_t *e,
                  bool (*cb)(const mask_rule_t *, size_t idx, void *),
                  void *ud) {
    if (!e || !cb) return;
    pthread_mutex_lock(&e->lock);
    size_t i = 0;
    for (mask_rule_t *r = e->rules; r; r = r->next, i++) {
        if (!cb(r, i, ud)) break;
    }
    pthread_mutex_unlock(&e->lock);
}

/* ------------------------------------------------------------ application */

/* Apply one rule across `in` producing into `out`. Operates on NUL-free
 * byte ranges; any embedded NUL is passed through and resets scanning. */
static void apply_one(const mask_rule_t *r,
                      const char *in, size_t in_len,
                      strbuf_t *out) {
    if (r->disabled) { strbuf_append(out, in, in_len); return; }

    const char *p   = in;
    size_t      rem = in_len;

    while (rem > 0) {
        /* Split on embedded NUL. */
        const char *nul = memchr(p, '\0', rem);
        size_t chunk = nul ? (size_t)(nul - p) : rem;

        /* regexec needs a NUL-terminated string; copy the chunk. */
        char *tmp = xmalloc(chunk + 1);
        memcpy(tmp, p, chunk);
        tmp[chunk] = '\0';

        const char *cur = tmp;
        size_t curlen = chunk;
        regmatch_t m;
        while (curlen > 0 &&
               regexec(&r->re, cur, 1, &m, cur == tmp ? 0 : REG_NOTBOL) == 0) {
            if (m.rm_eo == m.rm_so) { /* degenerate zero-width; skip 1 */
                if ((size_t)m.rm_so < curlen) {
                    strbuf_push(out, cur[m.rm_so]);
                    cur    += m.rm_so + 1;
                    curlen -= m.rm_so + 1;
                    continue;
                }
                break;
            }
            strbuf_append(out, cur, (size_t)m.rm_so);
            strbuf_appendz(out, r->replacement);
            cur    += m.rm_eo;
            curlen -= (size_t)m.rm_eo;
        }
        strbuf_append(out, cur, curlen);
        free(tmp);

        p   += chunk;
        rem -= chunk;
        if (nul) {
            strbuf_push(out, '\0');
            p++;
            rem--;
        }
    }
}

void mask_apply(mask_engine_t *e,
                const char *in, size_t in_len,
                char **out, size_t *out_len) {
    strbuf_t a, b;
    strbuf_init(&a);
    strbuf_init(&b);
    strbuf_append(&a, in, in_len);

    pthread_mutex_lock(&e->lock);
    for (mask_rule_t *r = e->rules; r; r = r->next) {
        strbuf_reset(&b);
        apply_one(r, a.data ? a.data : "", a.len, &b);
        /* Swap a <-> b. */
        strbuf_t tmp = a;
        a = b;
        b = tmp;
    }
    pthread_mutex_unlock(&e->lock);

    strbuf_free(&b);
    size_t n = 0;
    char *res = strbuf_detach(&a, &n);
    if (out)     *out     = res;
    else         free(res);
    if (out_len) *out_len = n;
}

/* ----------------------------------------------------------- streaming */

void mask_stream_init(mask_stream_t *ms, mask_engine_t *e) {
    memset(ms, 0, sizeof(*ms));
    ms->engine       = e;
    ms->max_line     = MASK_STREAM_LINE_SOFT;
    ms->block_max    = MASK_STREAM_BLOCK_MAX;
    ms->overlap_tail = MASK_STREAM_OVERLAP;
    strbuf_init(&ms->pending);
}

void mask_stream_free(mask_stream_t *ms) {
    strbuf_free(&ms->pending);
    memset(ms, 0, sizeof(*ms));
}

/* Naive substring search. memmem() is non-portable; this is invoked at
 * most a handful of times per push so the simple loop is fine. */
static const char *find_substr(const char *hay, size_t hay_len,
                               const char *needle, size_t nlen) {
    if (nlen == 0) return hay;
    if (hay_len < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return NULL;
}

/* True if `pending` contains an opened multi-line secret block (a
 * "-----BEGIN" marker that has no matching "-----END" yet). When this
 * holds, we delay flushing so mask_apply() can run the multi-line PEM
 * rule against BEGIN..END atomically.
 *
 * The marker is intentionally generic ("-----BEGIN"): it covers any
 * PEM-like block (RSA / EC / OPENSSH / DSA / encrypted PRIVATE KEY,
 * certificate request bodies, etc.) without us having to enumerate
 * every variant the rules know about. */
static bool has_open_multiline_block(const char *data, size_t len) {
    static const char BEGIN_M[] = "-----BEGIN";
    static const char END_M[]   = "-----END";
    const size_t blen = sizeof(BEGIN_M) - 1;
    const size_t elen = sizeof(END_M)   - 1;

    /* Walk every BEGIN; only declare "open" if the *last* BEGIN has no
     * subsequent END. A second BEGIN-END pair within the same buffer is
     * fine because the rule will match each block independently. */
    const char *cursor = data;
    size_t      remain = len;
    const char *last_begin = NULL;
    for (;;) {
        const char *b = find_substr(cursor, remain, BEGIN_M, blen);
        if (!b) break;
        last_begin = b;
        size_t advance = (size_t)(b - cursor) + blen;
        cursor = cursor + advance;
        remain = remain >= advance ? remain - advance : 0;
    }
    if (!last_begin) return false;
    size_t after = (size_t)(last_begin - data) + blen;
    if (after > len) after = len;
    return find_substr(data + after, len - after, END_M, elen) == NULL;
}

/* Apply rules to the first `n` bytes of pending, emit them, and shift the
 * remainder back to the start of the buffer. Caller is responsible for
 * choosing a `n` that does not split a multi-line secret. */
static void flush_prefix(mask_stream_t *ms, size_t n, strbuf_t *out) {
    if (n == 0) return;
    if (n > ms->pending.len) n = ms->pending.len;
    char  *masked = NULL;
    size_t mlen   = 0;
    mask_apply(ms->engine, ms->pending.data, n, &masked, &mlen);
    if (masked && mlen) strbuf_append(out, masked, mlen);
    free(masked);
    if (ms->pending.len > n) {
        memmove(ms->pending.data, ms->pending.data + n, ms->pending.len - n);
        ms->pending.len -= n;
    } else {
        ms->pending.len = 0;
    }
    if (ms->pending.data) ms->pending.data[ms->pending.len] = '\0';
}

void mask_stream_push(mask_stream_t *ms,
                      const char *buf, size_t len,
                      strbuf_t *out) {
    if (len == 0) return;

    /* Heuristic binary detection: too many NULs => stream is likely binary.
     * We still mask, but line-batching would break. */
    for (size_t i = 0; i < len; i++) if (buf[i] == '\0') ms->bytes_null++;
    ms->bytes_total += len;
    if (!ms->binary_detected && ms->bytes_total >= 4096 &&
        ms->bytes_null * 100 >= ms->bytes_total) {
        ms->binary_detected = true;
    }

    /* Always accumulate first; flush_prefix() decides what's safe to emit. */
    strbuf_append(&ms->pending, buf, len);

    if (ms->binary_detected) {
        /* Retain a small overlap tail so a token straddling chunk boundaries
         * is still seen as one unit by mask_apply on the next push. */
        if (ms->pending.len > ms->overlap_tail) {
            flush_prefix(ms, ms->pending.len - ms->overlap_tail, out);
        }
        if (ms->pending.len >= ms->block_max) {
            flush_prefix(ms, ms->pending.len, out);
        }
        return;
    }

    /* Hold off flushing while a multi-line secret block is open and we
     * still have headroom. Once the closing marker arrives mask_apply
     * matches BEGIN..END as a single replacement. */
    if (ms->pending.len < ms->block_max &&
        has_open_multiline_block(ms->pending.data, ms->pending.len)) {
        return;
    }

    /* Flush up to the last newline so multi-line patterns within a single
     * batch (e.g. a PEM block whose BEGIN and END are now both present)
     * are masked as a unit rather than line by line. */
    size_t last_nl = 0;
    for (size_t i = ms->pending.len; i > 0; i--) {
        if (ms->pending.data[i - 1] == '\n') { last_nl = i; break; }
    }
    if (last_nl) flush_prefix(ms, last_nl, out);

    /* If we still exceed the soft cap we have a giant no-newline blob.
     * Force-flush, but leave a small overlap tail so word-boundary patterns
     * straddling the boundary remain matchable on the next push. */
    if (ms->pending.len >= ms->max_line) {
        size_t tail = ms->pending.len > ms->overlap_tail ? ms->overlap_tail : 0;
        if (ms->pending.len > tail) {
            flush_prefix(ms, ms->pending.len - tail, out);
        }
    }

    /* And as a hard ceiling, never grow without bound. */
    if (ms->pending.len >= ms->block_max) {
        flush_prefix(ms, ms->pending.len, out);
    }
}

void mask_stream_finish(mask_stream_t *ms, strbuf_t *out) {
    if (ms->pending.len) flush_prefix(ms, ms->pending.len, out);
}

void mask_stream_idle_flush(mask_stream_t *ms, strbuf_t *out) {
    if (!ms || ms->pending.len == 0) return;
    /* Don't break a multi-line secret in half just because the wire went
     * idle. The block_max safety net in mask_stream_push will eventually
     * force the issue if BEGIN never gets its END. */
    if (has_open_multiline_block(ms->pending.data, ms->pending.len)) return;
    flush_prefix(ms, ms->pending.len, out);
}

/* ----------------------------------------------------------- rule seeding */

/* Hard-coded universal patterns. Ordering: most specific first. */
static const struct {
    mask_cat_t cat;
    const char *pattern;
} HARD_CODED[] = {
    /* Private key blocks (multiline; we match the marker line). */
    { MASK_CAT_PRIVATE_KEY,
      "-----BEGIN[A-Z ]+PRIVATE KEY-----[^-]*-----END[A-Z ]+PRIVATE KEY-----" },
    { MASK_CAT_PRIVATE_KEY,
      "-----BEGIN[A-Z ]+PRIVATE KEY-----" },

    /* AWS access key id / secret. */
    { MASK_CAT_AWS_KEY,  "AKIA[0-9A-Z]{16}" },
    { MASK_CAT_AWS_KEY,  "ASIA[0-9A-Z]{16}" },

    /* GitHub tokens. */
    { MASK_CAT_GH_TOKEN, "gh[pousr]_[A-Za-z0-9]{30,255}" },
    /* Slack. */
    { MASK_CAT_GENERIC_TOKEN,
      "xox[abpr]-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}" },
    /* Google API keys / OAuth. */
    { MASK_CAT_GENERIC_TOKEN, "AIza[0-9A-Za-z_-]{35}" },
    { MASK_CAT_GENERIC_TOKEN, "ya29\\.[0-9A-Za-z_-]+" },

    /* JWT: three base64url pieces separated by dots. */
    { MASK_CAT_JWT,
      "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+" },

    /* Bearer tokens: capture just the secret. */
    { MASK_CAT_GENERIC_TOKEN,
      "([Bb]earer[ \t]+)[A-Za-z0-9._~+/=-]{16,}" },

    /* IBAN (loose). */
    { MASK_CAT_IBAN,
      "[A-Z]{2}[0-9]{2}[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{4}[ ]?[A-Z0-9]{1,16}" },

    /* Credit card (Luhn not enforced; pattern-matched). POSIX ERE: no (?:). */
    { MASK_CAT_CREDITCARD,
      "\\b(4[0-9]{12}([0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(011|5[0-9]{2})[0-9]{12}|(2131|1800|35[0-9]{3})[0-9]{11})\\b" },

    /* US SSN. */
    { MASK_CAT_SSN,    "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b" },

    /* E.164 / dashed phone numbers (tuned to avoid arbitrary 7+ digits). */
    { MASK_CAT_PHONE,  "\\+[1-9][0-9]{7,14}\\b" },
    { MASK_CAT_PHONE,  "\\b\\(?[0-9]{3}\\)?[-. ][0-9]{3}[-. ][0-9]{4}\\b" },

    /* Email. */
    { MASK_CAT_EMAIL,
      "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}" },

    /* UUIDv4-ish. */
    { MASK_CAT_UUID,
      "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\\b" },

    /* IPv4. */
    { MASK_CAT_IPV4,
      "\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\\b" },

    /* IPv6 (loose). */
    { MASK_CAT_IPV6,
      "\\b(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|::([fF]{4}(:0{1,4})?:)?([0-9]{1,3}\\.){3}[0-9]{1,3})" },

    /* MAC address. */
    { MASK_CAT_MAC,
      "\\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b" },

    /* Hex secrets (32/40/64 bytes worth of hex). */
    { MASK_CAT_HEX_SECRET, "\\b[A-Fa-f0-9]{32}\\b" },
    { MASK_CAT_HEX_SECRET, "\\b[A-Fa-f0-9]{40}\\b" },
    { MASK_CAT_HEX_SECRET, "\\b[A-Fa-f0-9]{64}\\b" },
};

static void seed_hard_coded(mask_engine_t *e) {
    const size_t n = sizeof(HARD_CODED) / sizeof(HARD_CODED[0]);
    for (size_t i = 0; i < n; i++) {
        mask_add_pattern(e, HARD_CODED[i].cat, HARD_CODED[i].pattern, NULL);
    }
}

/* Runtime-derived literals: user, home, hostname, interface addresses. */
static void seed_runtime(mask_engine_t *e) {
    /* USER / LOGNAME / SUDO_USER. */
    const char *const users[] = { "USER", "LOGNAME", "SUDO_USER", NULL };
    for (size_t i = 0; users[i]; i++) {
        const char *v = getenv(users[i]);
        if (v && *v) mask_add_literal(e, MASK_CAT_USER, v);
    }
    /* passwd lookup as a fallback. */
    struct passwd *pw = getpwuid(getuid());
    if (pw) {
        if (pw->pw_name) mask_add_literal(e, MASK_CAT_USER, pw->pw_name);
        if (pw->pw_gecos && *pw->pw_gecos) {
            /* Only the first comma-separated field (full name). */
            char *c = xstrdup(pw->pw_gecos);
            char *comma = strchr(c, ',');
            if (comma) *comma = '\0';
            if (*c) mask_add_literal(e, MASK_CAT_USER, c);
            free(c);
        }
    }

    /* HOME. */
    const char *home = getenv("HOME");
    if (home && *home) mask_add_literal(e, MASK_CAT_HOME, home);
    if (pw && pw->pw_dir && *pw->pw_dir) mask_add_literal(e, MASK_CAT_HOME, pw->pw_dir);

    /* Hostname. */
    struct utsname un;
    if (uname(&un) == 0) {
        if (*un.nodename) mask_add_literal(e, MASK_CAT_HOST, un.nodename);
    }
    char hbuf[256];
    if (gethostname(hbuf, sizeof(hbuf)) == 0 && *hbuf) {
        mask_add_literal(e, MASK_CAT_HOST, hbuf);
    }

    /* UID / GID. */
    {
        char b[32];
        snprintf(b, sizeof(b), "uid=%u", (unsigned)getuid());
        mask_add_literal(e, MASK_CAT_UID, b);
        snprintf(b, sizeof(b), "gid=%u", (unsigned)getgid());
        mask_add_literal(e, MASK_CAT_UID, b);
    }

    /* Interface addresses. */
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) == 0) {
        for (struct ifaddrs *ia = ifs; ia; ia = ia->ifa_next) {
            if (!ia->ifa_addr) continue;
            char buf[INET6_ADDRSTRLEN];
            if (ia->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ia->ifa_addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) &&
                    strcmp(buf, "127.0.0.1") != 0) {
                    mask_add_literal(e, MASK_CAT_IPV4, buf);
                }
            } else if (ia->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ia->ifa_addr;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) &&
                    strcmp(buf, "::1") != 0) {
                    mask_add_literal(e, MASK_CAT_IPV6, buf);
                }
            }
#if defined(__linux__)
            else if (ia->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)ia->ifa_addr;
                if (sll->sll_halen == 6) {
                    char mac[32];
                    snprintf(mac, sizeof(mac),
                             "%02x:%02x:%02x:%02x:%02x:%02x",
                             sll->sll_addr[0], sll->sll_addr[1],
                             sll->sll_addr[2], sll->sll_addr[3],
                             sll->sll_addr[4], sll->sll_addr[5]);
                    mask_add_literal(e, MASK_CAT_MAC, mac);
                }
            }
#endif
        }
        freeifaddrs(ifs);
    }

    /* SSH / mail envs (flag leakage of remote IPs). */
    const char *const more[] = { "SSH_CLIENT", "SSH_TTY", "SSH_CONNECTION",
                                 "MAIL", "MAILPATH", NULL };
    for (size_t i = 0; more[i]; i++) {
        const char *v = getenv(more[i]);
        if (v && *v) mask_add_literal(e, MASK_CAT_CUSTOM, v);
    }
}

void mash_mask_init_defaults(mask_engine_t *e) {
    seed_hard_coded(e);
    seed_runtime(e);
}

int mash_mask_load_file(mask_engine_t *e, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int added = 0;
    while ((n = getline(&line, &cap, f)) != -1) {
        /* Strip trailing newline and skip blanks/comments. */
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        /* Syntax: <CAT> <pattern>
         *         literal <CAT> <string> */
        char *sp = strchr(p, ' ');
        if (!sp) continue;
        *sp++ = '\0';
        while (*sp == ' ' || *sp == '\t') sp++;

        bool is_literal = false;
        if (strcmp(p, "literal") == 0) {
            is_literal = true;
            p = sp;
            sp = strchr(p, ' ');
            if (!sp) continue;
            *sp++ = '\0';
            while (*sp == ' ' || *sp == '\t') sp++;
        }

        mask_cat_t cat = MASK_CAT_CUSTOM;
        for (int c = 0; c < MASK_CAT__COUNT; c++) {
            if (CAT_NAMES[c] && strcmp(CAT_NAMES[c], p) == 0) {
                cat = (mask_cat_t)c;
                break;
            }
        }
        int rc = is_literal
            ? mask_add_literal(e, cat, sp)
            : mask_add_pattern(e, cat, sp, NULL);
        if (rc == 0) added++;
    }
    free(line);
    fclose(f);
    return added;
}
