/* mask.c - masking engine.
 *
 * Rule storage is a singly linked list in insertion order. Application runs
 * rules sequentially, each one scanning the whole buffer for matches; a
 * replacement is emitted in category form «CATEGORY» unless the rule carries
 * a custom template. Rule ordering matters: more specific rules first
 * (e.g. private key blocks before generic hex secrets).
 *
 * The streaming variant is line-oriented: we accumulate bytes until we see
 * a '\n', then mask_apply the completed line. If the pending buffer grows
 * past `max_line` we flush it unconditionally to bound memory.
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
        char buf[256];
        regerror(rc, &r->re, buf, sizeof(buf));
        fprintf(stderr, "mash: regex compile failed for \"%s\": %s\n",
                pattern, buf);
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
    ms->engine   = e;
    ms->max_line = 64 * 1024;
    strbuf_init(&ms->pending);
}

void mask_stream_free(mask_stream_t *ms) {
    strbuf_free(&ms->pending);
    memset(ms, 0, sizeof(*ms));
}

static void flush_pending(mask_stream_t *ms, strbuf_t *out) {
    if (ms->pending.len == 0) return;
    char  *masked = NULL;
    size_t mlen = 0;
    mask_apply(ms->engine, ms->pending.data, ms->pending.len, &masked, &mlen);
    strbuf_append(out, masked, mlen);
    free(masked);
    strbuf_reset(&ms->pending);
}

void mask_stream_push(mask_stream_t *ms,
                      const char *buf, size_t len,
                      strbuf_t *out) {
    if (len == 0) return;

    /* Heuristic binary detection: too many NULs => stream is likely binary.
     * We still mask, but line-batching would break; instead we fall back to
     * masking each incoming chunk independently. Derived-literal rules are
     * byte-oriented so they still catch the important leaks. */
    for (size_t i = 0; i < len; i++) if (buf[i] == '\0') ms->bytes_null++;
    ms->bytes_total += len;
    if (!ms->binary_detected && ms->bytes_total >= 4096 &&
        ms->bytes_null * 100 >= ms->bytes_total) {
        ms->binary_detected = true;
    }

    if (ms->binary_detected) {
        flush_pending(ms, out);
        char  *m = NULL;
        size_t ml = 0;
        mask_apply(ms->engine, buf, len, &m, &ml);
        strbuf_append(out, m, ml);
        free(m);
        return;
    }

    /* Append; flush each complete line. */
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            strbuf_append(&ms->pending, buf + start, (i - start) + 1);
            flush_pending(ms, out);
            start = i + 1;
        }
    }
    if (start < len) {
        strbuf_append(&ms->pending, buf + start, len - start);
    }

    /* Bound pending to avoid unbounded memory for giant one-liners. */
    if (ms->pending.len >= ms->max_line) {
        flush_pending(ms, out);
    }
}

void mask_stream_finish(mask_stream_t *ms, strbuf_t *out) {
    flush_pending(ms, out);
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
