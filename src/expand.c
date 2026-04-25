/* expand.c - word expansion pipeline.
 *
 * Produces a sequence of final bytes tagged as either "quoted" or
 * "unquoted". Unquoted spans are later split on $IFS and then glob-matched.
 * Internally we use the byte 0x01 as a sentinel to mark the boundaries
 * between sections whose split/glob behavior differs.
 *
 * Sentinels used in internal buffers (stripped before returning to caller):
 *   0x01 : toggle quoted/unquoted context (start/end of a quoted run)
 */

#include "expand.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "env.h"
#include "lexer.h"
#include "mask.h"
#include "mask_fd.h"
#include "parser.h"
#include "util.h"

#define Q_SENTINEL '\x01'

void fields_init(fields_t *f) { f->v = NULL; f->n = f->cap = 0; }
void fields_push(fields_t *f, char *s) {
    if (f->n + 1 >= f->cap) {
        f->cap = f->cap ? f->cap * 2 : 4;
        f->v = xrealloc(f->v, f->cap * sizeof(*f->v));
    }
    f->v[f->n++] = s;
    f->v[f->n] = NULL;
}
void fields_free(fields_t *f) {
    if (!f || !f->v) return;
    for (size_t i = 0; i < f->n; i++) free(f->v[i]);
    free(f->v);
    f->v = NULL; f->n = f->cap = 0;
}

/* ------------------------------------------------ tilde / parameter helpers */

static char *tilde_expand(shell_t *sh, const char *s) {
    if (s[0] != '~') return xstrdup(s);
    const char *rest = s + 1;
    if (!*rest || *rest == '/' || *rest == ':') {
        const char *home = env_get(sh->env, "HOME");
        if (!home) {
            struct passwd *pw = getpwuid(getuid());
            home = pw ? pw->pw_dir : "";
        }
        strbuf_t b; strbuf_init(&b);
        strbuf_appendz(&b, home);
        strbuf_appendz(&b, rest);
        return strbuf_detach(&b, NULL);
    }
    /* ~user[/...] */
    const char *slash = strchr(rest, '/');
    size_t nlen = slash ? (size_t)(slash - rest) : strlen(rest);
    char *user = xstrndup(rest, nlen);
    struct passwd *pw = getpwnam(user);
    free(user);
    if (!pw) return xstrdup(s);
    strbuf_t b; strbuf_init(&b);
    strbuf_appendz(&b, pw->pw_dir);
    if (slash) strbuf_appendz(&b, slash);
    return strbuf_detach(&b, NULL);
}

/* Look up a parameter name. Returns a newly allocated string (possibly
 * empty) describing the value to substitute; *was_set is set to whether
 * the variable actually existed. */
static char *param_lookup(shell_t *sh, const char *name, bool *was_set) {
    *was_set = false;
    if (!name || !*name) return xstrdup("");

    if (str_eq(name, "?")) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", sh->last_status);
        *was_set = true;
        return xstrdup(buf);
    }
    if (str_eq(name, "$")) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%ld", (long)getpid());
        *was_set = true;
        return xstrdup(buf);
    }
    if (str_eq(name, "#")) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%zu", sh->pos_argc);
        *was_set = true;
        return xstrdup(buf);
    }
    if (str_eq(name, "*") || str_eq(name, "@")) {
        strbuf_t b; strbuf_init(&b);
        const char *ifs = env_get(sh->env, "IFS");
        char sep = (ifs && *ifs) ? ifs[0] : ' ';
        for (size_t i = 0; i < sh->pos_argc; i++) {
            if (i) strbuf_push(&b, sep);
            strbuf_appendz(&b, sh->pos_args[i]);
        }
        *was_set = true;
        return strbuf_detach(&b, NULL);
    }
    if (str_eq(name, "-")) {
        strbuf_t b; strbuf_init(&b);
        if (sh->opts.errexit)  strbuf_push(&b, 'e');
        if (sh->opts.nounset)  strbuf_push(&b, 'u');
        if (sh->opts.xtrace)   strbuf_push(&b, 'x');
        if (sh->opts.verbose)  strbuf_push(&b, 'v');
        *was_set = true;
        return strbuf_detach(&b, NULL);
    }
    if (str_eq(name, "!")) { *was_set = true; return xstrdup(""); }
    if (str_eq(name, "0")) { *was_set = true; return xstrdup(sh->progname ? sh->progname : "mash"); }
    if (strlen(name) == 1 && isdigit((unsigned char)name[0])) {
        size_t i = (size_t)(name[0] - '0') - 1;
        if (i < sh->pos_argc) { *was_set = true; return xstrdup(sh->pos_args[i]); }
        return xstrdup("");
    }

    const char *v = env_get(sh->env, name);
    if (v) { *was_set = true; return xstrdup(v); }
    return xstrdup("");
}

/* Parse ${...} body and yield a substituted string. Supports the common
 * forms: NAME, #NAME, NAME:-word, NAME:=word, NAME:?word, NAME:+word,
 * NAME#pat, NAME##pat, NAME%pat, NAME%%pat, NAME/pat/rep, NAME//pat/rep.
 * `word` replacements are *not* re-expanded recursively here (kept simple). */
static char *param_brace(shell_t *sh, const char *body) {
    const char *p = body;
    bool want_len = false;
    if (*p == '#') { want_len = true; p++; }

    /* name */
    const char *name_start = p;
    if (strchr("?$#!@*-", *p)) p++;
    else if (isdigit((unsigned char)*p)) p++;
    else while (isalnum((unsigned char)*p) || *p == '_') p++;
    char *name = xstrndup(name_start, (size_t)(p - name_start));

    bool was_set = false;
    char *val = param_lookup(sh, name, &was_set);

    if (want_len) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%zu", strlen(val));
        free(name);
        free(val);
        return xstrdup(buf);
    }

    if (*p == '\0') { free(name); return val; }

    /* :-, :=, :?, :+ */
    if (*p == ':' && (p[1] == '-' || p[1] == '=' || p[1] == '?' || p[1] == '+')) {
        char op = p[1];
        const char *word = p + 2;
        bool is_empty = !was_set || !*val;
        switch (op) {
        case '-':
            if (is_empty) { free(val); val = xstrdup(word); }
            break;
        case '=':
            if (is_empty) {
                env_set(sh->env, name, word);
                free(val);
                val = xstrdup(word);
            }
            break;
        case '?':
            if (is_empty) mash_err(1, "%s: %s", name, *word ? word : "parameter null or not set");
            break;
        case '+':
            if (!is_empty) { free(val); val = xstrdup(word); }
            else           { free(val); val = xstrdup(""); }
            break;
        }
        free(name);
        return val;
    }

    /* ##, #, %%, % - pattern strip */
    if (*p == '#' || *p == '%') {
        bool greedy = (p[0] == p[1]);
        char kind = *p;
        const char *pat = p + (greedy ? 2 : 1);
        /* Simplified: only support literal prefix/suffix (no globs). */
        size_t pl = strlen(pat);
        size_t vl = strlen(val);
        char *res = val;
        if (pl <= vl) {
            if (kind == '#') {
                if (memcmp(val, pat, pl) == 0) {
                    res = xstrdup(val + pl);
                    free(val);
                }
            } else {
                if (memcmp(val + vl - pl, pat, pl) == 0) {
                    res = xstrndup(val, vl - pl);
                    free(val);
                }
            }
        }
        free(name);
        (void)greedy; /* greedy would differ for globs; we only do literals */
        return res;
    }

    /* /pat/rep or //pat/rep */
    if (*p == '/') {
        bool all = (p[1] == '/');
        const char *pat = p + (all ? 2 : 1);
        const char *slash = strchr(pat, '/');
        char *pattern;
        const char *rep;
        if (slash) {
            pattern = xstrndup(pat, (size_t)(slash - pat));
            rep = slash + 1;
        } else {
            pattern = xstrdup(pat);
            rep = "";
        }
        size_t pl = strlen(pattern);
        strbuf_t b; strbuf_init(&b);
        const char *v = val;
        while (*v) {
            if (pl && strncmp(v, pattern, pl) == 0) {
                strbuf_appendz(&b, rep);
                v += pl;
                if (!all) { strbuf_appendz(&b, v); v += strlen(v); }
            } else {
                strbuf_push(&b, *v++);
            }
        }
        free(pattern);
        free(name);
        free(val);
        return strbuf_detach(&b, NULL);
    }

    free(name);
    return val;
}

/* -------------------------------------------- command substitution capture */

int expand_run_capture(shell_t *sh, const char *src, char **out_str) {
    int pfd[2];
    if (pipe(pfd) < 0) { *out_str = xstrdup(""); return -1; }

    /* Optionally wrap the write end with the mask. */
    mask_fd_t mfd;
    int child_stdout;
    bool wrapped = false;
    if (!sh->opts.nomask_cmdsub) {
        if (mask_fd_wrap_write(sh->mask, pfd[1], true, &mfd) == 0) {
            child_stdout = mfd.write_fd;
            wrapped = true;
        } else {
            child_stdout = pfd[1];
        }
    } else {
        child_stdout = pfd[1];
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        if (wrapped) mask_fd_close(&mfd); else close(pfd[1]);
        *out_str = xstrdup("");
        return -1;
    }
    if (pid == 0) {
        /* child */
        close(pfd[0]);
        if (child_stdout != STDOUT_FILENO) {
            dup2(child_stdout, STDOUT_FILENO);
            close(child_stdout);
        }
        /* stderr remains as masked_stderr from the shell. */
        if (sh->masked_stderr >= 0 && sh->masked_stderr != STDERR_FILENO) {
            dup2(sh->masked_stderr, STDERR_FILENO);
        }
        /* The cmdsub child runs shell code without execing, so CLOEXEC
         * doesn't help. Drop the saved raw fds so a `printf >&3` or
         * similar can't bypass the mask. */
        if (sh->real_stdout >= 0) { close(sh->real_stdout); sh->real_stdout = -1; }
        if (sh->real_stderr >= 0) { close(sh->real_stderr); sh->real_stderr = -1; }
        /* Execute src as shell commands in the same process. */
        int rc = mash_run_string(sh, src, "cmdsub");
        _exit(rc & 0xFF);
    }

    /* parent. When wrapped, the pump OWNS pfd[1] (own_real_fd=true);
     * we must not close pfd[1] ourselves. We only close mfd.write_fd so
     * that the pump sees EOF after the child's copy is also closed. */
    if (wrapped) {
        close(mfd.write_fd);
        mfd.write_fd = -1;
    } else {
        close(pfd[1]);
    }

    strbuf_t b; strbuf_init(&b);
    char buf[4096];
    for (;;) {
        ssize_t n = read(pfd[0], buf, sizeof(buf));
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        strbuf_append(&b, buf, (size_t)n);
    }
    close(pfd[0]);
    if (wrapped) {
        /* mask_fd_close handles every piece of pump teardown:
         *   - write_fd is already -1 (so it's a no-op there)
         *   - joins the pump thread
         *   - closes the drain self-pipe write end
         *   - destroys the drain mutex / condvar
         * Calling pthread_join() directly leaked all of those. */
        mask_fd_close(&mfd);
    }

    int st = 0;
    waitpid(pid, &st, 0);
    sh->last_status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);

    /* Strip trailing newlines (POSIX $() semantics). */
    while (b.len > 0 && b.data[b.len - 1] == '\n') b.data[--b.len] = '\0';

    *out_str = strbuf_detach(&b, NULL);
    return 0;
}

/* ----------------------------------------------------------- arithmetic */

/* Tiny recursive-descent arithmetic evaluator with most C operators. */
typedef struct {
    const char *s;
    shell_t    *sh;
    bool        err;
} arith_t;

static void skip_ws(arith_t *a) { while (*a->s && isspace((unsigned char)*a->s)) a->s++; }
static long arith_expr(arith_t *a);

static long arith_primary(arith_t *a) {
    skip_ws(a);
    if (*a->s == '(') {
        a->s++;
        long v = arith_expr(a);
        skip_ws(a);
        if (*a->s == ')') a->s++;
        else a->err = true;
        return v;
    }
    if (*a->s == '!') { a->s++; return !arith_primary(a); }
    if (*a->s == '~') { a->s++; return ~arith_primary(a); }
    if (*a->s == '-') { a->s++; return -arith_primary(a); }
    if (*a->s == '+') { a->s++; return  arith_primary(a); }
    if (isdigit((unsigned char)*a->s)) {
        char *e;
        long v = strtol(a->s, &e, 0);
        a->s = e;
        return v;
    }
    if (isalpha((unsigned char)*a->s) || *a->s == '_') {
        const char *st = a->s;
        while (isalnum((unsigned char)*a->s) || *a->s == '_') a->s++;
        char *nm = xstrndup(st, (size_t)(a->s - st));
        const char *v = env_get(a->sh->env, nm);
        free(nm);
        return v ? strtol(v, NULL, 0) : 0;
    }
    a->err = true;
    return 0;
}

static long arith_mul(arith_t *a) {
    long l = arith_primary(a);
    for (;;) {
        skip_ws(a);
        char c = *a->s;
        if (c != '*' && c != '/' && c != '%') break;
        a->s++;
        long r = arith_primary(a);
        if (c == '*') l = l * r;
        else if (c == '/') l = r ? l / r : 0;
        else               l = r ? l % r : 0;
    }
    return l;
}
static long arith_add(arith_t *a) {
    long l = arith_mul(a);
    for (;;) {
        skip_ws(a);
        char c = *a->s;
        if (c != '+' && c != '-') break;
        a->s++;
        long r = arith_mul(a);
        if (c == '+') l += r; else l -= r;
    }
    return l;
}
static long arith_shift(arith_t *a) {
    long l = arith_add(a);
    for (;;) {
        skip_ws(a);
        if (a->s[0] == '<' && a->s[1] == '<') { a->s += 2; l <<= arith_add(a); }
        else if (a->s[0] == '>' && a->s[1] == '>') { a->s += 2; l >>= arith_add(a); }
        else break;
    }
    return l;
}
static long arith_rel(arith_t *a) {
    long l = arith_shift(a);
    for (;;) {
        skip_ws(a);
        if (a->s[0] == '<' && a->s[1] == '=') { a->s += 2; l = l <= arith_shift(a); }
        else if (a->s[0] == '>' && a->s[1] == '=') { a->s += 2; l = l >= arith_shift(a); }
        else if (a->s[0] == '<') { a->s++; l = l < arith_shift(a); }
        else if (a->s[0] == '>') { a->s++; l = l > arith_shift(a); }
        else break;
    }
    return l;
}
static long arith_eq(arith_t *a) {
    long l = arith_rel(a);
    for (;;) {
        skip_ws(a);
        if (a->s[0] == '=' && a->s[1] == '=') { a->s += 2; l = l == arith_rel(a); }
        else if (a->s[0] == '!' && a->s[1] == '=') { a->s += 2; l = l != arith_rel(a); }
        else break;
    }
    return l;
}
static long arith_band(arith_t *a) { long l = arith_eq(a); while ((skip_ws(a), *a->s == '&' && a->s[1] != '&')) { a->s++; l &= arith_eq(a); } return l; }
static long arith_bxor(arith_t *a) { long l = arith_band(a); while ((skip_ws(a), *a->s == '^')) { a->s++; l ^= arith_band(a); } return l; }
static long arith_bor (arith_t *a) { long l = arith_bxor(a); while ((skip_ws(a), *a->s == '|' && a->s[1] != '|')) { a->s++; l |= arith_bxor(a); } return l; }
static long arith_land(arith_t *a) {
    long l = arith_bor(a);
    while ((skip_ws(a), a->s[0] == '&' && a->s[1] == '&')) { a->s += 2; long r = arith_bor(a); l = l && r; }
    return l;
}
static long arith_lor(arith_t *a) {
    long l = arith_land(a);
    while ((skip_ws(a), a->s[0] == '|' && a->s[1] == '|')) { a->s += 2; long r = arith_land(a); l = l || r; }
    return l;
}
static long arith_expr(arith_t *a) {
    long c = arith_lor(a);
    skip_ws(a);
    if (*a->s == '?') {
        a->s++;
        long t = arith_expr(a);
        skip_ws(a);
        if (*a->s == ':') a->s++;
        long f = arith_expr(a);
        return c ? t : f;
    }
    return c;
}

static char *arith_eval(shell_t *sh, const char *src) {
    arith_t a = { .s = src, .sh = sh, .err = false };
    long v = arith_expr(&a);
    /* Trailing junk in the expression also indicates a syntax error. */
    skip_ws(&a);
    if (a.err || *a.s) {
        mash_err(1, "arithmetic: syntax error in '%s'", src);
        return xstrdup("0");
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%ld", v);
    return xstrdup(buf);
}

/* ------------------------------------------------------- word walker */

/* Append raw text inside a quoted context (wrapped by sentinels). */
static void emit_quoted(strbuf_t *b, const char *s, size_t n) {
    strbuf_push(b, Q_SENTINEL);
    for (size_t i = 0; i < n; i++) {
        /* Escape sentinel byte if it appears in data. */
        strbuf_push(b, s[i] == Q_SENTINEL ? ' ' : s[i]);
    }
    strbuf_push(b, Q_SENTINEL);
}

static void expand_segs(shell_t *sh, const word_t *w, strbuf_t *b,
                        bool inside_dq);

static void expand_one_seg(shell_t *sh, const word_seg_t *s, strbuf_t *b,
                           bool inside_dq) {
    switch (s->kind) {
    case WSEG_LITERAL:
        if (inside_dq) {
            emit_quoted(b, s->text, strlen(s->text));
        } else {
            strbuf_appendz(b, s->text);
        }
        break;
    case WSEG_SINGLE:
        emit_quoted(b, s->text, strlen(s->text));
        break;
    case WSEG_DOUBLE: {
        /* Recurse into children; force inside_dq. */
        expand_segs(sh, s->child, b, true);
        break;
    }
    case WSEG_TILDE: {
        char *e = tilde_expand(sh, s->text);
        if (inside_dq) emit_quoted(b, e, strlen(e));
        else           strbuf_appendz(b, e);
        free(e);
        break;
    }
    case WSEG_DOLLAR: {
        char *v;
        if (strchr("?$#!@*-", s->text[0]) || isdigit((unsigned char)s->text[0]) ||
            isalpha((unsigned char)s->text[0]) || s->text[0] == '_') {
            /* Maybe simple name or a ${...} brace body. If body contains
             * ':', '#', '%', '/' then it's a brace body. */
            if (strpbrk(s->text, ":#%/")) {
                v = param_brace(sh, s->text);
            } else {
                bool was_set = false;
                v = param_lookup(sh, s->text, &was_set);
                if (sh->opts.nounset && !was_set) {
                    mash_err(1, "%s: unbound variable", s->text);
                }
            }
        } else {
            /* Assume brace body. */
            v = param_brace(sh, s->text);
        }
        if (inside_dq) emit_quoted(b, v, strlen(v));
        else           strbuf_appendz(b, v);
        free(v);
        break;
    }
    case WSEG_CMDSUB: {
        char *out = NULL;
        expand_run_capture(sh, s->text, &out);
        if (inside_dq) emit_quoted(b, out, strlen(out));
        else           strbuf_appendz(b, out);
        free(out);
        break;
    }
    case WSEG_ARITH: {
        char *v = arith_eval(sh, s->text);
        if (inside_dq) emit_quoted(b, v, strlen(v));
        else           strbuf_appendz(b, v);
        free(v);
        break;
    }
    }
}

static void expand_segs(shell_t *sh, const word_t *w, strbuf_t *b,
                        bool inside_dq) {
    if (!w) return;
    for (word_seg_t *s = w->segs; s; s = s->next)
        expand_one_seg(sh, s, b, inside_dq);
}

/* ------------------------------------------------- field splitting / glob */

/* Does the string contain unquoted glob magic?
 * already-stripped string (we dropped sentinels before this call). We use a
 * shadow buffer with sentinels to tell unquoted magic from quoted literals.*/
static bool has_unquoted_glob(const char *s_with_sent) {
    bool quoted = false;
    for (const char *p = s_with_sent; *p; p++) {
        if (*p == Q_SENTINEL) { quoted = !quoted; continue; }
        if (!quoted && (*p == '*' || *p == '?' || *p == '[')) return true;
    }
    return false;
}

/* Strip sentinels. */
static char *strip_sentinels(const char *s, size_t len) {
    strbuf_t b; strbuf_init(&b);
    for (size_t i = 0; i < len; i++) if (s[i] != Q_SENTINEL) strbuf_push(&b, s[i]);
    return strbuf_detach(&b, NULL);
}

/* Glob a field. On no match returns the original string unchanged. */
static void glob_field(const char *field_with_sent, fields_t *out) {
    bool glob_it = has_unquoted_glob(field_with_sent);
    char *plain = strip_sentinels(field_with_sent, strlen(field_with_sent));
    if (!glob_it) { fields_push(out, plain); return; }

    glob_t g;
    int rc = glob(plain, GLOB_NOCHECK | GLOB_BRACE | GLOB_TILDE, NULL, &g);
    if (rc == 0 && g.gl_pathc > 0) {
        for (size_t i = 0; i < g.gl_pathc; i++)
            fields_push(out, xstrdup(g.gl_pathv[i]));
        globfree(&g);
        free(plain);
        return;
    }
    if (rc == 0) globfree(&g);
    fields_push(out, plain);
}

/* --------------------------------------------------------------- public */

int expand_word(shell_t *sh, const word_t *w, fields_t *out,
                bool assignment_context, bool expand_glob) {
    strbuf_t raw; strbuf_init(&raw);
    expand_segs(sh, w, &raw, false);

    if (assignment_context) {
        /* No splitting/globbing. Strip sentinels and return as single. */
        char *s = strip_sentinels(raw.data ? raw.data : "", raw.len);
        fields_push(out, s);
        strbuf_free(&raw);
        return 0;
    }

    /* Split into fields preserving sentinels inside each field. */
    fields_t tmp; fields_init(&tmp);
    /* We split on IFS but need to preserve sentinels inside a field for
     * glob detection. Reimplement the split over raw including sentinels. */
    {
        const char *ifs = env_get(sh->env, "IFS");
        if (!ifs) ifs = " \t\n";
        strbuf_t cur; strbuf_init(&cur);
        bool quoted = false;
        bool has_field = false;
        for (size_t i = 0; i < raw.len; i++) {
            char c = raw.data[i];
            if (c == Q_SENTINEL) { quoted = !quoted; has_field = true; strbuf_push(&cur, c); continue; }
            if (!quoted && strchr(ifs, c)) {
                if (has_field || cur.len) { fields_push(&tmp, strbuf_detach(&cur, NULL)); strbuf_init(&cur); has_field = false; }
                continue;
            }
            strbuf_push(&cur, c);
            has_field = true;
        }
        if (has_field || cur.len) fields_push(&tmp, strbuf_detach(&cur, NULL));
        else strbuf_free(&cur);
    }
    strbuf_free(&raw);

    for (size_t i = 0; i < tmp.n; i++) {
        if (expand_glob) glob_field(tmp.v[i], out);
        else fields_push(out, strip_sentinels(tmp.v[i], strlen(tmp.v[i])));
    }
    fields_free(&tmp);
    return 0;
}

char *expand_redir_target(shell_t *sh, const word_t *w) {
    strbuf_t raw; strbuf_init(&raw);
    expand_segs(sh, w, &raw, false);
    char *s = strip_sentinels(raw.data ? raw.data : "", raw.len);
    strbuf_free(&raw);
    return s;
}

char *expand_assign_value(shell_t *sh, const word_t *w) {
    return expand_redir_target(sh, w);
}
