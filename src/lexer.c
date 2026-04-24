/* lexer.c - hand-written scanner.
 *
 * Walks the input one byte at a time, producing tokens. Word assembly is
 * segment-oriented: whenever we switch between unquoted / 'single' /
 * "double" / $-expansion context, we close the current segment and open a
 * new one. The parser + expander therefore know exactly which parts of a
 * word were quoted.
 */

#include "lexer.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/* ---------------------------------------------------- ast helpers (here to
 * keep ast.c tiny without a dedicated .c file). */

word_t *word_new(void) { return xcalloc(1, sizeof(word_t)); }

word_seg_t *wseg_new(wseg_kind_t k, char *text) {
    word_seg_t *s = xcalloc(1, sizeof(*s));
    s->kind = k;
    s->text = text;
    return s;
}

void word_push_seg(word_t *w, word_seg_t *s) {
    if (!w->segs) { w->segs = s; return; }
    word_seg_t *t = w->segs;
    while (t->next) t = t->next;
    t->next = s;
}

void word_free(word_t *w) {
    if (!w) return;
    word_seg_t *s = w->segs;
    while (s) {
        word_seg_t *n = s->next;
        free(s->text);
        word_free(s->child);
        free(s);
        s = n;
    }
    free(w);
}

redir_t *redir_new(void) { return xcalloc(1, sizeof(redir_t)); }

void redir_free(redir_t *r) {
    while (r) {
        redir_t *n = r->next;
        word_free(r->target);
        free(r->heredoc_tag);
        free(r);
        r = n;
    }
}

void assign_free(assign_t *a) {
    while (a) {
        assign_t *n = a->next;
        free(a->name);
        word_free(a->value);
        free(a);
        a = n;
    }
}

node_t *node_new(node_kind_t k) {
    node_t *n = xcalloc(1, sizeof(*n));
    n->kind = k;
    return n;
}

void node_free(node_t *n) {
    if (!n) return;
    switch (n->kind) {
    case N_SIMPLE:
        assign_free(n->u.simple.assigns);
        if (n->u.simple.words) {
            for (size_t i = 0; i < n->u.simple.word_count; i++)
                word_free(n->u.simple.words[i]);
            free(n->u.simple.words);
        }
        redir_free(n->u.simple.redirs);
        break;
    case N_PIPELINE:
        for (size_t i = 0; i < n->u.pipe.count; i++)
            node_free(n->u.pipe.children[i]);
        free(n->u.pipe.children);
        break;
    case N_AND_OR:
        node_free(n->u.andor.left);
        node_free(n->u.andor.right);
        break;
    case N_LIST:
        for (size_t i = 0; i < n->u.list.count; i++)
            node_free(n->u.list.items[i]);
        free(n->u.list.items);
        free(n->u.list.seps);
        break;
    case N_IF:
        node_free(n->u.ifc.cond);
        node_free(n->u.ifc.body);
        node_free(n->u.ifc.elif);
        node_free(n->u.ifc.else_body);
        break;
    case N_WHILE:
    case N_UNTIL:
        node_free(n->u.loop.cond);
        node_free(n->u.loop.body);
        break;
    case N_FOR:
        free(n->u.forc.name);
        for (size_t i = 0; i < n->u.forc.word_count; i++)
            word_free(n->u.forc.words[i]);
        free(n->u.forc.words);
        node_free(n->u.forc.body);
        break;
    case N_CASE: {
        word_free(n->u.casec.subject);
        case_item_t *it = n->u.casec.items;
        while (it) {
            case_item_t *ne = it->next;
            for (size_t i = 0; i < it->pattern_count; i++) word_free(it->patterns[i]);
            free(it->patterns);
            node_free(it->body);
            free(it);
            it = ne;
        }
        break;
    }
    case N_SUBSHELL:
    case N_GROUP:
    case N_NEG:
        node_free(n->u.inner);
        break;
    case N_FUNCDEF:
        free(n->u.funcdef.name);
        node_free(n->u.funcdef.body);
        redir_free(n->u.funcdef.redirs);
        break;
    }
    redir_free(n->redirs);
    free(n);
}

/* ---------------------------------------------------------- token helpers */

static token_t *tok_new(tok_kind_t k) {
    token_t *t = xcalloc(1, sizeof(*t));
    t->kind = k;
    return t;
}

static void list_push(token_list_t *l, token_t *t) {
    if (!l->head) { l->head = l->tail = t; return; }
    l->tail->next = t;
    l->tail = t;
}

void token_list_free(token_list_t *l) {
    token_t *t = l->head;
    while (t) {
        token_t *n = t->next;
        word_free(t->word);
        free(t->name);
        free(t);
        t = n;
    }
    l->head = l->tail = NULL;
}

/* ---------------------------------------------------------- core scanner */

typedef struct {
    const char *src;
    size_t      pos;
    size_t      len;
    int         line;
    int         col;
    char       *err;
} lex_t;

static int peek(lex_t *L, size_t o) {
    return (L->pos + o < L->len) ? (unsigned char)L->src[L->pos + o] : -1;
}
static int eat(lex_t *L) {
    if (L->pos >= L->len) return -1;
    int c = (unsigned char)L->src[L->pos++];
    if (c == '\n') { L->line++; L->col = 1; } else L->col++;
    return c;
}

static void set_err(lex_t *L, const char *msg) {
    if (L->err) return;
    strbuf_t b; strbuf_init(&b);
    strbuf_appendf(&b, "line %d col %d: %s", L->line, L->col, msg);
    L->err = strbuf_detach(&b, NULL);
}

static bool is_meta(int c) {
    return c == '|' || c == '&' || c == ';' || c == '<' || c == '>' ||
           c == '(' || c == ')' || c == ' ' || c == '\t' || c == '\n';
}

/* Scan inside $(...) preserving nesting and quotes; consumes the trailing ).
 * Returns the captured body (without the surrounding $( and )). */
static char *scan_cmdsub(lex_t *L) {
    strbuf_t b; strbuf_init(&b);
    int depth = 1;
    while (L->pos < L->len) {
        int c = eat(L);
        if (c == '\\') {
            strbuf_push(&b, (char)c);
            if (L->pos < L->len) strbuf_push(&b, (char)eat(L));
            continue;
        }
        if (c == '\'') {
            strbuf_push(&b, (char)c);
            while (L->pos < L->len) {
                int d = eat(L);
                strbuf_push(&b, (char)d);
                if (d == '\'') break;
            }
            continue;
        }
        if (c == '"') {
            strbuf_push(&b, (char)c);
            while (L->pos < L->len) {
                int d = eat(L);
                strbuf_push(&b, (char)d);
                if (d == '\\' && L->pos < L->len) strbuf_push(&b, (char)eat(L));
                else if (d == '"') break;
            }
            continue;
        }
        if (c == '$' && peek(L, 0) == '(') {
            strbuf_push(&b, (char)c);
            strbuf_push(&b, (char)eat(L));
            depth++;
            continue;
        }
        if (c == '(') { depth++; strbuf_push(&b, (char)c); continue; }
        if (c == ')') {
            if (--depth == 0) return strbuf_detach(&b, NULL);
            strbuf_push(&b, (char)c);
            continue;
        }
        strbuf_push(&b, (char)c);
    }
    set_err(L, "unterminated $(...)");
    return strbuf_detach(&b, NULL);
}

static char *scan_brace_param(lex_t *L) {
    strbuf_t b; strbuf_init(&b);
    int depth = 1;
    while (L->pos < L->len) {
        int c = eat(L);
        if (c == '{') { depth++; strbuf_push(&b, (char)c); continue; }
        if (c == '}') {
            if (--depth == 0) return strbuf_detach(&b, NULL);
            strbuf_push(&b, (char)c);
            continue;
        }
        if (c == '\\' && L->pos < L->len) {
            strbuf_push(&b, (char)c);
            strbuf_push(&b, (char)eat(L));
            continue;
        }
        strbuf_push(&b, (char)c);
    }
    set_err(L, "unterminated ${...}");
    return strbuf_detach(&b, NULL);
}

/* Append the current literal chunk as a segment. */
static void flush_lit(word_t *w, strbuf_t *buf, wseg_kind_t kind) {
    if (buf->len == 0) return;
    char *t = strbuf_detach(buf, NULL);
    word_push_seg(w, wseg_new(kind, t));
    strbuf_init(buf);
}

/* Scan a word. Returns a freshly allocated word_t; empty segments are
 * collapsed. Stops at unquoted metacharacters. */
static word_t *scan_word(lex_t *L) {
    word_t *w = word_new();
    strbuf_t lit; strbuf_init(&lit);
    bool started = false;

    while (L->pos < L->len) {
        int c = peek(L, 0);

        if (!started && c == '~') {
            /* Tilde at start: accumulate until / or : or end of word. */
            size_t start = L->pos;
            eat(L);
            while (L->pos < L->len) {
                int d = peek(L, 0);
                if (d == '/' || d == ':' || is_meta(d)) break;
                eat(L);
            }
            char *text = xstrndup(L->src + start, L->pos - start);
            word_push_seg(w, wseg_new(WSEG_TILDE, text));
            started = true;
            continue;
        }

        if (!started && !isprint(c) && c != '\t') break;
        if (is_meta(c)) break;

        started = true;

        if (c == '\\') {
            eat(L);
            int d = eat(L);
            if (d == -1) { set_err(L, "dangling backslash"); break; }
            if (d == '\n') continue; /* line continuation */
            strbuf_push(&lit, (char)d);
            continue;
        }

        if (c == '\'') {
            flush_lit(w, &lit, WSEG_LITERAL);
            eat(L);
            strbuf_t s; strbuf_init(&s);
            bool ok = false;
            while (L->pos < L->len) {
                int d = eat(L);
                if (d == '\'') { ok = true; break; }
                strbuf_push(&s, (char)d);
            }
            if (!ok) set_err(L, "unterminated '");
            word_push_seg(w, wseg_new(WSEG_SINGLE, strbuf_detach(&s, NULL)));
            continue;
        }

        if (c == '"') {
            flush_lit(w, &lit, WSEG_LITERAL);
            eat(L);
            /* Collect inner content, preserving $...$()${} markers. */
            word_t *inner = word_new();
            strbuf_t s; strbuf_init(&s);
            bool ok = false;
            while (L->pos < L->len) {
                int d = eat(L);
                if (d == '"') { ok = true; break; }
                if (d == '\\') {
                    int e = eat(L);
                    if (e == -1) break;
                    /* In double quotes, backslash only escapes $ ` " \ and newline. */
                    if (e == '$' || e == '`' || e == '"' || e == '\\' || e == '\n')
                        strbuf_push(&s, (char)e);
                    else {
                        strbuf_push(&s, '\\');
                        strbuf_push(&s, (char)e);
                    }
                    continue;
                }
                if (d == '$') {
                    if (s.len) {
                        char *t = strbuf_detach(&s, NULL);
                        word_push_seg(inner, wseg_new(WSEG_LITERAL, t));
                        strbuf_init(&s);
                    }
                    /* $(...) / ${VAR} / $NAME / $? etc. */
                    int e = peek(L, 0);
                    if (e == '(') {
                        eat(L);
                        char *body = scan_cmdsub(L);
                        word_push_seg(inner, wseg_new(WSEG_CMDSUB, body));
                    } else if (e == '{') {
                        eat(L);
                        char *body = scan_brace_param(L);
                        word_push_seg(inner, wseg_new(WSEG_DOLLAR, body));
                    } else {
                        strbuf_t name; strbuf_init(&name);
                        if (strchr("?$#!@*-0123456789", e) != NULL) {
                            strbuf_push(&name, (char)eat(L));
                        } else if (isalpha(e) || e == '_') {
                            while (L->pos < L->len &&
                                   (isalnum(peek(L, 0)) || peek(L, 0) == '_'))
                                strbuf_push(&name, (char)eat(L));
                        }
                        word_push_seg(inner, wseg_new(WSEG_DOLLAR, strbuf_detach(&name, NULL)));
                    }
                    continue;
                }
                if (d == '`') {
                    if (s.len) {
                        char *t = strbuf_detach(&s, NULL);
                        word_push_seg(inner, wseg_new(WSEG_LITERAL, t));
                        strbuf_init(&s);
                    }
                    strbuf_t body; strbuf_init(&body);
                    while (L->pos < L->len) {
                        int f = eat(L);
                        if (f == '`') break;
                        if (f == '\\' && L->pos < L->len) {
                            int g = eat(L);
                            if (g != '`' && g != '\\' && g != '$')
                                strbuf_push(&body, '\\');
                            strbuf_push(&body, (char)g);
                        } else strbuf_push(&body, (char)f);
                    }
                    word_push_seg(inner, wseg_new(WSEG_CMDSUB, strbuf_detach(&body, NULL)));
                    continue;
                }
                strbuf_push(&s, (char)d);
            }
            if (!ok) set_err(L, "unterminated \"");
            if (s.len) {
                char *t = strbuf_detach(&s, NULL);
                word_push_seg(inner, wseg_new(WSEG_LITERAL, t));
            } else {
                strbuf_free(&s);
            }
            word_seg_t *dq = wseg_new(WSEG_DOUBLE, NULL);
            dq->child = inner;
            word_push_seg(w, dq);
            continue;
        }

        if (c == '$') {
            flush_lit(w, &lit, WSEG_LITERAL);
            eat(L);
            int d = peek(L, 0);
            if (d == '(') {
                eat(L);
                /* Arithmetic $((...)) vs cmdsub $(...) */
                if (peek(L, 0) == '(') {
                    eat(L);
                    /* Collect body until )). */
                    strbuf_t a; strbuf_init(&a);
                    int depth = 1;
                    while (L->pos < L->len) {
                        int e = peek(L, 0);
                        if (e == '(') depth++;
                        else if (e == ')') {
                            if (peek(L, 1) == ')' && depth == 1) {
                                eat(L); eat(L);
                                word_push_seg(w, wseg_new(WSEG_ARITH, strbuf_detach(&a, NULL)));
                                goto arith_done;
                            }
                            depth--;
                        }
                        strbuf_push(&a, (char)eat(L));
                    }
                    set_err(L, "unterminated $((...))");
                    word_push_seg(w, wseg_new(WSEG_ARITH, strbuf_detach(&a, NULL)));
arith_done:;
                } else {
                    char *body = scan_cmdsub(L);
                    word_push_seg(w, wseg_new(WSEG_CMDSUB, body));
                }
            } else if (d == '{') {
                eat(L);
                char *body = scan_brace_param(L);
                word_push_seg(w, wseg_new(WSEG_DOLLAR, body));
            } else {
                strbuf_t name; strbuf_init(&name);
                if (d != -1 && strchr("?$#!@*-0123456789", d) != NULL) {
                    strbuf_push(&name, (char)eat(L));
                } else if (d != -1 && (isalpha(d) || d == '_')) {
                    while (L->pos < L->len &&
                           (isalnum(peek(L, 0)) || peek(L, 0) == '_'))
                        strbuf_push(&name, (char)eat(L));
                } else {
                    /* Lone $ - treat as literal. */
                    strbuf_push(&lit, '$');
                    continue;
                }
                word_push_seg(w, wseg_new(WSEG_DOLLAR, strbuf_detach(&name, NULL)));
            }
            continue;
        }

        if (c == '`') {
            flush_lit(w, &lit, WSEG_LITERAL);
            eat(L);
            strbuf_t body; strbuf_init(&body);
            bool ok = false;
            while (L->pos < L->len) {
                int d = eat(L);
                if (d == '`') { ok = true; break; }
                if (d == '\\' && L->pos < L->len) {
                    int e = eat(L);
                    if (e != '`' && e != '\\' && e != '$')
                        strbuf_push(&body, '\\');
                    strbuf_push(&body, (char)e);
                } else strbuf_push(&body, (char)d);
            }
            if (!ok) set_err(L, "unterminated `");
            word_push_seg(w, wseg_new(WSEG_CMDSUB, strbuf_detach(&body, NULL)));
            continue;
        }

        /* Ordinary byte. */
        strbuf_push(&lit, (char)c);
        eat(L);
    }
    flush_lit(w, &lit, WSEG_LITERAL);
    strbuf_free(&lit);
    return w;
}

/* -------------------------------------------------------- keyword table */

static const struct { const char *s; tok_kind_t k; } KWS[] = {
    { "if", TOK_IF }, { "then", TOK_THEN }, { "elif", TOK_ELIF },
    { "else", TOK_ELSE }, { "fi", TOK_FI },
    { "while", TOK_WHILE }, { "until", TOK_UNTIL },
    { "do", TOK_DO }, { "done", TOK_DONE },
    { "for", TOK_FOR }, { "in", TOK_IN },
    { "case", TOK_CASE }, { "esac", TOK_ESAC },
    { "function", TOK_FUNCTION },
    { "{", TOK_LBRACE }, { "}", TOK_RBRACE },
    { "!", TOK_BANG },
    { NULL, 0 }
};

/* True if the single-segment literal word exactly equals s. */
static bool word_is(const word_t *w, const char *s) {
    if (!w || !w->segs || w->segs->next) return false;
    if (w->segs->kind != WSEG_LITERAL) return false;
    return str_eq(w->segs->text, s);
}

/* Promote a WORD token to a reserved-word token if applicable. The caller
 * must only invoke this in positions where the grammar allows a reserved
 * word (i.e. at the start of a command). */
static void promote_if_keyword(token_t *t) {
    if (t->kind != TOK_WORD) return;
    for (size_t i = 0; KWS[i].s; i++) {
        if (word_is(t->word, KWS[i].s)) {
            word_free(t->word);
            t->word = NULL;
            t->kind = KWS[i].k;
            return;
        }
    }
}

/* A word is an assignment iff it begins with a valid name followed by '='. */
static bool detect_assign(const word_t *w, char **name_out, word_t **rest_out) {
    if (!w || !w->segs) return false;
    if (w->segs->kind != WSEG_LITERAL) return false;
    const char *s = w->segs->text;
    if (!s || !*s) return false;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    size_t i = 0;
    while (s[i] && (isalnum((unsigned char)s[i]) || s[i] == '_')) i++;
    if (s[i] != '=') return false;

    *name_out = xstrndup(s, i);

    word_t *rest = word_new();
    const char *after = s + i + 1;
    if (*after) word_push_seg(rest, wseg_new(WSEG_LITERAL, xstrdup(after)));

    /* Copy any subsequent segments verbatim. */
    for (word_seg_t *p = w->segs->next; p; p = p->next) {
        word_seg_t *c = xcalloc(1, sizeof(*c));
        c->kind = p->kind;
        c->text = p->text ? xstrdup(p->text) : NULL;
        /* Deep child copy isn't needed for assignments in practice since the
         * original word is freed by the caller; we take ownership lazily by
         * duplicating text only. */
        word_push_seg(rest, c);
    }
    *rest_out = rest;
    return true;
}

/* ------------------------------------------------------------- driver */

int lex(const char *src, token_list_t *out, char **err_out) {
    lex_t L = { .src = src, .pos = 0, .len = strlen(src), .line = 1, .col = 1 };
    out->head = out->tail = NULL;
    bool after_cmd_start = true;     /* allow reserved words here */

    while (L.pos < L.len) {
        int c = peek(&L, 0);

        /* Skip unquoted whitespace (but not newline which is a token). */
        if (c == ' ' || c == '\t') { eat(&L); continue; }
        if (c == '\\' && peek(&L, 1) == '\n') { eat(&L); eat(&L); continue; }
        if (c == '#') { /* comment */
            while (L.pos < L.len && peek(&L, 0) != '\n') eat(&L);
            continue;
        }
        if (c == '\n') {
            eat(&L);
            list_push(out, tok_new(TOK_NEWLINE));
            after_cmd_start = true;
            continue;
        }

        /* Operators. */
        if (c == '|') {
            eat(&L);
            if (peek(&L, 0) == '|') { eat(&L); list_push(out, tok_new(TOK_OR)); }
            else                     list_push(out, tok_new(TOK_PIPE));
            after_cmd_start = true;
            continue;
        }
        if (c == '&') {
            eat(&L);
            if (peek(&L, 0) == '&') { eat(&L); list_push(out, tok_new(TOK_AND)); }
            else if (peek(&L, 0) == '>') { eat(&L); list_push(out, tok_new(TOK_REDIR_AMP_OUT)); }
            else                      list_push(out, tok_new(TOK_AMP));
            after_cmd_start = true;
            continue;
        }
        if (c == ';') {
            eat(&L);
            if (peek(&L, 0) == ';') { eat(&L); list_push(out, tok_new(TOK_DSEMI)); }
            else                     list_push(out, tok_new(TOK_SEMI));
            after_cmd_start = true;
            continue;
        }
        if (c == '(') { eat(&L); list_push(out, tok_new(TOK_LPAREN)); after_cmd_start = true; continue; }
        if (c == ')') { eat(&L); list_push(out, tok_new(TOK_RPAREN)); after_cmd_start = true; continue; }
        if (c == '<') {
            eat(&L);
            int d = peek(&L, 0);
            if (d == '<') {
                eat(&L);
                if (peek(&L, 0) == '-') { eat(&L); list_push(out, tok_new(TOK_REDIR_HEREDOC_STRIP)); }
                else list_push(out, tok_new(TOK_REDIR_HEREDOC));
            } else if (d == '&') {
                eat(&L); list_push(out, tok_new(TOK_REDIR_DUP_IN));
            } else if (d == '>') {
                eat(&L); list_push(out, tok_new(TOK_REDIR_INOUT));
            } else {
                list_push(out, tok_new(TOK_REDIR_IN));
            }
            continue;
        }
        if (c == '>') {
            eat(&L);
            int d = peek(&L, 0);
            if (d == '>') { eat(&L); list_push(out, tok_new(TOK_REDIR_APPEND)); }
            else if (d == '&') { eat(&L); list_push(out, tok_new(TOK_REDIR_DUP_OUT)); }
            else if (d == '|') { eat(&L); list_push(out, tok_new(TOK_REDIR_CLOBBER)); }
            else list_push(out, tok_new(TOK_REDIR_OUT));
            continue;
        }

        /* Leading digit that could be IO number: scan digits, if followed
         * by '<' or '>' produce an IO_NUMBER token, else it's a word. */
        if (isdigit(c)) {
            size_t save = L.pos;
            int save_line = L.line, save_col = L.col;
            strbuf_t d; strbuf_init(&d);
            while (L.pos < L.len && isdigit(peek(&L, 0)))
                strbuf_push(&d, (char)eat(&L));
            int nx = peek(&L, 0);
            if (nx == '<' || nx == '>') {
                token_t *t = tok_new(TOK_IO_NUMBER);
                t->io_number = atoi(d.data ? d.data : "0");
                list_push(out, t);
                strbuf_free(&d);
                continue;
            }
            /* Not an IO number - roll back and re-lex as word. */
            L.pos = save;
            L.line = save_line;
            L.col = save_col;
            strbuf_free(&d);
        }

        /* Word. */
        word_t *w = scan_word(&L);
        if (L.err) goto err;
        token_t *t = tok_new(TOK_WORD);
        t->word = w;

        /* Detect leading assignment form. Only honored at cmd-start. */
        char *aname = NULL;
        word_t *arest = NULL;
        if (after_cmd_start && detect_assign(w, &aname, &arest)) {
            word_free(w);
            t->kind = TOK_ASSIGN;
            t->name = aname;
            t->word = arest;
        }
        list_push(out, t);
        /* After a (potential) keyword scan, allow keyword promotion. */
        if (after_cmd_start) promote_if_keyword(t);
        after_cmd_start = false;
    }

    list_push(out, tok_new(TOK_EOF));
    return 0;

err:
    if (err_out) *err_out = L.err ? L.err : xstrdup("lex error");
    token_list_free(out);
    return -1;
}
