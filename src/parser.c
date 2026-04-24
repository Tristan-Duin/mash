/* parser.c - recursive descent parser over token_t.
 *
 * Grammar:
 *   list       := and_or ((';' | '&' | NL) and_or)* [';' | '&' | NL]
 *   and_or     := pipeline (( '&&' | '||' ) NL* pipeline)*
 *   pipeline   := ['!'] command ('|' NL* command)*
 *   command    := simple | compound
 *   compound   := if | while | until | for | case
 *               | subshell | group | funcdef
 *   simple     := (assign | redir)* WORD (WORD | assign | redir)*
 *
 * Redirections may appear anywhere inside a simple command.
 */

#include "parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

typedef struct {
    token_t *cur;
    char    *err;
} P;

static token_t *at(P *p)            { return p->cur; }
static tok_kind_t peek_k(P *p)      { return p->cur ? p->cur->kind : TOK_EOF; }
static void advance(P *p)           { if (p->cur) p->cur = p->cur->next; }
static bool eat_tok(P *p, tok_kind_t k) {
    if (peek_k(p) == k) { advance(p); return true; }
    return false;
}
static void skip_newlines(P *p) { while (peek_k(p) == TOK_NEWLINE) advance(p); }

static void perror_at(P *p, const char *fmt, ...) {
    if (p->err) return;
    va_list ap;
    va_start(ap, fmt);
    strbuf_t b; strbuf_init(&b);
    if (p->cur) strbuf_appendf(&b, "line %d col %d: ", p->cur->line, p->cur->col);
    strbuf_vappendf(&b, fmt, ap);
    va_end(ap);
    p->err = strbuf_detach(&b, NULL);
}

/* Forward decls. */
static node_t *parse_list_in(P *p, const tok_kind_t *stops, size_t nstops);
static node_t *parse_command(P *p);
static node_t *parse_compound(P *p);

/* ------------------------------------------------------------ redirection */

static redir_op_t redir_op_from_tok(tok_kind_t k) {
    switch (k) {
    case TOK_REDIR_IN:            return R_IN;
    case TOK_REDIR_OUT:           return R_OUT;
    case TOK_REDIR_APPEND:        return R_APPEND;
    case TOK_REDIR_HEREDOC:       return R_HEREDOC;
    case TOK_REDIR_HEREDOC_STRIP: return R_HEREDOC_STRIP;
    case TOK_REDIR_DUP_IN:        return R_DUP_IN;
    case TOK_REDIR_DUP_OUT:       return R_DUP_OUT;
    case TOK_REDIR_CLOBBER:       return R_CLOBBER_OUT;
    case TOK_REDIR_INOUT:         return R_IN_OUT;
    case TOK_REDIR_AMP_OUT:       return R_OUT;   /* &> - handled specially */
    default:                      return R_OUT;
    }
}

static bool is_redir_tok(tok_kind_t k) {
    switch (k) {
    case TOK_REDIR_IN: case TOK_REDIR_OUT: case TOK_REDIR_APPEND:
    case TOK_REDIR_HEREDOC: case TOK_REDIR_HEREDOC_STRIP:
    case TOK_REDIR_DUP_IN: case TOK_REDIR_DUP_OUT:
    case TOK_REDIR_CLOBBER: case TOK_REDIR_INOUT:
    case TOK_REDIR_AMP_OUT:
        return true;
    default: return false;
    }
}

/* parse a redirection given (possibly) the preceding io_number, and the
 * current token is the redirection operator. Consumes op + target. */
static redir_t *parse_redir(P *p, int io_number) {
    tok_kind_t opk = peek_k(p);
    redir_t *r = redir_new();
    r->io = io_number;
    r->op = redir_op_from_tok(opk);
    bool amp_out = (opk == TOK_REDIR_AMP_OUT);
    advance(p);

    if (peek_k(p) != TOK_WORD) {
        perror_at(p, "expected filename after redirection");
        redir_free(r);
        return NULL;
    }
    r->target = at(p)->word;
    at(p)->word = NULL;
    advance(p);

    /* &> foo means both stdout and stderr to foo: emulate by building a
     * second redirection for fd 2 duplicating fd 1. We chain them. */
    if (amp_out) {
        r->io = 1;
        redir_t *dup2err = redir_new();
        dup2err->io = 2;
        dup2err->op = R_DUP_OUT;
        /* target is literal "1" */
        word_t *w = word_new();
        word_push_seg(w, wseg_new(WSEG_LITERAL, xstrdup("1")));
        dup2err->target = w;
        r->next = dup2err;
    }
    return r;
}

/* ------------------------------------------------------------------ simple */

/* Append assignment / redirection / word to the simple command being built. */
typedef struct {
    assign_t *ah;
    assign_t *at;
    redir_t  *rh;
    redir_t  *rt;
    size_t    word_cap, word_count;
    word_t  **words;
} simple_builder;

static void sb_init(simple_builder *s) { memset(s, 0, sizeof(*s)); }
static void sb_add_assign(simple_builder *s, assign_t *a) {
    if (!s->ah) s->ah = s->at = a;
    else { s->at->next = a; s->at = a; }
}
static void sb_add_redir(simple_builder *s, redir_t *r) {
    if (!s->rh) s->rh = s->rt = r;
    else { s->rt->next = r; s->rt = r; }
    while (s->rt->next) s->rt = s->rt->next;
}
static void sb_add_word(simple_builder *s, word_t *w) {
    if (s->word_count + 1 >= s->word_cap) {
        s->word_cap = s->word_cap ? s->word_cap * 2 : 4;
        s->words = xrealloc(s->words, s->word_cap * sizeof(*s->words));
    }
    s->words[s->word_count++] = w;
}
static void sb_finalize(simple_builder *s, simple_t *out) {
    out->assigns = s->ah;
    out->redirs  = s->rh;
    out->words   = s->words;
    out->word_count = s->word_count;
}

static node_t *parse_simple(P *p) {
    simple_builder s; sb_init(&s);
    bool got_any = false;

    while (1) {
        /* Redirection (optionally prefixed by IO_NUMBER). */
        if (peek_k(p) == TOK_IO_NUMBER) {
            int io = at(p)->io_number;
            advance(p);
            if (!is_redir_tok(peek_k(p))) {
                perror_at(p, "expected redirection after fd number");
                goto err;
            }
            redir_t *r = parse_redir(p, io);
            if (!r) goto err;
            sb_add_redir(&s, r);
            got_any = true;
            continue;
        }
        if (is_redir_tok(peek_k(p))) {
            redir_t *r = parse_redir(p, -1);
            if (!r) goto err;
            sb_add_redir(&s, r);
            got_any = true;
            continue;
        }

        if (peek_k(p) == TOK_ASSIGN && s.word_count == 0) {
            assign_t *a = xcalloc(1, sizeof(*a));
            a->name  = at(p)->name;
            a->value = at(p)->word;
            at(p)->name = NULL;
            at(p)->word = NULL;
            advance(p);
            sb_add_assign(&s, a);
            got_any = true;
            continue;
        }

        /* Treat reserved-word tokens as plain words after the first word. */
        if (peek_k(p) == TOK_WORD) {
            word_t *w = at(p)->word;
            at(p)->word = NULL;
            advance(p);
            sb_add_word(&s, w);
            got_any = true;
            continue;
        }
        break;
    }

    if (!got_any) {
        perror_at(p, "expected command");
        goto err;
    }

    node_t *n = node_new(N_SIMPLE);
    sb_finalize(&s, &n->u.simple);
    return n;

err:
    assign_free(s.ah);
    redir_free(s.rh);
    if (s.words) {
        for (size_t i = 0; i < s.word_count; i++) word_free(s.words[i]);
        free(s.words);
    }
    return NULL;
}

/* ---------------------------------------------------------------- compound */

static node_t *parse_if(P *p) {
    advance(p); /* consume if */
    static const tok_kind_t stops_then[] = { TOK_THEN };
    node_t *cond = parse_list_in(p, stops_then, 1);
    if (!cond) return NULL;
    if (!eat_tok(p, TOK_THEN)) { perror_at(p, "expected 'then'"); node_free(cond); return NULL; }
    skip_newlines(p);
    static const tok_kind_t stops_body[] = { TOK_ELIF, TOK_ELSE, TOK_FI };
    node_t *body = parse_list_in(p, stops_body, 3);
    if (!body) { node_free(cond); return NULL; }

    node_t *n = node_new(N_IF);
    n->u.ifc.cond = cond;
    n->u.ifc.body = body;

    if (peek_k(p) == TOK_ELIF) {
        node_t *elif = parse_if(p);
        if (!elif) { node_free(n); return NULL; }
        n->u.ifc.elif = elif;
        return n;
    }
    if (peek_k(p) == TOK_ELSE) {
        advance(p);
        skip_newlines(p);
        static const tok_kind_t stops_else[] = { TOK_FI };
        node_t *eb = parse_list_in(p, stops_else, 1);
        if (!eb) { node_free(n); return NULL; }
        n->u.ifc.else_body = eb;
    }
    if (!eat_tok(p, TOK_FI)) { perror_at(p, "expected 'fi'"); node_free(n); return NULL; }
    return n;
}

static node_t *parse_loop(P *p, node_kind_t kind) {
    advance(p); /* consume while/until */
    static const tok_kind_t stops_do[] = { TOK_DO };
    node_t *cond = parse_list_in(p, stops_do, 1);
    if (!cond) return NULL;
    if (!eat_tok(p, TOK_DO)) { perror_at(p, "expected 'do'"); node_free(cond); return NULL; }
    skip_newlines(p);
    static const tok_kind_t stops_done[] = { TOK_DONE };
    node_t *body = parse_list_in(p, stops_done, 1);
    if (!body) { node_free(cond); return NULL; }
    if (!eat_tok(p, TOK_DONE)) { perror_at(p, "expected 'done'"); node_free(cond); node_free(body); return NULL; }
    node_t *n = node_new(kind);
    n->u.loop.cond = cond;
    n->u.loop.body = body;
    return n;
}

static node_t *parse_for(P *p) {
    advance(p); /* consume 'for' */
    if (peek_k(p) != TOK_WORD) { perror_at(p, "expected name after 'for'"); return NULL; }
    /* Name must be a single literal segment. */
    word_t *nm = at(p)->word;
    char *name = NULL;
    if (nm && nm->segs && !nm->segs->next && nm->segs->kind == WSEG_LITERAL) {
        name = xstrdup(nm->segs->text);
    } else {
        perror_at(p, "invalid variable name");
        return NULL;
    }
    at(p)->word = NULL;
    word_free(nm);
    advance(p);

    node_t *n = node_new(N_FOR);
    n->u.forc.name = name;

    skip_newlines(p);
    if (peek_k(p) == TOK_IN) {
        advance(p);
        n->u.forc.in_seen = true;
        size_t cap = 0, cnt = 0;
        word_t **arr = NULL;
        while (peek_k(p) == TOK_WORD) {
            if (cnt + 1 >= cap) {
                cap = cap ? cap * 2 : 4;
                arr = xrealloc(arr, cap * sizeof(*arr));
            }
            arr[cnt++] = at(p)->word;
            at(p)->word = NULL;
            advance(p);
        }
        n->u.forc.words = arr;
        n->u.forc.word_count = cnt;
    }

    /* terminator (; or newline) then do ... done */
    while (peek_k(p) == TOK_SEMI || peek_k(p) == TOK_NEWLINE) advance(p);
    if (!eat_tok(p, TOK_DO)) { perror_at(p, "expected 'do'"); node_free(n); return NULL; }
    skip_newlines(p);
    static const tok_kind_t stops_done[] = { TOK_DONE };
    node_t *body = parse_list_in(p, stops_done, 1);
    if (!body) { node_free(n); return NULL; }
    if (!eat_tok(p, TOK_DONE)) { perror_at(p, "expected 'done'"); node_free(n); node_free(body); return NULL; }
    n->u.forc.body = body;
    return n;
}

static node_t *parse_case(P *p) {
    advance(p); /* case */
    if (peek_k(p) != TOK_WORD) { perror_at(p, "expected word after 'case'"); return NULL; }
    word_t *subj = at(p)->word;
    at(p)->word = NULL;
    advance(p);
    skip_newlines(p);
    if (!eat_tok(p, TOK_IN)) { perror_at(p, "expected 'in'"); word_free(subj); return NULL; }
    skip_newlines(p);

    node_t *n = node_new(N_CASE);
    n->u.casec.subject = subj;

    case_item_t **tail = &n->u.casec.items;
    while (peek_k(p) != TOK_ESAC && peek_k(p) != TOK_EOF) {
        /* optional leading ( */
        eat_tok(p, TOK_LPAREN);
        size_t cap = 0, cnt = 0;
        word_t **pats = NULL;
        if (peek_k(p) == TOK_WORD) {
            for (;;) {
                if (cnt + 1 >= cap) {
                    cap = cap ? cap * 2 : 2;
                    pats = xrealloc(pats, cap * sizeof(*pats));
                }
                pats[cnt++] = at(p)->word;
                at(p)->word = NULL;
                advance(p);
                if (peek_k(p) == TOK_PIPE) { advance(p); continue; }
                break;
            }
        }
        if (!eat_tok(p, TOK_RPAREN)) { perror_at(p, "expected ')'"); node_free(n); return NULL; }
        skip_newlines(p);

        static const tok_kind_t stops_item[] = { TOK_DSEMI, TOK_ESAC };
        node_t *body = parse_list_in(p, stops_item, 2);

        case_item_t *it = xcalloc(1, sizeof(*it));
        it->patterns = pats;
        it->pattern_count = cnt;
        it->body = body;
        *tail = it;
        tail = &it->next;

        if (peek_k(p) == TOK_DSEMI) { advance(p); skip_newlines(p); continue; }
        break;
    }
    if (!eat_tok(p, TOK_ESAC)) { perror_at(p, "expected 'esac'"); node_free(n); return NULL; }
    return n;
}

static node_t *parse_subshell(P *p) {
    advance(p); /* ( */
    static const tok_kind_t stops[] = { TOK_RPAREN };
    node_t *body = parse_list_in(p, stops, 1);
    if (!body) return NULL;
    if (!eat_tok(p, TOK_RPAREN)) { perror_at(p, "expected ')'"); node_free(body); return NULL; }
    node_t *n = node_new(N_SUBSHELL);
    n->u.inner = body;
    return n;
}

static node_t *parse_group(P *p) {
    advance(p); /* { */
    skip_newlines(p);
    static const tok_kind_t stops[] = { TOK_RBRACE };
    node_t *body = parse_list_in(p, stops, 1);
    if (!body) return NULL;
    if (!eat_tok(p, TOK_RBRACE)) { perror_at(p, "expected '}'"); node_free(body); return NULL; }
    node_t *n = node_new(N_GROUP);
    n->u.inner = body;
    return n;
}

/* function def:   NAME ( ) compound
 * or:             function NAME [()] compound */
static node_t *parse_funcdef_named(P *p, char *name) {
    node_t *body = NULL;
    if (peek_k(p) == TOK_LBRACE)       body = parse_group(p);
    else if (peek_k(p) == TOK_LPAREN)  body = parse_subshell(p);
    else { perror_at(p, "expected function body"); free(name); return NULL; }
    if (!body) { free(name); return NULL; }
    node_t *n = node_new(N_FUNCDEF);
    n->u.funcdef.name = name;
    n->u.funcdef.body = body;
    return n;
}

static node_t *parse_compound(P *p) {
    switch (peek_k(p)) {
    case TOK_IF:     return parse_if(p);
    case TOK_WHILE:  return parse_loop(p, N_WHILE);
    case TOK_UNTIL:  return parse_loop(p, N_UNTIL);
    case TOK_FOR:    return parse_for(p);
    case TOK_CASE:   return parse_case(p);
    case TOK_LPAREN: return parse_subshell(p);
    case TOK_LBRACE: return parse_group(p);
    case TOK_FUNCTION: {
        advance(p);
        if (peek_k(p) != TOK_WORD) { perror_at(p, "expected name"); return NULL; }
        word_t *nm = at(p)->word;
        if (!nm || !nm->segs || nm->segs->next || nm->segs->kind != WSEG_LITERAL) {
            perror_at(p, "invalid function name");
            return NULL;
        }
        char *name = xstrdup(nm->segs->text);
        at(p)->word = NULL;
        word_free(nm);
        advance(p);
        if (eat_tok(p, TOK_LPAREN)) {
            if (!eat_tok(p, TOK_RPAREN)) { perror_at(p, "expected ')'"); free(name); return NULL; }
        }
        skip_newlines(p);
        return parse_funcdef_named(p, name);
    }
    default: return NULL;
    }
}

/* ---------------------------------------------------------------- command */

/* Check for POSIX-form funcdef: WORD '(' ')' compound
 * Requires lookahead of 2 tokens. */
static bool looks_like_funcdef(P *p) {
    if (peek_k(p) != TOK_WORD) return false;
    token_t *t1 = p->cur->next;
    token_t *t2 = t1 ? t1->next : NULL;
    return t1 && t2 && t1->kind == TOK_LPAREN && t2->kind == TOK_RPAREN;
}

static node_t *parse_command(P *p) {
    if (peek_k(p) == TOK_BANG) {
        advance(p);
        node_t *inner = parse_command(p);
        if (!inner) return NULL;
        node_t *n = node_new(N_NEG);
        n->u.inner = inner;
        return n;
    }

    if (looks_like_funcdef(p)) {
        word_t *nm = at(p)->word;
        if (!nm || !nm->segs || nm->segs->next || nm->segs->kind != WSEG_LITERAL) {
            perror_at(p, "invalid function name");
            return NULL;
        }
        char *name = xstrdup(nm->segs->text);
        at(p)->word = NULL;
        word_free(nm);
        advance(p);            /* WORD */
        advance(p);            /* ( */
        advance(p);            /* ) */
        skip_newlines(p);
        return parse_funcdef_named(p, name);
    }

    switch (peek_k(p)) {
    case TOK_IF: case TOK_WHILE: case TOK_UNTIL: case TOK_FOR:
    case TOK_CASE: case TOK_LPAREN: case TOK_LBRACE: case TOK_FUNCTION:
        return parse_compound(p);
    default:
        return parse_simple(p);
    }
}

/* Optional trailing redirections for pipelines / compound commands. */
static int parse_trailing_redirs(P *p, redir_t **head) {
    *head = NULL;
    redir_t *tail = NULL;
    while (is_redir_tok(peek_k(p)) || peek_k(p) == TOK_IO_NUMBER) {
        int io = -1;
        if (peek_k(p) == TOK_IO_NUMBER) { io = at(p)->io_number; advance(p); }
        if (!is_redir_tok(peek_k(p))) { perror_at(p, "expected redirection"); return -1; }
        redir_t *r = parse_redir(p, io);
        if (!r) return -1;
        if (!*head) *head = r;
        else tail->next = r;
        tail = r;
        while (tail->next) tail = tail->next;
    }
    return 0;
}

/* ------------------------------------------------------------- pipeline */

static node_t *parse_pipeline(P *p) {
    size_t cap = 0, cnt = 0;
    node_t **arr = NULL;
    node_t *first = parse_command(p);
    if (!first) return NULL;
    if (cnt + 1 >= cap) { cap = cap ? cap * 2 : 2; arr = xrealloc(arr, cap * sizeof(*arr)); }
    arr[cnt++] = first;

    while (peek_k(p) == TOK_PIPE) {
        advance(p);
        skip_newlines(p);
        node_t *c = parse_command(p);
        if (!c) { for (size_t i = 0; i < cnt; i++) node_free(arr[i]); free(arr); return NULL; }
        if (cnt + 1 >= cap) { cap *= 2; arr = xrealloc(arr, cap * sizeof(*arr)); }
        arr[cnt++] = c;
    }

    /* Trailing redirs attach to the last command in the pipeline. */
    redir_t *trailing = NULL;
    if (parse_trailing_redirs(p, &trailing) < 0) {
        for (size_t i = 0; i < cnt; i++) node_free(arr[i]);
        free(arr);
        redir_free(trailing);
        return NULL;
    }
    if (trailing) {
        node_t *last = arr[cnt - 1];
        if (last->kind == N_SIMPLE) {
            redir_t *end = last->u.simple.redirs;
            if (!end) last->u.simple.redirs = trailing;
            else {
                while (end->next) end = end->next;
                end->next = trailing;
            }
        } else {
            redir_t *end = last->redirs;
            if (!end) last->redirs = trailing;
            else {
                while (end->next) end = end->next;
                end->next = trailing;
            }
        }
    }

    if (cnt == 1) { node_t *only = arr[0]; free(arr); return only; }
    node_t *n = node_new(N_PIPELINE);
    n->u.pipe.children = arr;
    n->u.pipe.count = cnt;
    return n;
}

/* -------------------------------------------------------------- and/or */

static node_t *parse_and_or(P *p) {
    node_t *left = parse_pipeline(p);
    if (!left) return NULL;
    while (peek_k(p) == TOK_AND || peek_k(p) == TOK_OR) {
        ao_op_t op = (peek_k(p) == TOK_AND) ? AND_OP : OR_OP;
        advance(p);
        skip_newlines(p);
        node_t *right = parse_pipeline(p);
        if (!right) { node_free(left); return NULL; }
        node_t *n = node_new(N_AND_OR);
        n->u.andor.op = op;
        n->u.andor.left = left;
        n->u.andor.right = right;
        left = n;
    }
    return left;
}

/* ---------------------------------------------------------------- list */

static bool is_list_sep(tok_kind_t k) {
    return k == TOK_SEMI || k == TOK_AMP || k == TOK_NEWLINE;
}

static bool in_set(tok_kind_t k, const tok_kind_t *set, size_t n) {
    for (size_t i = 0; i < n; i++) if (set[i] == k) return true;
    return false;
}

static node_t *parse_list_in(P *p, const tok_kind_t *stops, size_t nstops) {
    skip_newlines(p);
    size_t cap = 0, cnt = 0;
    node_t **items = NULL;
    sep_t   *seps  = NULL;

    while (peek_k(p) != TOK_EOF && !in_set(peek_k(p), stops, nstops)) {
        node_t *ao = parse_and_or(p);
        if (!ao) {
            for (size_t i = 0; i < cnt; i++) node_free(items[i]);
            free(items);
            free(seps);
            return NULL;
        }
        if (cnt + 1 >= cap) {
            cap = cap ? cap * 2 : 4;
            items = xrealloc(items, cap * sizeof(*items));
            seps  = xrealloc(seps,  cap * sizeof(*seps));
        }
        items[cnt] = ao;
        sep_t sep = SEP_SEMI;
        if (is_list_sep(peek_k(p))) {
            sep = (peek_k(p) == TOK_SEMI) ? SEP_SEMI
                : (peek_k(p) == TOK_AMP)  ? SEP_AMP
                                          : SEP_NEWLINE;
            advance(p);
            while (peek_k(p) == TOK_NEWLINE) advance(p);
        } else if (!in_set(peek_k(p), stops, nstops) && peek_k(p) != TOK_EOF) {
            perror_at(p, "expected ';' '&' or newline");
            for (size_t i = 0; i <= cnt; i++) node_free(items[i]);
            free(items);
            free(seps);
            return NULL;
        }
        seps[cnt++] = sep;
    }

    if (cnt == 0) {
        free(items);
        free(seps);
        node_t *empty = node_new(N_LIST);
        return empty;
    }
    node_t *n = node_new(N_LIST);
    n->u.list.items = items;
    n->u.list.seps  = seps;
    n->u.list.count = cnt;
    return n;
}

/* --------------------------------------------------------------- driver */

int parse(token_list_t *toks, node_t **out, char **err_out) {
    P p = { .cur = toks->head, .err = NULL };
    static const tok_kind_t stops_eof[] = { TOK_EOF };
    node_t *n = parse_list_in(&p, stops_eof, 1);
    if (!n || p.err) {
        if (err_out) *err_out = p.err ? p.err : xstrdup("parse error");
        if (n) node_free(n);
        return -1;
    }
    *out = n;
    return 0;
}
