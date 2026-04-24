/* highlight.c - streaming shell-source syntax highlighter.
 *
 * Walks the source byte by byte producing a colored rendering. The states
 * we care about are extremely shallow, which is enough for live editor
 * feedback:
 *
 *   - top level: words, operators, redirections, comments, quotes, $...
 *   - inside ' ... ': everything literal until next '
 *   - inside " ... ": literal except for $ and `
 *   - inside ${...}: matched braces, nothing else interpreted
 *   - inside $(...): matched parens, with quote skipping so a ')' inside
 *                    a 'string' or "string" doesn't end the substitution
 *   - inside $((...)): matched double parens
 *
 * We track at_cmd_start so the first word of a command is highlighted as a
 * builtin / command and reserved words are recognised. Any operator that
 * starts a fresh command (| || && ; ( ) { } newline) flips it back on.
 *
 * One small twist: a redirection like '<file' wants the immediately-
 * following word to render as a plain argument rather than a command, so
 * we set a one-shot 'next word is redir target' flag.
 */

#include "highlight.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtins.h"
#include "util.h"

/* ---------------------------------------------------------- SGR colors */

#define SGR_RESET        "\x1b[0m"
#define SGR_GRAY         "\x1b[90m"
#define SGR_YELLOW       "\x1b[33m"
#define SGR_BLUE         "\x1b[34m"
#define SGR_MAGENTA      "\x1b[35m"
#define SGR_CYAN         "\x1b[36m"
#define SGR_BOLD_GREEN   "\x1b[1;32m"
#define SGR_BOLD_YELLOW  "\x1b[1;33m"
#define SGR_BOLD_CYAN    "\x1b[1;36m"
#define SGR_BOLD_MAGENTA "\x1b[1;35m"

typedef enum {
    HL_DEFAULT = 0,
    HL_COMMENT,
    HL_KEYWORD,
    HL_COMMAND,
    HL_BUILTIN,
    HL_OPERATOR,
    HL_REDIR,
    HL_STRING,
    HL_VARIABLE,
    HL_CMDSUB,
    HL_NUMBER,
    HL_ASSIGN,
} hl_t;

static const char *hl_seq(hl_t k) {
    switch (k) {
    case HL_COMMENT:  return SGR_GRAY;
    case HL_KEYWORD:  return SGR_BOLD_YELLOW;
    case HL_COMMAND:  return SGR_BOLD_GREEN;
    case HL_BUILTIN:  return SGR_BOLD_CYAN;
    case HL_OPERATOR: return SGR_BOLD_MAGENTA;
    case HL_REDIR:    return SGR_CYAN;
    case HL_STRING:   return SGR_YELLOW;
    case HL_VARIABLE: return SGR_MAGENTA;
    case HL_CMDSUB:   return SGR_BOLD_MAGENTA;
    case HL_NUMBER:   return SGR_BLUE;
    case HL_ASSIGN:   return SGR_CYAN;
    case HL_DEFAULT:
    default:          return SGR_RESET;
    }
}

/* Reserved words we recognise at the start of a command. The shell's
 * lexer also promotes '{' and '}' to keywords, but we already colorize
 * those as operators, which reads better in the editor. */
static const char *KEYWORDS[] = {
    "if", "then", "elif", "else", "fi",
    "while", "until", "do", "done",
    "for", "in", "case", "esac",
    "function",
    NULL
};

static bool is_keyword(const char *s, size_t n) {
    for (size_t i = 0; KEYWORDS[i]; i++) {
        size_t kl = strlen(KEYWORDS[i]);
        if (kl == n && memcmp(KEYWORDS[i], s, n) == 0) return true;
    }
    return false;
}

static bool name_first(unsigned char c) { return isalpha(c) || c == '_'; }
static bool name_rest(unsigned char c)  { return isalnum(c) || c == '_'; }

/* ----------------------------------------------------------- context */

typedef struct {
    const char *src;
    size_t      len;
    size_t      i;
    strbuf_t   *out;
    bool        color;
    hl_t        cur;
} hl_ctx_t;

static void set_color(hl_ctx_t *c, hl_t k) {
    if (!c->color) return;
    if (c->cur == k) return;
    strbuf_appendz(c->out, hl_seq(k));
    c->cur = k;
}

static void emit_byte(hl_ctx_t *c, char b) { strbuf_push(c->out, b); }

static void emit_range(hl_ctx_t *c, size_t from, size_t to) {
    if (to > from) strbuf_append(c->out, c->src + from, to - from);
}

/* ---------------------------------------------------------- substrings */

/* Consume a $(...), $((...)) or ${...} starting at c->i pointing at '$'. */
static void scan_dollar(hl_ctx_t *c) {
    set_color(c, HL_VARIABLE);
    emit_byte(c, c->src[c->i]);          /* '$' */
    c->i++;
    if (c->i >= c->len) return;
    char d = c->src[c->i];

    if (d == '{') {
        emit_byte(c, d); c->i++;
        int depth = 1;
        while (c->i < c->len && depth > 0) {
            char x = c->src[c->i];
            if (x == '\\' && c->i + 1 < c->len) {
                emit_byte(c, x); c->i++;
                emit_byte(c, c->src[c->i]); c->i++;
                continue;
            }
            if (x == '{') depth++;
            else if (x == '}') {
                depth--;
                emit_byte(c, x); c->i++;
                if (depth == 0) return;
                continue;
            }
            emit_byte(c, x); c->i++;
        }
        return;
    }

    if (d == '(') {
        set_color(c, HL_CMDSUB);
        emit_byte(c, d); c->i++;
        /* Arithmetic $((...)) ? */
        if (c->i < c->len && c->src[c->i] == '(') {
            emit_byte(c, c->src[c->i]); c->i++;
            int depth = 2;
            while (c->i < c->len && depth > 0) {
                char x = c->src[c->i];
                if (x == '(') depth++;
                else if (x == ')') {
                    depth--;
                    emit_byte(c, x); c->i++;
                    if (depth == 0) return;
                    continue;
                }
                emit_byte(c, x); c->i++;
            }
            return;
        }
        /* Plain $(...) - skip over nested quotes to find the close paren. */
        int depth = 1;
        while (c->i < c->len && depth > 0) {
            char x = c->src[c->i];
            if (x == '\\' && c->i + 1 < c->len) {
                emit_byte(c, x); c->i++;
                emit_byte(c, c->src[c->i]); c->i++;
                continue;
            }
            if (x == '\'' || x == '"' || x == '`') {
                char q = x;
                emit_byte(c, q); c->i++;
                while (c->i < c->len && c->src[c->i] != q) {
                    if (c->src[c->i] == '\\' && c->i + 1 < c->len) {
                        emit_byte(c, c->src[c->i]); c->i++;
                    }
                    emit_byte(c, c->src[c->i]); c->i++;
                }
                if (c->i < c->len) { emit_byte(c, c->src[c->i]); c->i++; }
                continue;
            }
            if (x == '(') depth++;
            else if (x == ')') {
                depth--;
                emit_byte(c, x); c->i++;
                if (depth == 0) return;
                continue;
            }
            emit_byte(c, x); c->i++;
        }
        return;
    }

    /* Single-char specials: $? $$ $# $! $@ $* $- $0..$9 */
    if (strchr("?$#!@*-0123456789", d) != NULL) {
        emit_byte(c, d); c->i++;
        return;
    }
    /* Plain $NAME */
    if (name_first((unsigned char)d)) {
        while (c->i < c->len && name_rest((unsigned char)c->src[c->i])) {
            emit_byte(c, c->src[c->i]); c->i++;
        }
        return;
    }
    /* Lone '$' - leave coloring on the bare $ and bail out. */
}

static void scan_squote(hl_ctx_t *c) {
    set_color(c, HL_STRING);
    emit_byte(c, c->src[c->i]); c->i++;       /* opening ' */
    while (c->i < c->len && c->src[c->i] != '\'') {
        emit_byte(c, c->src[c->i]); c->i++;
    }
    if (c->i < c->len) { emit_byte(c, c->src[c->i]); c->i++; } /* closing ' */
}

static void scan_dquote(hl_ctx_t *c) {
    set_color(c, HL_STRING);
    emit_byte(c, c->src[c->i]); c->i++;       /* opening " */
    while (c->i < c->len && c->src[c->i] != '"') {
        char x = c->src[c->i];
        if (x == '\\' && c->i + 1 < c->len) {
            emit_byte(c, x); c->i++;
            emit_byte(c, c->src[c->i]); c->i++;
            continue;
        }
        if (x == '$') {
            scan_dollar(c);
            set_color(c, HL_STRING);
            continue;
        }
        if (x == '`') {
            set_color(c, HL_CMDSUB);
            emit_byte(c, x); c->i++;
            while (c->i < c->len && c->src[c->i] != '`') {
                if (c->src[c->i] == '\\' && c->i + 1 < c->len) {
                    emit_byte(c, c->src[c->i]); c->i++;
                }
                emit_byte(c, c->src[c->i]); c->i++;
            }
            if (c->i < c->len) { emit_byte(c, c->src[c->i]); c->i++; }
            set_color(c, HL_STRING);
            continue;
        }
        emit_byte(c, x); c->i++;
    }
    if (c->i < c->len) { emit_byte(c, c->src[c->i]); c->i++; } /* closing " */
}

static void scan_backtick(hl_ctx_t *c) {
    set_color(c, HL_CMDSUB);
    emit_byte(c, c->src[c->i]); c->i++;
    while (c->i < c->len && c->src[c->i] != '`') {
        if (c->src[c->i] == '\\' && c->i + 1 < c->len) {
            emit_byte(c, c->src[c->i]); c->i++;
        }
        emit_byte(c, c->src[c->i]); c->i++;
    }
    if (c->i < c->len) { emit_byte(c, c->src[c->i]); c->i++; }
}

/* ------------------------------------------------------------- driver */

/* True if src[wstart..wend) is a syntactically valid shell name. */
static bool valid_name(const char *src, size_t wstart, size_t wend) {
    if (wend <= wstart) return false;
    if (!name_first((unsigned char)src[wstart])) return false;
    for (size_t k = wstart + 1; k < wend; k++)
        if (!name_rest((unsigned char)src[k])) return false;
    return true;
}

void highlight_render(const char *src, size_t len, strbuf_t *out, bool color) {
    if (!color) {
        if (len) strbuf_append(out, src, len);
        return;
    }

    hl_ctx_t c = { src, len, 0, out, true, HL_DEFAULT };
    /* Reset whatever color the prompt left active. */
    strbuf_appendz(out, SGR_RESET);

    bool at_cmd_start    = true;   /* next word is a command */
    bool redir_target    = false;  /* next word is a redir target (a path) */

    while (c.i < c.len) {
        char x = c.src[c.i];

        if (x == ' ' || x == '\t') {
            set_color(&c, HL_DEFAULT);
            emit_byte(&c, x);
            c.i++;
            continue;
        }
        if (x == '\n') {
            set_color(&c, HL_DEFAULT);
            emit_byte(&c, x);
            c.i++;
            at_cmd_start = true;
            redir_target = false;
            continue;
        }
        /* line continuation: backslash + newline */
        if (x == '\\' && c.i + 1 < c.len && c.src[c.i + 1] == '\n') {
            set_color(&c, HL_DEFAULT);
            emit_byte(&c, x); c.i++;
            emit_byte(&c, c.src[c.i]); c.i++;
            at_cmd_start = true;
            redir_target = false;
            continue;
        }

        /* Comment: any '#' that's not consumed by a word becomes a comment.
         * Words don't break on '#', so reaching this point means '#' is at
         * a top-level position (start, or right after operator/whitespace). */
        if (x == '#') {
            set_color(&c, HL_COMMENT);
            while (c.i < c.len && c.src[c.i] != '\n') {
                emit_byte(&c, c.src[c.i]); c.i++;
            }
            continue;
        }

        /* Operators */
        if (x == '|' || x == '&' || x == ';') {
            set_color(&c, HL_OPERATOR);
            emit_byte(&c, x); c.i++;
            if (c.i < c.len) {
                char y = c.src[c.i];
                if      (x == '|' && y == '|') { emit_byte(&c, y); c.i++; }
                else if (x == '&' && y == '&') { emit_byte(&c, y); c.i++; }
                else if (x == ';' && y == ';') { emit_byte(&c, y); c.i++; }
                else if (x == '&' && y == '>') {
                    set_color(&c, HL_REDIR);
                    emit_byte(&c, y); c.i++;
                    if (c.i < c.len && c.src[c.i] == '>') {
                        emit_byte(&c, c.src[c.i]); c.i++;
                    }
                    redir_target = true;
                }
            }
            /* &> set redir_target above; everything else opens a fresh
             * command position. */
            at_cmd_start = !redir_target;
            continue;
        }
        if (x == '(' || x == ')' || x == '{' || x == '}') {
            set_color(&c, HL_OPERATOR);
            emit_byte(&c, x); c.i++;
            at_cmd_start = true;
            redir_target = false;
            continue;
        }
        if (x == '<' || x == '>') {
            set_color(&c, HL_REDIR);
            emit_byte(&c, x); c.i++;
            if (c.i < c.len) {
                char y = c.src[c.i];
                if ((x == '<' && (y == '<' || y == '&' || y == '>')) ||
                    (x == '>' && (y == '>' || y == '&' || y == '|'))) {
                    emit_byte(&c, y); c.i++;
                    if (x == '<' && y == '<' &&
                        c.i < c.len && c.src[c.i] == '-') {
                        emit_byte(&c, c.src[c.i]); c.i++;
                    }
                }
            }
            redir_target = true;
            continue;
        }

        if (x == '$')  { scan_dollar(&c);   at_cmd_start = false; redir_target = false; continue; }
        if (x == '\'') { scan_squote(&c);   at_cmd_start = false; redir_target = false; continue; }
        if (x == '"')  { scan_dquote(&c);   at_cmd_start = false; redir_target = false; continue; }
        if (x == '`')  { scan_backtick(&c); at_cmd_start = false; redir_target = false; continue; }

        /* ------- plain word ------- */
        size_t wstart = c.i;
        bool   saw_eq = false;
        size_t eq_pos = 0;
        bool   assign_candidate = at_cmd_start && (name_first((unsigned char)x));

        while (c.i < c.len) {
            char y = c.src[c.i];
            if (y == ' ' || y == '\t' || y == '\n') break;
            if (y == '|' || y == '&' || y == ';')   break;
            if (y == '<' || y == '>')               break;
            if (y == '(' || y == ')')               break;
            if (y == '\'' || y == '"' || y == '`')  break;
            if (y == '$')                           break;
            if (y == '\\' && c.i + 1 < c.len) { c.i += 2; continue; }
            if (y == '=' && assign_candidate && !saw_eq) {
                if (valid_name(c.src, wstart, c.i)) {
                    saw_eq = true;
                    eq_pos = c.i;
                }
            }
            c.i++;
        }
        size_t wend = c.i;
        size_t wlen = wend - wstart;

        if (saw_eq) {
            /* NAME=value ... */
            set_color(&c, HL_ASSIGN);
            emit_range(&c, wstart, eq_pos);
            set_color(&c, HL_OPERATOR);
            emit_byte(&c, '=');
            set_color(&c, HL_DEFAULT);
            emit_range(&c, eq_pos + 1, wend);
            /* Consecutive assignments are still 'cmd-start' positions. */
            redir_target = false;
            continue;
        }

        if (redir_target) {
            set_color(&c, HL_DEFAULT);
            emit_range(&c, wstart, wend);
            redir_target = false;
            /* After consuming the redir's filename we are still in
             * command-start position (e.g. '<file cat foo'). */
            continue;
        }

        /* All-digit word followed immediately by '<' or '>' is an IO num. */
        bool all_digits = wlen > 0;
        for (size_t k = 0; k < wlen && all_digits; k++)
            if (!isdigit((unsigned char)c.src[wstart + k])) all_digits = false;
        if (all_digits && c.i < c.len && (c.src[c.i] == '<' || c.src[c.i] == '>')) {
            set_color(&c, HL_NUMBER);
            emit_range(&c, wstart, wend);
            continue;
        }

        if (at_cmd_start) {
            if (is_keyword(c.src + wstart, wlen)) {
                set_color(&c, HL_KEYWORD);
                emit_range(&c, wstart, wend);
                /* Most keywords introduce another command position. */
                at_cmd_start = true;
                continue;
            }
            char tmp[128];
            if (wlen < sizeof(tmp)) {
                memcpy(tmp, c.src + wstart, wlen);
                tmp[wlen] = '\0';
                if (builtin_find(tmp)) {
                    set_color(&c, HL_BUILTIN);
                    emit_range(&c, wstart, wend);
                    at_cmd_start = false;
                    continue;
                }
            }
            set_color(&c, HL_COMMAND);
            emit_range(&c, wstart, wend);
            at_cmd_start = false;
            continue;
        }

        set_color(&c, HL_DEFAULT);
        emit_range(&c, wstart, wend);
    }

    /* Always end on a clean slate so the cursor isn't stuck in some color. */
    set_color(&c, HL_DEFAULT);
}

/* ----------------------------------------------------- color enablement */

bool highlight_color_enabled(int fd) {
    if (!isatty(fd)) return false;
    const char *nc = getenv("NO_COLOR");
    if (nc) return false;
    const char *term = getenv("TERM");
    if (!term || term[0] == '\0') return false;
    if (str_eq(term, "dumb")) return false;
    return true;
}
