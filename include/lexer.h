/* lexer.h - tokenizer.
 *
 * Produces a linked list of tokens. WORD tokens carry a word_t whose segs
 * preserve quoting context (so the expander can decide what to expand vs
 * keep literal).
 */
#ifndef MASH_LEXER_H
#define MASH_LEXER_H

#include <stdbool.h>
#include <stddef.h>

#include "ast.h"

typedef enum {
    TOK_EOF = 0,
    TOK_NEWLINE,
    TOK_WORD,         /* with tok->word */
    TOK_ASSIGN,       /* NAME=word ; tok->name + tok->word */
    TOK_IO_NUMBER,    /* leading digit followed by redirect op */
    TOK_PIPE,         /* | */
    TOK_OR,           /* || */
    TOK_AND,          /* && */
    TOK_SEMI,         /* ; */
    TOK_DSEMI,        /* ;; */
    TOK_AMP,          /* & */
    TOK_LPAREN,       /* ( */
    TOK_RPAREN,       /* ) */
    TOK_LBRACE,       /* { (keyword) */
    TOK_RBRACE,       /* } (keyword) */
    TOK_BANG,         /* ! (keyword) */
    TOK_REDIR_IN,     /* <  */
    TOK_REDIR_OUT,    /* >  */
    TOK_REDIR_APPEND, /* >> */
    TOK_REDIR_HEREDOC,/* << */
    TOK_REDIR_HEREDOC_STRIP, /* <<- */
    TOK_REDIR_DUP_IN, /* <& */
    TOK_REDIR_DUP_OUT,/* >& */
    TOK_REDIR_CLOBBER,/* >| */
    TOK_REDIR_INOUT,  /* <> */
    TOK_REDIR_ERR_OUT,/* 2> (encoded via io_number) */
    TOK_REDIR_ERR_APP,/* 2>> */
    TOK_REDIR_AMP_OUT,/* &> */
    /* reserved words */
    TOK_IF, TOK_THEN, TOK_ELIF, TOK_ELSE, TOK_FI,
    TOK_WHILE, TOK_UNTIL, TOK_DO, TOK_DONE,
    TOK_FOR, TOK_IN,
    TOK_CASE, TOK_ESAC,
    TOK_FUNCTION
} tok_kind_t;

typedef struct token_t {
    tok_kind_t      kind;
    word_t         *word;   /* for WORD / ASSIGN */
    char           *name;   /* for ASSIGN */
    int             io_number; /* for IO_NUMBER */
    int             line;
    int             col;
    struct token_t *next;
} token_t;

typedef struct {
    token_t *head;
    token_t *tail;
} token_list_t;

/* Lex an entire source string. Returns 0 on success, -1 on error; on error
 * *err_out gets a human-readable message (caller frees). On success out->head
 * is the linked list of tokens. Always ends with TOK_EOF. */
int  lex(const char *src, token_list_t *out, char **err_out);

void token_list_free(token_list_t *t);

#endif /* MASH_LEXER_H */
