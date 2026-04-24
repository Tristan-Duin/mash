/* ast.h - AST node types produced by the parser and consumed by the
 * expander and executor.
 *
 * Nodes own their children; ast_free() cleans up the whole tree.
 *
 * The core hierarchy:
 *
 *   list       -> several and_or joined by ; & or newline
 *   and_or     -> pipeline chain joined by && or ||
 *   pipeline   -> one or more commands joined by |
 *   command    -> simple (words + redirections) | compound (if/while/...)
 *
 * A "word" is carried as a list of word_seg_t, retaining quote context so
 * the expander can decide what to split/expand.
 */
#ifndef MASH_AST_H
#define MASH_AST_H

#include <stdbool.h>
#include <stddef.h>

/* ------------------------------------------------------------------ words */

typedef enum {
    WSEG_LITERAL,       /* raw bytes */
    WSEG_SINGLE,        /* 'quoted' - no expansion inside */
    WSEG_DOUBLE,        /* "quoted" - param/cmd/arith still expand */
    WSEG_DOLLAR,        /* $VAR or ${VAR...} */
    WSEG_CMDSUB,        /* $(...) or backticks */
    WSEG_ARITH,         /* $(( ... )) */
    WSEG_TILDE          /* ~ or ~user at start of word */
} wseg_kind_t;

typedef struct word_seg {
    wseg_kind_t      kind;
    char            *text;     /* raw text for this segment */
    struct word_t   *child;    /* inner word for nested expansions */
    struct word_seg *next;
} word_seg_t;

typedef struct word_t {
    word_seg_t *segs;
    /* When a word is wholly double-quoted, "$@" expansion rules differ.
     * We cache that condition to avoid walking segments at exec time. */
    bool        double_quoted_all;
} word_t;

word_t     *word_new(void);
void        word_free(word_t *w);
void        word_push_seg(word_t *w, word_seg_t *s);
word_seg_t *wseg_new(wseg_kind_t k, char *text);

/* ------------------------------------------------------------- redirection */

typedef enum {
    R_IN,           /* <  */
    R_OUT,          /* >  */
    R_APPEND,       /* >> */
    R_HEREDOC,      /* << */
    R_HEREDOC_STRIP,/* <<- */
    R_DUP_IN,       /* <& */
    R_DUP_OUT,      /* >& */
    R_CLOBBER_OUT,  /* >| */
    R_IN_OUT        /* <> */
} redir_op_t;

typedef struct redir_t {
    int             io;          /* -1 if default; else fd number */
    redir_op_t      op;
    word_t         *target;      /* word; or heredoc body for <<,<<- */
    char           *heredoc_tag; /* for validation only */
    bool            heredoc_expand; /* true if tag was unquoted */
    struct redir_t *next;
} redir_t;

redir_t *redir_new(void);
void     redir_free(redir_t *r);

/* ----------------------------------------------------------------- assigns */

typedef struct assign_t {
    char            *name;
    word_t          *value;
    struct assign_t *next;
} assign_t;

void assign_free(assign_t *a);

/* --------------------------------------------------------------- commands */

typedef enum {
    N_SIMPLE,
    N_PIPELINE,
    N_AND_OR,
    N_LIST,
    N_IF,
    N_WHILE,
    N_UNTIL,
    N_FOR,
    N_CASE,
    N_SUBSHELL,
    N_GROUP,
    N_FUNCDEF,
    N_NEG            /* ! command */
} node_kind_t;

struct node_t;
typedef struct node_t node_t;

typedef struct {
    assign_t  *assigns;
    word_t   **words;     /* NULL-terminated array */
    size_t     word_count;
    redir_t   *redirs;
} simple_t;

typedef struct {
    node_t **children;
    size_t   count;
} pipeline_t;

typedef enum { AND_OP, OR_OP } ao_op_t;

typedef struct {
    node_t  *left;
    ao_op_t  op;
    node_t  *right;
} andor_t;

/* list separators */
typedef enum { SEP_SEMI, SEP_AMP, SEP_NEWLINE } sep_t;

typedef struct {
    node_t **items;
    sep_t   *seps;     /* length == count */
    size_t   count;
} list_t;

typedef struct {
    node_t *cond;     /* list */
    node_t *body;     /* list */
    node_t *elif;     /* another N_IF or NULL */
    node_t *else_body;
} if_t;

typedef struct {
    node_t *cond;
    node_t *body;
} loop_t;

typedef struct {
    char     *name;
    word_t  **words;
    size_t    word_count;
    bool      in_seen;  /* differentiates `for x` vs `for x in ...` */
    node_t   *body;
} for_t;

typedef struct case_item {
    word_t          **patterns;
    size_t            pattern_count;
    node_t           *body;
    struct case_item *next;
} case_item_t;

typedef struct {
    word_t      *subject;
    case_item_t *items;
} case_t;

typedef struct {
    char    *name;
    node_t  *body;
    redir_t *redirs;
} funcdef_t;

struct node_t {
    node_kind_t kind;
    union {
        simple_t   simple;
        pipeline_t pipe;
        andor_t    andor;
        list_t     list;
        if_t       ifc;
        loop_t     loop;
        for_t      forc;
        case_t     casec;
        funcdef_t  funcdef;
        node_t    *inner;   /* subshell / group / neg */
    } u;
    redir_t *redirs;        /* pipeline / compound redirs */
};

node_t *node_new(node_kind_t k);
void    node_free(node_t *n);

#endif /* MASH_AST_H */
