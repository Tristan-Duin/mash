/* parser.h - recursive-descent parser over the token list. */
#ifndef MASH_PARSER_H
#define MASH_PARSER_H

#include "ast.h"
#include "lexer.h"

/* Parse a token list into a list-node AST.
 * Returns 0 on success and *out = the AST root (caller owns).
 * On error, returns -1 and writes a message to *err_out (caller frees). */
int parse(token_list_t *toks, node_t **out, char **err_out);

#endif /* MASH_PARSER_H */
