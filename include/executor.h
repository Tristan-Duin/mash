/* executor.h - AST evaluator. */
#ifndef MASH_EXECUTOR_H
#define MASH_EXECUTOR_H

#include "ast.h"
#include "mash.h"

/* Execute an AST node. Returns the exit status of the last visible
 * command. The shell's sh->last_status is also updated. */
int exec_node(shell_t *sh, node_t *n);

#endif /* MASH_EXECUTOR_H */
