/* expand.h - expand a parsed word into one or more final strings.
 *
 * Order (per POSIX, simplified):
 *   1. Tilde expansion
 *   2. Parameter expansion / command substitution / arithmetic
 *   3. Field splitting on $IFS (for unquoted expansions)
 *   4. Pathname expansion (glob)
 *   5. Quote removal
 */
#ifndef MASH_EXPAND_H
#define MASH_EXPAND_H

#include <stddef.h>

#include "ast.h"
#include "mash.h"

typedef struct {
    char  **v;
    size_t  n;
    size_t  cap;
} fields_t;

void fields_init(fields_t *f);
void fields_push(fields_t *f, char *s);
void fields_free(fields_t *f);

/* Expand a word into 0..N fields and append them to out. Honors the
 * shell's current IFS, nounset option, and mask.nomask_cmdsub option. */
int expand_word(shell_t *sh, const word_t *w, fields_t *out,
                bool assignment_context, bool expand_glob);

/* Expand a redirection target word into a single string (joined, IFS ignored). */
char *expand_redir_target(shell_t *sh, const word_t *w);

/* Expand an assignment value into a single string. */
char *expand_assign_value(shell_t *sh, const word_t *w);

/* Capture the stdout of a command (used for $(...)). Applies the mask
 * engine to the captured bytes unless set -o nomask-cmdsub is active. */
int  expand_run_capture(shell_t *sh, const char *src, char **out);

#endif /* MASH_EXPAND_H */
