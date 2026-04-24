/* builtins.h - built-in command dispatch. */
#ifndef MASH_BUILTINS_H
#define MASH_BUILTINS_H

#include <stdbool.h>

#include "mash.h"

/* A builtin runs in-process. argc/argv are post-expansion. Returns exit
 * status to propagate to $?. */
typedef int (*builtin_fn)(shell_t *sh, int argc, char **argv);

typedef struct {
    const char *name;
    builtin_fn  fn;
    const char *synopsis;
} builtin_t;

/* Lookup by name. Returns NULL if not a builtin. */
const builtin_t *builtin_find(const char *name);

/* Enumerate (for `help`). */
const builtin_t *builtin_all(size_t *n_out);

#endif /* MASH_BUILTINS_H */
