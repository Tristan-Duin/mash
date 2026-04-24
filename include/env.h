/* env.h - shell variables, exported environment, aliases, functions. */
#ifndef MASH_ENV_H
#define MASH_ENV_H

#include <stdbool.h>
#include <stddef.h>

#include "ast.h"

/* --------------------------------------------------------------- variables */

typedef struct var_t {
    char          *name;
    char          *value;       /* NULL means "unset but present" */
    bool           exported;
    bool           readonly;
    struct var_t  *next;
} var_t;

typedef struct alias_t {
    char            *name;
    char            *value;
    struct alias_t  *next;
} alias_t;

typedef struct func_t {
    char           *name;
    node_t         *body;       /* owned */
    struct func_t  *next;
} func_t;

typedef struct env_t {
    var_t   *vars;
    alias_t *aliases;
    func_t  *funcs;
} env_t;

env_t *env_new(void);
void   env_free(env_t *e);

/* Seed from the process environment (envp). */
void   env_import_process(env_t *e);

/* -------------------------------------------------------------- variables */

const char *env_get(env_t *e, const char *name);
void        env_set(env_t *e, const char *name, const char *value);
void        env_export(env_t *e, const char *name);
void        env_unset(env_t *e, const char *name);
bool        env_is_set(env_t *e, const char *name);
var_t      *env_find(env_t *e, const char *name);

/* Produce a NULL-terminated array of "NAME=value" exported vars for execve.
 * Caller frees with env_free_strv. */
char      **env_build_exec(env_t *e);
void        env_free_strv(char **v);

/* ---------------------------------------------------------------- aliases */

const char *alias_get(env_t *e, const char *name);
void        alias_set(env_t *e, const char *name, const char *value);
void        alias_unset(env_t *e, const char *name);

/* -------------------------------------------------------------- functions */

void        func_define(env_t *e, const char *name, node_t *body);
node_t     *func_find(env_t *e, const char *name);
void        func_undef(env_t *e, const char *name);

#endif /* MASH_ENV_H */
