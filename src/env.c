/* env.c - env vars + aliases + functions.
 *
 * Simple linked lists since lookup frequency is low relative to everything
 * else the shell does. Replace with a hash table if profiling ever cares. */

#include "env.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

extern char **environ;

env_t *env_new(void) { return xcalloc(1, sizeof(env_t)); }

static void var_free(var_t *v) {
    if (!v) return;
    free(v->name);
    free(v->value);
    free(v);
}

static void alias_free_one(alias_t *a) {
    if (!a) return;
    free(a->name);
    free(a->value);
    free(a);
}

static void func_free_one(func_t *f) {
    if (!f) return;
    free(f->name);
    node_free(f->body);
    free(f);
}

void env_free(env_t *e) {
    if (!e) return;
    var_t *v = e->vars;
    while (v) { var_t *n = v->next; var_free(v); v = n; }
    alias_t *a = e->aliases;
    while (a) { alias_t *n = a->next; alias_free_one(a); a = n; }
    func_t *f = e->funcs;
    while (f) { func_t *n = f->next; func_free_one(f); f = n; }
    free(e);
}

/* -------------------------------------------------------------- variables */

var_t *env_find(env_t *e, const char *name) {
    if (!e || !name) return NULL;
    for (var_t *v = e->vars; v; v = v->next)
        if (str_eq(v->name, name)) return v;
    return NULL;
}

const char *env_get(env_t *e, const char *name) {
    var_t *v = env_find(e, name);
    return v ? v->value : NULL;
}

bool env_is_set(env_t *e, const char *name) {
    var_t *v = env_find(e, name);
    return v && v->value;
}

void env_set(env_t *e, const char *name, const char *value) {
    var_t *v = env_find(e, name);
    if (!v) {
        v = xcalloc(1, sizeof(*v));
        v->name = xstrdup(name);
        v->next = e->vars;
        e->vars = v;
    }
    if (v->readonly) return;
    free(v->value);
    v->value = value ? xstrdup(value) : NULL;
}

void env_export(env_t *e, const char *name) {
    var_t *v = env_find(e, name);
    if (!v) {
        v = xcalloc(1, sizeof(*v));
        v->name = xstrdup(name);
        v->next = e->vars;
        e->vars = v;
    }
    v->exported = true;
}

void env_unset(env_t *e, const char *name) {
    if (!e || !name) return;
    var_t **cur = &e->vars;
    while (*cur) {
        if (str_eq((*cur)->name, name)) {
            if ((*cur)->readonly) return;
            var_t *v = *cur;
            *cur = v->next;
            var_free(v);
            return;
        }
        cur = &(*cur)->next;
    }
}

void env_import_process(env_t *e) {
    for (char **ep = environ; ep && *ep; ep++) {
        char *eq = strchr(*ep, '=');
        if (!eq) continue;
        char *name = xstrndup(*ep, (size_t)(eq - *ep));
        env_set(e, name, eq + 1);
        env_export(e, name);
        free(name);
    }
}

char **env_build_exec(env_t *e) {
    size_t n = 0;
    for (var_t *v = e->vars; v; v = v->next)
        if (v->exported && v->value) n++;
    char **a = xcalloc(n + 1, sizeof(*a));
    size_t i = 0;
    for (var_t *v = e->vars; v; v = v->next) {
        if (v->exported && v->value) {
            strbuf_t b; strbuf_init(&b);
            strbuf_appendz(&b, v->name);
            strbuf_push(&b, '=');
            strbuf_appendz(&b, v->value);
            a[i++] = strbuf_detach(&b, NULL);
        }
    }
    a[i] = NULL;
    return a;
}

void env_free_strv(char **v) {
    if (!v) return;
    for (size_t i = 0; v[i]; i++) free(v[i]);
    free(v);
}

/* ---------------------------------------------------------------- aliases */

const char *alias_get(env_t *e, const char *name) {
    if (!e || !name) return NULL;
    for (alias_t *a = e->aliases; a; a = a->next)
        if (str_eq(a->name, name)) return a->value;
    return NULL;
}

void alias_set(env_t *e, const char *name, const char *value) {
    for (alias_t *a = e->aliases; a; a = a->next) {
        if (str_eq(a->name, name)) {
            free(a->value);
            a->value = xstrdup(value);
            return;
        }
    }
    alias_t *a = xcalloc(1, sizeof(*a));
    a->name = xstrdup(name);
    a->value = xstrdup(value);
    a->next = e->aliases;
    e->aliases = a;
}

void alias_unset(env_t *e, const char *name) {
    alias_t **cur = &e->aliases;
    while (*cur) {
        if (str_eq((*cur)->name, name)) {
            alias_t *a = *cur;
            *cur = a->next;
            alias_free_one(a);
            return;
        }
        cur = &(*cur)->next;
    }
}

/* -------------------------------------------------------------- functions */

void func_define(env_t *e, const char *name, node_t *body) {
    for (func_t *f = e->funcs; f; f = f->next) {
        if (str_eq(f->name, name)) {
            node_free(f->body);
            f->body = body;
            return;
        }
    }
    func_t *f = xcalloc(1, sizeof(*f));
    f->name = xstrdup(name);
    f->body = body;
    f->next = e->funcs;
    e->funcs = f;
}

node_t *func_find(env_t *e, const char *name) {
    for (func_t *f = e->funcs; f; f = f->next)
        if (str_eq(f->name, name)) return f->body;
    return NULL;
}

void func_undef(env_t *e, const char *name) {
    func_t **cur = &e->funcs;
    while (*cur) {
        if (str_eq((*cur)->name, name)) {
            func_t *f = *cur;
            *cur = f->next;
            func_free_one(f);
            return;
        }
        cur = &(*cur)->next;
    }
}
