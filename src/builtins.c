/* builtins.c - in-process commands.
 *
 * Every builtin writes through mashf() so output is masked. They are
 * dispatched by the executor when the first word of a simple command
 * matches a registered name. */

#include "builtins.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "env.h"
#include "history.h"
#include "jobs.h"
#include "mash.h"
#include "mask.h"
#include "util.h"

/* -------------------------------------------------------------------- */
/* Forward declarations of each implementation. */
static int b_cd(shell_t *sh, int argc, char **argv);
static int b_pwd(shell_t *sh, int argc, char **argv);
static int b_echo(shell_t *sh, int argc, char **argv);
static int b_printf(shell_t *sh, int argc, char **argv);
static int b_export(shell_t *sh, int argc, char **argv);
static int b_unset(shell_t *sh, int argc, char **argv);
static int b_set(shell_t *sh, int argc, char **argv);
static int b_alias(shell_t *sh, int argc, char **argv);
static int b_unalias(shell_t *sh, int argc, char **argv);
static int b_source(shell_t *sh, int argc, char **argv);
static int b_exit(shell_t *sh, int argc, char **argv);
static int b_return(shell_t *sh, int argc, char **argv);
static int b_shift(shell_t *sh, int argc, char **argv);
static int b_break(shell_t *sh, int argc, char **argv);
static int b_continue(shell_t *sh, int argc, char **argv);
static int b_true(shell_t *sh, int argc, char **argv);
static int b_false(shell_t *sh, int argc, char **argv);
static int b_test(shell_t *sh, int argc, char **argv);
static int b_type(shell_t *sh, int argc, char **argv);
static int b_help(shell_t *sh, int argc, char **argv);
static int b_history(shell_t *sh, int argc, char **argv);
static int b_jobs(shell_t *sh, int argc, char **argv);
static int b_fg(shell_t *sh, int argc, char **argv);
static int b_bg(shell_t *sh, int argc, char **argv);
static int b_kill(shell_t *sh, int argc, char **argv);
static int b_wait(shell_t *sh, int argc, char **argv);
static int b_umask(shell_t *sh, int argc, char **argv);
static int b_read(shell_t *sh, int argc, char **argv);
static int b_mask(shell_t *sh, int argc, char **argv);
static int b_colon(shell_t *sh, int argc, char **argv);

static const builtin_t TABLE[] = {
    { ":",        b_colon,    ": - no-op (returns true)" },
    { "cd",       b_cd,       "cd [DIR]" },
    { "pwd",      b_pwd,      "pwd" },
    { "echo",     b_echo,     "echo [-n] [-e] [args...]" },
    { "printf",   b_printf,   "printf FMT [args...]" },
    { "export",   b_export,   "export [NAME[=VALUE] ...]" },
    { "unset",    b_unset,    "unset NAME..." },
    { "set",      b_set,      "set [-/+eux] [-o opt] [--]" },
    { "alias",    b_alias,    "alias [NAME[=VALUE] ...]" },
    { "unalias",  b_unalias,  "unalias NAME..." },
    { "source",   b_source,   "source FILE [args...]" },
    { ".",        b_source,   ". FILE [args...]" },
    { "exit",     b_exit,     "exit [N]" },
    { "return",   b_return,   "return [N]" },
    { "shift",    b_shift,    "shift [N]" },
    { "break",    b_break,    "break [N]" },
    { "continue", b_continue, "continue [N]" },
    { "true",     b_true,     "true" },
    { "false",    b_false,    "false" },
    { "test",     b_test,     "test EXPR" },
    { "[",        b_test,     "[ EXPR ]" },
    { "type",     b_type,     "type NAME..." },
    { "help",     b_help,     "help [builtin]" },
    { "history",  b_history,  "history [N|-c]" },
    { "jobs",     b_jobs,     "jobs" },
    { "fg",       b_fg,       "fg [%N]" },
    { "bg",       b_bg,       "bg [%N]" },
    { "kill",     b_kill,     "kill [-SIG] PID|%N..." },
    { "wait",     b_wait,     "wait [PID|%N]" },
    { "umask",    b_umask,    "umask [MODE]" },
    { "read",     b_read,     "read VAR..." },
    { "mask",     b_mask,     "mask [show|disable N|enable N|add CAT PAT|literal CAT STR]" },
};
#define N_BUILTINS (sizeof(TABLE)/sizeof(TABLE[0]))

const builtin_t *builtin_find(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < N_BUILTINS; i++)
        if (str_eq(TABLE[i].name, name)) return &TABLE[i];
    return NULL;
}

const builtin_t *builtin_all(size_t *n_out) { *n_out = N_BUILTINS; return TABLE; }

/* -------------------------------------------------------------- : */

static int b_colon(shell_t *sh, int argc, char **argv) { (void)sh; (void)argc; (void)argv; return 0; }

/* ------------------------------------------------------------- cd */

static int b_cd(shell_t *sh, int argc, char **argv) {
    const char *target;
    if (argc < 2) target = env_get(sh->env, "HOME");
    else if (str_eq(argv[1], "-")) target = env_get(sh->env, "OLDPWD");
    else target = argv[1];
    if (!target || !*target) { mash_err(1, "cd: HOME not set"); return 1; }

    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd))) env_set(sh->env, "OLDPWD", cwd);

    if (chdir(target) < 0) {
        mash_err(1, "cd: %s: %s", target, strerror(errno));
        return 1;
    }
    if (getcwd(cwd, sizeof(cwd))) env_set(sh->env, "PWD", cwd);
    return 0;
}

/* ------------------------------------------------------------- pwd */

static int b_pwd(shell_t *sh, int argc, char **argv) {
    (void)sh; (void)argc; (void)argv;
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) { mash_err(1, "pwd: %s", strerror(errno)); return 1; }
    mashf(stdout, "%s\n", cwd);
    return 0;
}

/* ------------------------------------------------------------ echo */

static int b_echo(shell_t *sh, int argc, char **argv) {
    (void)sh;
    bool no_nl = false, interp = false;
    int i = 1;
    while (i < argc && argv[i][0] == '-' && argv[i][1]) {
        bool ok = true;
        for (const char *p = argv[i] + 1; *p; p++) {
            if (*p == 'n') continue;
            if (*p == 'e') continue;
            if (*p == 'E') continue;
            ok = false;
            break;
        }
        if (!ok) break;
        for (const char *p = argv[i] + 1; *p; p++) {
            if (*p == 'n') no_nl = true;
            else if (*p == 'e') interp = true;
            else if (*p == 'E') interp = false;
        }
        i++;
    }
    strbuf_t b; strbuf_init(&b);
    for (int j = i; j < argc; j++) {
        if (j > i) strbuf_push(&b, ' ');
        if (!interp) strbuf_appendz(&b, argv[j]);
        else {
            for (const char *p = argv[j]; *p; p++) {
                if (*p == '\\' && p[1]) {
                    char c = *++p;
                    switch (c) {
                    case 'n': strbuf_push(&b, '\n'); break;
                    case 't': strbuf_push(&b, '\t'); break;
                    case 'r': strbuf_push(&b, '\r'); break;
                    case '\\': strbuf_push(&b, '\\'); break;
                    case '0': strbuf_push(&b, '\0'); break;
                    case 'a': strbuf_push(&b, '\a'); break;
                    case 'b': strbuf_push(&b, '\b'); break;
                    default: strbuf_push(&b, '\\'); strbuf_push(&b, c); break;
                    }
                } else strbuf_push(&b, *p);
            }
        }
    }
    if (!no_nl) strbuf_push(&b, '\n');
    (void)mashf_fd(STDOUT_FILENO, "%.*s", (int)b.len, b.data ? b.data : "");
    strbuf_free(&b);
    return 0;
}

/* --------------------------------------------------------- printf */

/* The format spec is built from the user-supplied format string, so each
 * printf-family call below is intentionally dynamic. Suppress the check
 * around this function only. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
static int b_printf(shell_t *sh, int argc, char **argv) {
    (void)sh;
    if (argc < 2) return 0;
    const char *fmt = argv[1];
    int arg = 2;
    strbuf_t out; strbuf_init(&out);
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') { strbuf_push(&out, *p); continue; }
        p++;
        /* Capture full format spec until conversion. */
        strbuf_t spec; strbuf_init(&spec);
        strbuf_push(&spec, '%');
        while (*p && !strchr("diouxXeEfgGsc%", *p)) strbuf_push(&spec, *p++);
        if (!*p) { strbuf_free(&spec); break; }
        char conv = *p;
        strbuf_push(&spec, conv);
        char buf[256];
        const char *a = (arg < argc) ? argv[arg++] : "";
        if (conv == '%') strbuf_push(&out, '%');
        else if (conv == 's') { strbuf_appendf(&out, spec.data, a); }
        else if (conv == 'c') { strbuf_appendf(&out, spec.data, a[0]); }
        else if (conv == 'd' || conv == 'i') snprintf(buf, sizeof(buf), spec.data, (long)strtol(a, NULL, 0)), strbuf_appendz(&out, buf);
        else if (strchr("ouxX", conv)) snprintf(buf, sizeof(buf), spec.data, (unsigned long)strtoul(a, NULL, 0)), strbuf_appendz(&out, buf);
        else if (strchr("eEfgG", conv)) snprintf(buf, sizeof(buf), spec.data, strtod(a, NULL)), strbuf_appendz(&out, buf);
        strbuf_free(&spec);
    }
    (void)mashf_fd(STDOUT_FILENO, "%.*s", (int)out.len, out.data ? out.data : "");
    strbuf_free(&out);
    return 0;
}
#pragma GCC diagnostic pop

/* --------------------------------------------------------- export */

static int b_export(shell_t *sh, int argc, char **argv) {
    if (argc == 1) {
        for (var_t *v = sh->env->vars; v; v = v->next) {
            if (v->exported) {
                if (v->value) mashf(stdout, "export %s=%s\n", v->name, v->value);
                else          mashf(stdout, "export %s\n", v->name);
            }
        }
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq) {
            *eq = '\0';
            env_set(sh->env, argv[i], eq + 1);
            env_export(sh->env, argv[i]);
            *eq = '=';
        } else {
            env_export(sh->env, argv[i]);
        }
    }
    return 0;
}

/* ---------------------------------------------------------- unset */

static int b_unset(shell_t *sh, int argc, char **argv) {
    for (int i = 1; i < argc; i++) env_unset(sh->env, argv[i]);
    return 0;
}

/* ------------------------------------------------------------ set */

static int b_set(shell_t *sh, int argc, char **argv) {
    if (argc == 1) {
        for (var_t *v = sh->env->vars; v; v = v->next)
            if (v->value) mashf(stdout, "%s=%s\n", v->name, v->value);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (str_eq(a, "--")) { i++; /* reset positional args */
            size_t new_n = (size_t)(argc - i);
            for (size_t j = 0; j < sh->pos_argc; j++) free(sh->pos_args[j]);
            free(sh->pos_args);
            sh->pos_args = xcalloc(new_n + 1, sizeof(*sh->pos_args));
            for (size_t j = 0; j < new_n; j++) sh->pos_args[j] = xstrdup(argv[i + (int)j]);
            sh->pos_argc = new_n;
            return 0;
        }
        if ((a[0] == '-' || a[0] == '+') && a[1]) {
            bool on = (a[0] == '-');
            for (const char *p = a + 1; *p; p++) {
                if (*p == 'e') sh->opts.errexit = on;
                else if (*p == 'u') sh->opts.nounset = on;
                else if (*p == 'x') sh->opts.xtrace = on;
                else if (*p == 'v') sh->opts.verbose = on;
                else if (*p == 'n') sh->opts.noexec = on;
                else if (*p == 'o' || *p == 'O') {
                    if (i + 1 >= argc) { mash_err(1, "set: -o requires arg"); return 1; }
                    const char *opt = argv[++i];
                    if      (str_eq(opt, "errexit"))  sh->opts.errexit = on;
                    else if (str_eq(opt, "nounset"))  sh->opts.nounset = on;
                    else if (str_eq(opt, "xtrace"))   sh->opts.xtrace = on;
                    else if (str_eq(opt, "pipefail")) sh->opts.pipefail = on;
                    else if (str_eq(opt, "nomask-cmdsub")) sh->opts.nomask_cmdsub = on;
                    else { mash_err(1, "set: unknown option %s", opt); return 1; }
                } else {
                    mash_err(1, "set: unknown flag -%c", *p);
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------- alias */

static int b_alias(shell_t *sh, int argc, char **argv) {
    if (argc == 1) {
        for (alias_t *a = sh->env->aliases; a; a = a->next)
            mashf(stdout, "alias %s='%s'\n", a->name, a->value);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq) {
            const char *v = alias_get(sh->env, argv[i]);
            if (v) mashf(stdout, "alias %s='%s'\n", argv[i], v);
            else { mash_err(1, "alias: %s: not found", argv[i]); return 1; }
            continue;
        }
        *eq = '\0';
        alias_set(sh->env, argv[i], eq + 1);
        *eq = '=';
    }
    return 0;
}

static int b_unalias(shell_t *sh, int argc, char **argv) {
    for (int i = 1; i < argc; i++) alias_unset(sh->env, argv[i]);
    return 0;
}

/* --------------------------------------------------------- source */

static int b_source(shell_t *sh, int argc, char **argv) {
    if (argc < 2) { mash_err(1, "source: filename required"); return 1; }
    char **saved_args = sh->pos_args;
    size_t saved_argc = sh->pos_argc;
    sh->pos_args = xcalloc(argc, sizeof(*sh->pos_args));
    for (int i = 2; i < argc; i++) sh->pos_args[i-2] = xstrdup(argv[i]);
    sh->pos_argc = (size_t)(argc - 2);
    int rc = mash_run_file(sh, argv[1]);
    for (size_t i = 0; i < sh->pos_argc; i++) free(sh->pos_args[i]);
    free(sh->pos_args);
    sh->pos_args = saved_args;
    sh->pos_argc = saved_argc;
    return rc;
}

/* ----------------------------------------------------------- exit */

static int b_exit(shell_t *sh, int argc, char **argv) {
    int code = (argc >= 2) ? atoi(argv[1]) : sh->last_status;
    exit(code & 0xFF);
}

static int b_return(shell_t *sh, int argc, char **argv) {
    sh->return_req = 1;
    return (argc >= 2) ? atoi(argv[1]) : sh->last_status;
}

static int b_shift(shell_t *sh, int argc, char **argv) {
    int n = (argc >= 2) ? atoi(argv[1]) : 1;
    if (n < 0 || (size_t)n > sh->pos_argc) return 1;
    for (int i = 0; i < n; i++) free(sh->pos_args[i]);
    for (size_t i = n; i <= sh->pos_argc; i++) sh->pos_args[i - n] = sh->pos_args[i];
    sh->pos_argc -= n;
    return 0;
}

static int b_break(shell_t *sh, int argc, char **argv) {
    int n = (argc >= 2) ? atoi(argv[1]) : 1;
    if (n < 1) n = 1;
    if (sh->loop_depth == 0) return 0;
    sh->break_req = n;
    return 0;
}
static int b_continue(shell_t *sh, int argc, char **argv) {
    int n = (argc >= 2) ? atoi(argv[1]) : 1;
    if (n < 1) n = 1;
    if (sh->loop_depth == 0) return 0;
    sh->continue_req = n;
    return 0;
}

static int b_true(shell_t *sh, int argc, char **argv)  { (void)sh; (void)argc; (void)argv; return 0; }
static int b_false(shell_t *sh, int argc, char **argv) { (void)sh; (void)argc; (void)argv; return 1; }

/* ---------------------------------------------------------- test */

/* Minimal POSIX test. Supports:
 *   -z S, -n S
 *   -e F, -f F, -d F, -r F, -w F, -x F, -s F
 *   S = S, S != S, S < S, S > S, N -eq N, -ne, -lt, -le, -gt, -ge
 *   ! EXPR, EXPR -a EXPR, EXPR -o EXPR
 */
static int test_one(int argc, char **argv, int *i);
static int test_or(int argc, char **argv, int *i);

static bool test_unary(const char *op, const char *arg) {
    struct stat st;
    if (str_eq(op, "-z")) return arg[0] == '\0';
    if (str_eq(op, "-n")) return arg[0] != '\0';
    if (str_eq(op, "-e")) return stat(arg, &st) == 0;
    if (str_eq(op, "-f")) return stat(arg, &st) == 0 && S_ISREG(st.st_mode);
    if (str_eq(op, "-d")) return stat(arg, &st) == 0 && S_ISDIR(st.st_mode);
    if (str_eq(op, "-r")) return access(arg, R_OK) == 0;
    if (str_eq(op, "-w")) return access(arg, W_OK) == 0;
    if (str_eq(op, "-x")) return access(arg, X_OK) == 0;
    if (str_eq(op, "-s")) return stat(arg, &st) == 0 && st.st_size > 0;
    return false;
}

static int test_primary(int argc, char **argv, int *i) {
    if (*i >= argc) return 1;
    const char *a = argv[*i];
    if (str_eq(a, "!")) { (*i)++; return test_primary(argc, argv, i) ? 0 : 1; }
    if (str_eq(a, "(")) {
        (*i)++;
        int r = test_or(argc, argv, i);
        if (*i < argc && str_eq(argv[*i], ")")) (*i)++;
        return r;
    }
    if (*i + 1 < argc && a[0] == '-' && !argv[*i][2]) {
        bool b = test_unary(a, argv[*i + 1]);
        *i += 2;
        return b ? 0 : 1;
    }
    if (*i + 2 < argc) {
        const char *op = argv[*i + 1];
        const char *r = argv[*i + 2];
        int rc = 1;
        if (str_eq(op, "="))  rc = str_eq(a, r) ? 0 : 1;
        else if (str_eq(op, "!=")) rc = str_eq(a, r) ? 1 : 0;
        else if (str_eq(op, "<"))  rc = strcmp(a, r) < 0 ? 0 : 1;
        else if (str_eq(op, ">"))  rc = strcmp(a, r) > 0 ? 0 : 1;
        else if (str_eq(op, "-eq")) rc = strtol(a,NULL,0) == strtol(r,NULL,0) ? 0 : 1;
        else if (str_eq(op, "-ne")) rc = strtol(a,NULL,0) != strtol(r,NULL,0) ? 0 : 1;
        else if (str_eq(op, "-lt")) rc = strtol(a,NULL,0) <  strtol(r,NULL,0) ? 0 : 1;
        else if (str_eq(op, "-le")) rc = strtol(a,NULL,0) <= strtol(r,NULL,0) ? 0 : 1;
        else if (str_eq(op, "-gt")) rc = strtol(a,NULL,0) >  strtol(r,NULL,0) ? 0 : 1;
        else if (str_eq(op, "-ge")) rc = strtol(a,NULL,0) >= strtol(r,NULL,0) ? 0 : 1;
        else { *i += 1; return a[0] ? 0 : 1; }
        *i += 3;
        return rc;
    }
    /* Single string: true if non-empty. */
    *i += 1;
    return a[0] ? 0 : 1;
}

static int test_and(int argc, char **argv, int *i) {
    int l = test_primary(argc, argv, i);
    while (*i < argc && str_eq(argv[*i], "-a")) {
        (*i)++;
        int r = test_primary(argc, argv, i);
        l = (l == 0 && r == 0) ? 0 : 1;
    }
    return l;
}
static int test_or(int argc, char **argv, int *i) {
    int l = test_and(argc, argv, i);
    while (*i < argc && str_eq(argv[*i], "-o")) {
        (*i)++;
        int r = test_and(argc, argv, i);
        l = (l == 0 || r == 0) ? 0 : 1;
    }
    return l;
}
static int test_one(int argc, char **argv, int *i) { return test_or(argc, argv, i); }

static int b_test(shell_t *sh, int argc, char **argv) {
    (void)sh;
    if (str_eq(argv[0], "[")) {
        if (argc < 2 || !str_eq(argv[argc - 1], "]")) {
            mash_err(2, "[: missing ]");
            return 2;
        }
        argc--; /* drop trailing ] */
    }
    if (argc <= 1) return 1;
    int i = 1;
    return test_one(argc, argv, &i);
}

/* ---------------------------------------------------------- type */

static int b_type(shell_t *sh, int argc, char **argv) {
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        if (builtin_find(argv[i]))       { mashf(stdout, "%s is a builtin\n", argv[i]); continue; }
        if (alias_get(sh->env, argv[i])) { mashf(stdout, "%s is aliased to `%s'\n", argv[i], alias_get(sh->env, argv[i])); continue; }
        if (func_find(sh->env, argv[i])) { mashf(stdout, "%s is a function\n", argv[i]); continue; }
        /* Walk $PATH. */
        const char *path = env_get(sh->env, "PATH");
        if (!path) path = "/usr/bin:/bin";
        bool found = false;
        char *copy = xstrdup(path);
        for (char *p = copy, *save = NULL; (p = strtok_r(p, ":", &save)); p = NULL) {
            strbuf_t b; strbuf_init(&b);
            strbuf_appendz(&b, p); strbuf_push(&b, '/'); strbuf_appendz(&b, argv[i]);
            if (access(b.data, X_OK) == 0) {
                mashf(stdout, "%s is %s\n", argv[i], b.data);
                found = true;
                strbuf_free(&b);
                break;
            }
            strbuf_free(&b);
        }
        free(copy);
        if (!found) { mashf(stderr, "%s: not found\n", argv[i]); rc = 1; }
    }
    return rc;
}

/* ---------------------------------------------------------- help */

static int b_help(shell_t *sh, int argc, char **argv) {
    (void)sh;
    size_t n; const builtin_t *tbl = builtin_all(&n);
    if (argc < 2) {
        mashf(stdout, "mash - masked shell\nBuilt-ins:\n");
        for (size_t i = 0; i < n; i++)
            mashf(stdout, "  %-10s %s\n", tbl[i].name, tbl[i].synopsis);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        const builtin_t *b = builtin_find(argv[i]);
        if (b) mashf(stdout, "%s: %s\n", b->name, b->synopsis);
        else   mashf(stderr, "no help for %s\n", argv[i]);
    }
    return 0;
}

/* --------------------------------------------------------- history */

static void history_print_cb(int idx, const char *line, void *ud) {
    (void)ud;
    mashf(stdout, "%5d  %s\n", idx, line);
}

static int b_history(shell_t *sh, int argc, char **argv) {
    if (argc >= 2 && str_eq(argv[1], "-c")) { history_clear(sh->history); return 0; }
    int n = argc >= 2 ? atoi(argv[1]) : -1;
    history_iter(sh->history, n, history_print_cb, NULL);
    return 0;
}

/* jobs / fg / bg / kill / wait */

static int b_jobs(shell_t *sh, int argc, char **argv) {
    (void)argc; (void)argv;
    jobs_reap(sh->jobs);
    for (job_t *j = sh->jobs->head; j; j = j->next) {
        const char *st = j->state == JOB_RUNNING ? "Running"
                       : j->state == JOB_STOPPED ? "Stopped" : "Done";
        mashf(stdout, "[%d] %-7s %s\n", j->id, st, j->cmd);
    }
    return 0;
}
static int b_fg(shell_t *sh, int argc, char **argv) {
    job_t *j = jobs_find(sh->jobs, argc > 1 ? argv[1] : NULL);
    if (!j) { mash_err(1, "fg: no such job"); return 1; }
    kill(-j->pgid, SIGCONT);
    int st = 0;
    waitpid(j->last_pid, &st, 0);
    j->state = JOB_DONE;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}
static int b_bg(shell_t *sh, int argc, char **argv) {
    job_t *j = jobs_find(sh->jobs, argc > 1 ? argv[1] : NULL);
    if (!j) { mash_err(1, "bg: no such job"); return 1; }
    kill(-j->pgid, SIGCONT);
    return 0;
}
static int b_kill(shell_t *sh, int argc, char **argv) {
    int sig = SIGTERM;
    int i = 1;
    if (i < argc && argv[i][0] == '-') {
        sig = atoi(argv[i] + 1);
        if (sig == 0) sig = SIGTERM;
        i++;
    }
    int rc = 0;
    for (; i < argc; i++) {
        if (argv[i][0] == '%') {
            job_t *j = jobs_find(sh->jobs, argv[i]);
            if (j) kill(-j->pgid, sig);
            else rc = 1;
        } else {
            if (kill((pid_t)atoi(argv[i]), sig) < 0) rc = 1;
        }
    }
    return rc;
}
static int b_wait(shell_t *sh, int argc, char **argv) {
    if (argc < 2) {
        /* Wait for all children. */
        while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
        return 0;
    }
    pid_t p;
    if (argv[1][0] == '%') {
        job_t *j = jobs_find(sh->jobs, argv[1]);
        if (!j) return 1;
        p = j->last_pid;
    } else p = (pid_t)atoi(argv[1]);
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static int b_umask(shell_t *sh, int argc, char **argv) {
    (void)sh;
    mode_t m = umask(022);
    umask(m);
    if (argc < 2) { mashf(stdout, "%04o\n", m); return 0; }
    mode_t nm = (mode_t)strtol(argv[1], NULL, 8);
    umask(nm);
    return 0;
}

/* read VAR [VAR...] */
static int b_read(shell_t *sh, int argc, char **argv) {
    strbuf_t b; strbuf_init(&b);
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1) {
        if (c == '\n') break;
        strbuf_push(&b, c);
    }
    const char *ifs = env_get(sh->env, "IFS");
    if (!ifs) ifs = " \t\n";
    size_t n;
    char **parts = str_split_ifs(b.data ? b.data : "", ifs, &n);
    int names = argc - 1;
    for (int i = 0; i < names; i++) {
        if (i + 1 == names) {
            /* last variable gets the rest, joined with ' '. */
            strbuf_t rest; strbuf_init(&rest);
            for (size_t j = i; j < n; j++) {
                if (j > (size_t)i) strbuf_push(&rest, ' ');
                strbuf_appendz(&rest, parts[j]);
            }
            env_set(sh->env, argv[i + 1], rest.data ? rest.data : "");
            strbuf_free(&rest);
        } else {
            env_set(sh->env, argv[i + 1], (size_t)i < n ? parts[i] : "");
        }
    }
    for (size_t i = 0; i < n; i++) free(parts[i]);
    free(parts);
    strbuf_free(&b);
    return 0;
}

/* ----------------------------------------------------------- mask */

static bool show_rule_cb(const mask_rule_t *r, size_t idx, void *ud) {
    (void)ud;
    const char *src = r->literal ? r->literal : r->pattern_src;
    mashf(stdout, "  [%zu] %-12s %s%s\n",
          idx, mask_cat_name(r->category),
          r->disabled ? "(disabled) " : "",
          src ? src : "");
    return true;
}

static mask_cat_t cat_from_name(const char *s) {
    for (int i = 0; i < MASK_CAT__COUNT; i++)
        if (str_eq(mask_cat_name((mask_cat_t)i), s)) return (mask_cat_t)i;
    return MASK_CAT_CUSTOM;
}

static int b_mask(shell_t *sh, int argc, char **argv) {
    if (argc < 2 || str_eq(argv[1], "show")) {
        mashf(stdout, "%zu active mask rules\n", sh->mask->rule_count);
        mask_foreach(sh->mask, show_rule_cb, NULL);
        return 0;
    }
    if (str_eq(argv[1], "disable") && argc >= 3) {
        if (mask_set_disabled(sh->mask, (size_t)atol(argv[2]), true) < 0)
            { mash_err(1, "no such rule"); return 1; }
        return 0;
    }
    if (str_eq(argv[1], "enable") && argc >= 3) {
        if (mask_set_disabled(sh->mask, (size_t)atol(argv[2]), false) < 0)
            { mash_err(1, "no such rule"); return 1; }
        return 0;
    }
    if (str_eq(argv[1], "remove") && argc >= 3) {
        if (mask_remove(sh->mask, (size_t)atol(argv[2])) < 0)
            { mash_err(1, "no such rule"); return 1; }
        return 0;
    }
    if (str_eq(argv[1], "add") && argc >= 4) {
        return mask_add_pattern(sh->mask, cat_from_name(argv[2]), argv[3], NULL) == 0 ? 0 : 1;
    }
    if (str_eq(argv[1], "literal") && argc >= 4) {
        return mask_add_literal(sh->mask, cat_from_name(argv[2]), argv[3]) == 0 ? 0 : 1;
    }
    mash_err(2, "mask: usage: mask [show|disable N|enable N|remove N|add CAT PAT|literal CAT STR]");
    return 2;
}
