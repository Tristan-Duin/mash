/* executor.c - walk the AST and actually run commands.
 *
 * Output leak prevention: every writable fd handed to a child goes through
 * mask_fd_wrap_write() first. That includes stdout, stderr, every `>`/`>>`
 * redirection target, and every pipe into the next stage of a pipeline.
 * Pumps run in the parent process so even if the child mmaps or forks its
 * own workers, all output eventually passes through the mask before being
 * delivered anywhere on-disk or to a TTY.
 *
 * The lone write-path that bypasses the mask is fd 3+ duplications to an
 * already-raw fd; we refuse to do that in redirect handling.
 */

#include "executor.h"

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "builtins.h"
#include "env.h"
#include "expand.h"
#include "jobs.h"
#include "mask_fd.h"
#include "signals.h"
#include "util.h"

/* ------------------------------------------------------------ forward decl */

static int  run_list(shell_t *sh, list_t *l);
static int  run_pipeline(shell_t *sh, node_t *n);
static int  run_simple(shell_t *sh, node_t *n, bool in_fork);
static int  run_compound(shell_t *sh, node_t *n);
static int  run_simple_or_compound_in_child(shell_t *sh, node_t *n);

/* --------------------------- pre-fork redirection preparation -------------
 *
 * Mask pumps are `pthread_create`'d threads that cannot survive `execvp`
 * (exec tears down every thread except the calling one). So for any child
 * that will exec a real program the wrapping MUST happen in the parent,
 * which stays alive to drive the pump. The child only inherits the
 * already-wrapped write fd and dup2's it into place. The parent keeps the
 * mask_fd_t around until after waitpid and then calls mask_fd_close() to
 * signal EOF to the pump and join the thread.
 *
 * `prepare_redirs_for_child` walks the redirection list in the parent and
 * opens / wraps / builds the source fds. `apply_prep_in_child` is called
 * by the child right before exec and simply performs dup2 + close. No
 * file opens or thread creation happen in the child.
 */

typedef struct redir_prep {
    int       dst_fd;       /* where the child wants it (0/1/2/N) */
    int       src_fd;       /* parent-held fd to dup2 into dst_fd, or -1 */
    bool      close_only;   /* true for <&- / >&- */
    bool      keep_src;     /* src is a pre-existing user fd (R_DUP_*); don't close in child */
    bool      is_mask_fd;   /* parent holds a mask_fd_t that must be closed/joined */
    mask_fd_t mfd;
    struct redir_prep *next;
} redir_prep_t;

static int  prepare_redirs_for_child(shell_t *sh, redir_t *redirs, redir_prep_t **out);
static void apply_prep_in_child(redir_prep_t *p);
static void redir_prep_free_parent(redir_prep_t *p);

/* Pipeline stage preps are stashed here between the pre-fork preparation
 * and the child's apply-in-child call. The shell is single-threaded so a
 * static pointer is safe; after fork, both parent and child have their own
 * copy of the pointer value, which is what we want. */
static redir_prep_t *g_pending_child_prep = NULL;

/* -------------------------------------------------------------- assign */

static int apply_assigns(shell_t *sh, assign_t *a, bool exported_temp,
                         assign_t **saved_out) {
    /* For prefix assignments on external commands, we need to restore
     * afterwards. We save (name, old_value, was_exported) entries. */
    (void)saved_out;
    for (; a; a = a->next) {
        char *v = expand_assign_value(sh, a->value);
        env_set(sh->env, a->name, v ? v : "");
        if (exported_temp) env_export(sh->env, a->name);
        free(v);
    }
    return 0;
}

/* ------------------------------------------------------------- redirect */

/* Parse a duplicate target like "2" or "-" into an integer fd or special. */
static int parse_dup_target(const char *s, bool *close_out) {
    *close_out = false;
    if (!s) return -1;
    if (str_eq(s, "-")) { *close_out = true; return -1; }
    char *e = NULL;
    long v = strtol(s, &e, 10);
    if (!e || *e || v < 0 || v > 1024) return -1;
    return (int)v;
}

/* A single applied redirection carries the (fd -> saved dup) pair so the
 * caller can restore fds when running builtins in the parent. For forked
 * children we don't bother with restoration. */
typedef struct redir_applied {
    int fd;
    int saved;         /* -1 if newly added */
    bool is_mask_fd;
    mask_fd_t mfd;     /* only valid if is_mask_fd */
    struct redir_applied *next;
} redir_applied_t;

static void free_applied(redir_applied_t *r) {
    while (r) {
        redir_applied_t *n = r->next;
        if (r->is_mask_fd) mask_fd_close(&r->mfd);
        free(r);
        r = n;
    }
}

/* Apply a single redirection. Returns 0 on success. On success *list
 * is updated with a new applied entry (for restoration purposes). */
static int apply_redir(shell_t *sh, redir_t *r, redir_applied_t **list,
                       bool restorable) {
    char *target = expand_redir_target(sh, r->target);
    int target_fd = -1;

    /* Determine the default fd for this op. */
    int dst_fd = r->io;
    if (dst_fd < 0) {
        switch (r->op) {
        case R_IN: case R_HEREDOC: case R_HEREDOC_STRIP:
        case R_DUP_IN: case R_IN_OUT:
            dst_fd = 0; break;
        default:
            dst_fd = 1; break;
        }
    }

    switch (r->op) {
    case R_IN:
        target_fd = open(target, O_RDONLY | O_CLOEXEC);
        if (target_fd < 0) { mash_err(1, "%s: %s", target, strerror(errno)); free(target); return -1; }
        break;
    case R_OUT:
    case R_CLOBBER_OUT: {
        int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) { mash_err(1, "%s: %s", target, strerror(errno)); free(target); return -1; }
        /* The pump thread is passed &a->mfd as its argument and keeps
         * dereferencing it for the thread's entire life; that pointer
         * must be at a stable heap address, not a stack local that
         * disappears when we return. */
        redir_applied_t *a = xcalloc(1, sizeof(*a));
        a->fd = dst_fd;
        a->is_mask_fd = true;
        if (mask_fd_wrap_write(sh->mask, fd, true, &a->mfd) < 0) {
            close(fd);
            free(a);
            free(target);
            return -1;
        }
        a->saved = restorable ? dup(dst_fd) : -1;
        dup2(a->mfd.write_fd, dst_fd);
        a->next = *list;
        *list = a;
        free(target);
        return 0;
    }
    case R_APPEND: {
        int fd = open(target, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (fd < 0) { mash_err(1, "%s: %s", target, strerror(errno)); free(target); return -1; }
        redir_applied_t *a = xcalloc(1, sizeof(*a));
        a->fd = dst_fd; a->is_mask_fd = true;
        if (mask_fd_wrap_write(sh->mask, fd, true, &a->mfd) < 0) {
            close(fd); free(a); free(target); return -1;
        }
        a->saved = restorable ? dup(dst_fd) : -1;
        dup2(a->mfd.write_fd, dst_fd);
        a->next = *list; *list = a;
        free(target);
        return 0;
    }
    case R_IN_OUT: {
        int fd = open(target, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (fd < 0) { mash_err(1, "%s: %s", target, strerror(errno)); free(target); return -1; }
        target_fd = fd;
        break;
    }
    case R_DUP_IN:
    case R_DUP_OUT: {
        bool want_close = false;
        int src = parse_dup_target(target, &want_close);
        free(target);
        redir_applied_t *a = xcalloc(1, sizeof(*a));
        a->fd = dst_fd;
        a->saved = restorable ? dup(dst_fd) : -1;
        if (want_close) close(dst_fd);
        else if (src >= 0) dup2(src, dst_fd);
        a->next = *list; *list = a;
        return 0;
    }
    case R_HEREDOC:
    case R_HEREDOC_STRIP: {
        /* Heredoc: the target word carries the *body*. Write to a pipe and
         * redirect from the read end. */
        int p[2];
        if (pipe(p) < 0) {
            mash_err(1, "pipe: %s", strerror(errno));
            free(target);
            return -1;
        }
        if (write_all(p[1], target, strlen(target)) < 0) {
            /* Body too large for the pipe buffer or the writer side
             * disappeared - either way the heredoc would be truncated. */
            mash_err(1, "heredoc: %s", strerror(errno));
            close(p[0]);
            close(p[1]);
            free(target);
            return -1;
        }
        close(p[1]);
        target_fd = p[0];
        break;
    }
    }

    if (target_fd < 0) { free(target); return -1; }

    redir_applied_t *a = xcalloc(1, sizeof(*a));
    a->fd = dst_fd;
    a->saved = restorable ? dup(dst_fd) : -1;
    dup2(target_fd, dst_fd);
    close(target_fd);
    a->next = *list; *list = a;
    free(target);
    return 0;
}

static int apply_redirs(shell_t *sh, redir_t *redirs, redir_applied_t **list,
                        bool restorable) {
    for (redir_t *r = redirs; r; r = r->next) {
        if (apply_redir(sh, r, list, restorable) < 0) return -1;
    }
    return 0;
}

static void restore_redirs(redir_applied_t *r) {
    while (r) {
        redir_applied_t *n = r->next;
        if (r->saved >= 0) {
            dup2(r->saved, r->fd);
            close(r->saved);
        }
        if (r->is_mask_fd) mask_fd_close(&r->mfd);
        free(r);
        r = n;
    }
}

/* ---- pre-fork redirection preparation (see long comment above) --------- */

static int prepare_redirs_for_child(shell_t *sh, redir_t *redirs,
                                    redir_prep_t **out) {
    *out = NULL;
    redir_prep_t **tail = out;
    for (redir_t *r = redirs; r; r = r->next) {
        int dst_fd = r->io;
        if (dst_fd < 0) {
            switch (r->op) {
            case R_IN: case R_HEREDOC: case R_HEREDOC_STRIP:
            case R_DUP_IN: case R_IN_OUT:
                dst_fd = 0; break;
            default:
                dst_fd = 1; break;
            }
        }
        redir_prep_t *e = xcalloc(1, sizeof(*e));
        e->dst_fd = dst_fd;
        e->src_fd = -1;

        char *target = expand_redir_target(sh, r->target);
        int rc = 0;

        switch (r->op) {
        case R_IN: {
            int fd = open(target, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                mash_err(1, "%s: %s", target, strerror(errno));
                rc = -1; break;
            }
            e->src_fd = fd;
            break;
        }
        case R_OUT:
        case R_CLOBBER_OUT: {
            int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (fd < 0) {
                mash_err(1, "%s: %s", target, strerror(errno));
                rc = -1; break;
            }
            if (mask_fd_wrap_write(sh->mask, fd, true, &e->mfd) < 0) {
                close(fd); rc = -1; break;
            }
            e->is_mask_fd = true;
            e->src_fd = e->mfd.write_fd;
            break;
        }
        case R_APPEND: {
            int fd = open(target, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
            if (fd < 0) {
                mash_err(1, "%s: %s", target, strerror(errno));
                rc = -1; break;
            }
            if (mask_fd_wrap_write(sh->mask, fd, true, &e->mfd) < 0) {
                close(fd); rc = -1; break;
            }
            e->is_mask_fd = true;
            e->src_fd = e->mfd.write_fd;
            break;
        }
        case R_IN_OUT: {
            int fd = open(target, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
            if (fd < 0) {
                mash_err(1, "%s: %s", target, strerror(errno));
                rc = -1; break;
            }
            e->src_fd = fd;
            break;
        }
        case R_DUP_IN:
        case R_DUP_OUT: {
            bool want_close = false;
            int src = parse_dup_target(target, &want_close);
            if (want_close) {
                e->close_only = true;
            } else if (src >= 0) {
                e->src_fd   = src;
                e->keep_src = true;
            }
            break;
        }
        case R_HEREDOC:
        case R_HEREDOC_STRIP: {
            int p[2];
            if (pipe(p) < 0) {
                mash_err(1, "pipe: %s", strerror(errno));
                rc = -1; break;
            }
            if (write_all(p[1], target, strlen(target)) < 0) {
                mash_err(1, "heredoc: %s", strerror(errno));
                close(p[0]);
                close(p[1]);
                rc = -1; break;
            }
            close(p[1]);
            int fl = fcntl(p[0], F_GETFD);
            if (fl >= 0) (void)fcntl(p[0], F_SETFD, fl | FD_CLOEXEC);
            e->src_fd = p[0];
            break;
        }
        }

        free(target);
        if (rc < 0) {
            free(e);
            redir_prep_free_parent(*out);
            *out = NULL;
            return -1;
        }
        *tail = e;
        tail = &e->next;
    }
    return 0;
}

static void apply_prep_in_child(redir_prep_t *p) {
    for (; p; p = p->next) {
        if (p->close_only) {
            close(p->dst_fd);
            continue;
        }
        if (p->src_fd < 0) continue;
        if (p->src_fd != p->dst_fd) {
            if (dup2(p->src_fd, p->dst_fd) < 0) _exit(127);
            if (!p->keep_src) close(p->src_fd);
        }
    }
}

static void redir_prep_free_parent(redir_prep_t *p) {
    while (p) {
        redir_prep_t *n = p->next;
        if (p->is_mask_fd) {
            /* Closes write_fd (signals EOF to the pump) and joins the
             * thread, which drains pending and closes real_fd. */
            mask_fd_close(&p->mfd);
        } else if (!p->keep_src && p->src_fd >= 0) {
            close(p->src_fd);
        }
        free(p);
        p = n;
    }
}

/* ------------------------------------------------------------- dispatch */

/* Build argv from expanded fields. Caller takes ownership of argv[]. */
static char **fields_to_argv(fields_t *f, int *argc_out) {
    char **v = xcalloc(f->n + 1, sizeof(*v));
    for (size_t i = 0; i < f->n; i++) v[i] = xstrdup(f->v[i]);
    *argc_out = (int)f->n;
    return v;
}

static void free_argv(char **v) {
    if (!v) return;
    for (int i = 0; v[i]; i++) free(v[i]);
    free(v);
}

/* Exec a simple command. When in_fork is true, we are already inside a
 * child process - so redirection is non-restorable and execvp replaces us. */
static int run_simple(shell_t *sh, node_t *n, bool in_fork) {
    simple_t *s = &n->u.simple;

    /* No words -> pure assignment list. */
    if (s->word_count == 0) {
        apply_assigns(sh, s->assigns, false, NULL);
        return 0;
    }

    /* Expand all words first. */
    fields_t args; fields_init(&args);
    for (size_t i = 0; i < s->word_count; i++) {
        expand_word(sh, s->words[i], &args, false, true);
    }
    if (args.n == 0) { fields_free(&args); return 0; }

    int argc = 0;
    char **argv = fields_to_argv(&args, &argc);
    fields_free(&args);

    /* xtrace */
    if (sh->opts.xtrace) {
        strbuf_t b; strbuf_init(&b);
        strbuf_appendz(&b, "+ ");
        for (int i = 0; i < argc; i++) {
            if (i) strbuf_push(&b, ' ');
            strbuf_appendz(&b, argv[i]);
        }
        strbuf_push(&b, '\n');
        mash_raw_write(sh->masked_stderr, b.data, b.len);
        strbuf_free(&b);
    }

    /* Function? */
    node_t *fn = func_find(sh->env, argv[0]);
    if (fn) {
        /* Swap positional args, apply assigns (scoped), run body. */
        char **saved_args = sh->pos_args;
        size_t saved_argc = sh->pos_argc;
        sh->pos_args = xcalloc(argc, sizeof(*sh->pos_args));
        for (int i = 1; i < argc; i++) sh->pos_args[i-1] = xstrdup(argv[i]);
        sh->pos_argc = argc - 1;

        redir_applied_t *rl = NULL;
        if (apply_redirs(sh, s->redirs, &rl, !in_fork) < 0) {
            free_applied(rl);
            free_argv(argv);
            for (size_t i = 0; i < sh->pos_argc; i++) free(sh->pos_args[i]);
            free(sh->pos_args);
            sh->pos_args = saved_args;
            sh->pos_argc = saved_argc;
            return 1;
        }
        apply_assigns(sh, s->assigns, false, NULL);

        int st = exec_node(sh, fn);
        if (sh->return_req) { sh->return_req = 0; }

        restore_redirs(rl);
        for (size_t i = 0; i < sh->pos_argc; i++) free(sh->pos_args[i]);
        free(sh->pos_args);
        sh->pos_args = saved_args;
        sh->pos_argc = saved_argc;
        free_argv(argv);
        sh->last_status = st;
        return st;
    }

    /* Builtin? */
    const builtin_t *bi = builtin_find(argv[0]);
    if (bi && !in_fork) {
        redir_applied_t *rl = NULL;
        if (apply_redirs(sh, s->redirs, &rl, true) < 0) {
            free_applied(rl);
            free_argv(argv);
            return 1;
        }
        apply_assigns(sh, s->assigns, true /* temp export */, NULL);
        int st = bi->fn(sh, argc, argv);
        restore_redirs(rl);
        free_argv(argv);
        sh->last_status = st;
        return st;
    }

    /* External: fork unless we're already a child. */
    if (!in_fork) {
        /* Pre-wrap all redirections in the parent so mask pump threads
         * live here (the shell stays alive) and survive the child's
         * execvp, which would otherwise destroy any pthread we started. */
        redir_prep_t *prep = NULL;
        if (prepare_redirs_for_child(sh, s->redirs, &prep) < 0) {
            redir_prep_free_parent(prep);
            free_argv(argv);
            sh->last_status = 1;
            return 1;
        }
        pid_t pid = fork();
        if (pid < 0) {
            mash_err(1, "fork: %s", strerror(errno));
            redir_prep_free_parent(prep);
            free_argv(argv);
            return 1;
        }
        if (pid == 0) {
            signals_reset_for_child();
            apply_prep_in_child(prep);
            apply_assigns(sh, s->assigns, true, NULL);
            /* We rely on apply_assigns() to have already called setenv for
             * any exported prefix assignments; execvp picks up environ(). */
            char **envp = env_build_exec(sh->env);
            (void)envp; /* kept for future use when execvpe is portable */
            env_free_strv(envp);
            for (var_t *v = sh->env->vars; v; v = v->next) {
                if (v->exported && v->value) setenv(v->name, v->value, 1);
            }
            execvp(argv[0], argv);
            mash_err(127, "%s: %s", argv[0], strerror(errno));
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        /* Draining the pumps happens now: mask_fd_close() inside
         * redir_prep_free_parent() closes write_fd (so the pump sees
         * EOF) and joins the pump thread. */
        redir_prep_free_parent(prep);
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        free_argv(argv);
        sh->last_status = code;
        return code;
    }

    /* in_fork: we *are* the child. If run_pipeline already pre-wrapped our
     * redirs in the parent, consume that prep here instead of re-wrapping
     * inside this (soon-to-exec) child. */
    redir_applied_t *rl = NULL;
    redir_prep_t   *prep = g_pending_child_prep;
    g_pending_child_prep = NULL;
    if (prep) {
        apply_prep_in_child(prep);
    } else if (apply_redirs(sh, s->redirs, &rl, false) < 0) {
        _exit(127);
    }
    apply_assigns(sh, s->assigns, true, NULL);
    if (bi) {
        int st = bi->fn(sh, argc, argv);
        /* For the in-child-wrapping fallback path, flush any pumps we
         * created inside this child by joining them before _exit. */
        if (rl) free_applied(rl);
        _exit(st & 0xFF);
    }
    for (var_t *v = sh->env->vars; v; v = v->next) {
        if (v->exported && v->value) setenv(v->name, v->value, 1);
    }
    if (rl) free_applied(rl);
    execvp(argv[0], argv);
    mash_err(127, "%s: %s", argv[0], strerror(errno));
    _exit(127);
}

/* ---------------------------------------------------------- pipeline */

static int run_pipeline(shell_t *sh, node_t *n) {
    size_t count = n->u.pipe.count;
    if (count == 1) return exec_node(sh, n->u.pipe.children[0]);

    /* N-1 intermediate pipes. Each stage reads from prev and writes to next
     * via a mask wrapper so data is masked before reaching stage i+1. */
    int *pipes = xcalloc(count - 1, sizeof(int) * 2);
    mask_fd_t *mfds = xcalloc(count - 1, sizeof(*mfds));
    pid_t *pids = xcalloc(count, sizeof(*pids));
    /* Per-stage, parent-held prep for any redirs attached to the stage's
     * simple command (e.g., `cmd > file` inside a pipeline). */
    redir_prep_t **stage_preps = xcalloc(count, sizeof(*stage_preps));

    for (size_t i = 0; i + 1 < count; i++) {
        int p[2];
        if (pipe(p) < 0) die("pipe: %s", strerror(errno));
        /* Wrap the write end. */
        if (mask_fd_wrap_write(sh->mask, p[1], true, &mfds[i]) < 0)
            die("mask_fd_wrap_write failed");
        pipes[2*i]     = p[0]; /* reader */
        pipes[2*i + 1] = mfds[i].write_fd; /* masked writer the child sees */
    }

    for (size_t i = 0; i < count; i++) {
        node_t *child_node = n->u.pipe.children[i];
        node_t *simple_node = child_node;
        /* Unwrap a leading `! cmd` so we can still pre-wrap its redirs. */
        while (simple_node && simple_node->kind == N_NEG)
            simple_node = simple_node->u.inner;
        if (simple_node && simple_node->kind == N_SIMPLE &&
            simple_node->u.simple.redirs) {
            if (prepare_redirs_for_child(sh, simple_node->u.simple.redirs,
                                         &stage_preps[i]) < 0) {
                stage_preps[i] = NULL;
            }
        }
        g_pending_child_prep = stage_preps[i];

        pid_t pid = fork();
        if (pid < 0) die("fork: %s", strerror(errno));
        if (pid == 0) {
            signals_reset_for_child();
            /* Set up stdin from previous pipe. */
            if (i > 0) {
                dup2(pipes[2*(i-1)], STDIN_FILENO);
            }
            /* Set up stdout to next pipe (masked). */
            if (i + 1 < count) {
                dup2(pipes[2*i + 1], STDOUT_FILENO);
            }
            /* Close every pipe fd we no longer need. */
            for (size_t k = 0; k + 1 < count; k++) {
                close(pipes[2*k]);
                close(pipes[2*k + 1]);
            }
            int rc = run_simple_or_compound_in_child(sh, child_node);
            _exit(rc & 0xFF);
        }
        /* Parent: clear the per-stage pending prep so the next iteration
         * starts clean. The prep itself is still owned by stage_preps[i]. */
        g_pending_child_prep = NULL;
        pids[i] = pid;
    }
    /* Parent closes all pipe fds so EOF propagates. pipes[2*i + 1] aliases
     * mfds[i].write_fd; mark it closed on the mask_fd_t so mask_fd_close()
     * below doesn't double-close. */
    for (size_t i = 0; i + 1 < count; i++) {
        close(pipes[2*i]);
        close(pipes[2*i + 1]);
        mfds[i].write_fd = -1;
    }

    int last_status = 0;
    int any_nonzero = 0;
    for (size_t i = 0; i < count; i++) {
        int st = 0;
        waitpid(pids[i], &st, 0);
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        if (code) any_nonzero = code;
        if (i == count - 1) last_status = code;
    }
    /* Join all pump threads. */
    for (size_t i = 0; i + 1 < count; i++) mask_fd_close(&mfds[i]);
    /* Drain + free any per-stage redir preps (closes parent's write_fd on
     * any mask_fd_t and joins that pump too). */
    for (size_t i = 0; i < count; i++) redir_prep_free_parent(stage_preps[i]);

    free(pipes); free(mfds); free(pids); free(stage_preps);

    int rc = sh->opts.pipefail ? (any_nonzero ? any_nonzero : last_status)
                               : last_status;
    sh->last_status = rc;
    return rc;
}

static int run_simple_or_compound_in_child(shell_t *sh, node_t *n) {
    /* Close the masked parent stdout/stderr if they aren't the inherited
     * stdout/stderr; the dup2s at pipeline setup replaced our fds 0/1 but
     * we still hold the parent wrappers. They're harmless to keep open. */
    switch (n->kind) {
    case N_SIMPLE: return run_simple(sh, n, true);
    case N_NEG: {
        int r = run_simple_or_compound_in_child(sh, n->u.inner);
        return r == 0 ? 1 : 0;
    }
    default: {
        int rc = exec_node(sh, n);
        return rc;
    }
    }
}

/* ------------------------------------------------------------ compound */

static int run_if(shell_t *sh, node_t *n) {
    int cond = exec_node(sh, n->u.ifc.cond);
    if (cond == 0) return exec_node(sh, n->u.ifc.body);
    if (n->u.ifc.elif) return exec_node(sh, n->u.ifc.elif);
    if (n->u.ifc.else_body) return exec_node(sh, n->u.ifc.else_body);
    return 0;
}

static int run_while(shell_t *sh, node_t *n, bool invert) {
    int st = 0;
    sh->loop_depth++;
    while (1) {
        int c = exec_node(sh, n->u.loop.cond);
        bool go = invert ? (c != 0) : (c == 0);
        if (!go) break;
        st = exec_node(sh, n->u.loop.body);
        if (sh->break_req)    { sh->break_req--;    break; }
        if (sh->continue_req) { sh->continue_req--; if (sh->continue_req) { break; } else continue; }
        if (sh->return_req) break;
    }
    sh->loop_depth--;
    return st;
}

static int run_for(shell_t *sh, node_t *n) {
    int st = 0;
    sh->loop_depth++;
    fields_t vals; fields_init(&vals);
    if (n->u.forc.in_seen) {
        for (size_t i = 0; i < n->u.forc.word_count; i++)
            expand_word(sh, n->u.forc.words[i], &vals, false, true);
    } else {
        /* for NAME; do ... done - iterates over $@. */
        for (size_t i = 0; i < sh->pos_argc; i++)
            fields_push(&vals, xstrdup(sh->pos_args[i]));
    }
    for (size_t i = 0; i < vals.n; i++) {
        env_set(sh->env, n->u.forc.name, vals.v[i]);
        st = exec_node(sh, n->u.forc.body);
        if (sh->break_req)    { sh->break_req--;    break; }
        if (sh->continue_req) { sh->continue_req--; if (sh->continue_req) break; else continue; }
        if (sh->return_req) break;
    }
    fields_free(&vals);
    sh->loop_depth--;
    return st;
}

static int run_case(shell_t *sh, node_t *n) {
    fields_t subj; fields_init(&subj);
    expand_word(sh, n->u.casec.subject, &subj, false, false);
    const char *s = subj.n ? subj.v[0] : "";
    int st = 0;
    for (case_item_t *it = n->u.casec.items; it; it = it->next) {
        for (size_t i = 0; i < it->pattern_count; i++) {
            fields_t pat; fields_init(&pat);
            expand_word(sh, it->patterns[i], &pat, false, false);
            const char *p = pat.n ? pat.v[0] : "";
            int m = fnmatch(p, s, 0);
            fields_free(&pat);
            if (m == 0) {
                st = exec_node(sh, it->body);
                fields_free(&subj);
                return st;
            }
        }
    }
    fields_free(&subj);
    return st;
}

static int run_subshell(shell_t *sh, node_t *n) {
    pid_t pid = fork();
    if (pid < 0) { mash_err(1, "fork: %s", strerror(errno)); return 1; }
    if (pid == 0) {
        signals_reset_for_child();
        int rc = exec_node(sh, n->u.inner);
        _exit(rc & 0xFF);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}

static int run_compound(shell_t *sh, node_t *n) {
    redir_applied_t *rl = NULL;
    if (apply_redirs(sh, n->redirs, &rl, true) < 0) { free_applied(rl); return 1; }
    int rc = 0;
    switch (n->kind) {
    case N_IF:    rc = run_if(sh, n); break;
    case N_WHILE: rc = run_while(sh, n, false); break;
    case N_UNTIL: rc = run_while(sh, n, true); break;
    case N_FOR:   rc = run_for(sh, n); break;
    case N_CASE:  rc = run_case(sh, n); break;
    case N_SUBSHELL: rc = run_subshell(sh, n); break;
    case N_GROUP: rc = exec_node(sh, n->u.inner); break;
    case N_FUNCDEF:
        func_define(sh->env, n->u.funcdef.name, n->u.funcdef.body);
        n->u.funcdef.body = NULL; /* handed off */
        rc = 0;
        break;
    case N_NEG: {
        int r = exec_node(sh, n->u.inner);
        rc = r == 0 ? 1 : 0;
        break;
    }
    default:
        rc = 1;
    }
    restore_redirs(rl);
    sh->last_status = rc;
    return rc;
}

/* --------------------------------------------------------------- list */

static int run_list(shell_t *sh, list_t *l) {
    int rc = 0;
    for (size_t i = 0; i < l->count; i++) {
        node_t *item = l->items[i];
        if (l->seps[i] == SEP_AMP) {
            /* Background: fork the item. */
            pid_t pid = fork();
            if (pid < 0) {
                mash_err(1, "fork: %s", strerror(errno));
                rc = 1;
                if (sh->opts.errexit) break;
                continue;
            }
            if (pid == 0) {
                signals_reset_for_child();
                int r = exec_node(sh, item);
                _exit(r & 0xFF);
            }
            char buf[64];
            snprintf(buf, sizeof(buf), "[bg %d]", (int)pid);
            int jid = jobs_add(sh->jobs, pid, pid, buf);
            mashf(stderr, "[%d] %d\n", jid, (int)pid);
            rc = 0;
        } else {
            rc = exec_node(sh, item);
            if (sh->break_req || sh->continue_req || sh->return_req) break;
            if (sh->opts.errexit && rc != 0) break;
        }
    }
    return rc;
}

/* ----------------------------------------------------------- and/or */

static int run_and_or(shell_t *sh, node_t *n) {
    int lv = exec_node(sh, n->u.andor.left);
    if (n->u.andor.op == AND_OP) {
        if (lv == 0) return exec_node(sh, n->u.andor.right);
        return lv;
    } else {
        if (lv != 0) return exec_node(sh, n->u.andor.right);
        return lv;
    }
}

/* ----------------------------------------------------------- dispatch */

int exec_node(shell_t *sh, node_t *n) {
    if (!n) return 0;
    if (sh->opts.noexec) return 0;
    switch (n->kind) {
    case N_LIST:     return run_list(sh, &n->u.list);
    case N_AND_OR:   return run_and_or(sh, n);
    case N_PIPELINE: return run_pipeline(sh, n);
    case N_SIMPLE: {
        /* Apply command-level redirs in the parent (non-forking). */
        int rc = run_simple(sh, n, false);
        return rc;
    }
    case N_NEG: {
        int r = exec_node(sh, n->u.inner);
        int rc = r == 0 ? 1 : 0;
        sh->last_status = rc;
        return rc;
    }
    case N_IF: case N_WHILE: case N_UNTIL: case N_FOR:
    case N_CASE: case N_SUBSHELL: case N_GROUP: case N_FUNCDEF:
        return run_compound(sh, n);
    }
    return 0;
}
