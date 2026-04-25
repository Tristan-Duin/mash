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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__linux__) || defined(__sun) || defined(__CYGWIN__)
#  include <pty.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      defined(__OpenBSD__) || defined(__DragonFly__)
#  include <util.h>
#endif

#include "builtins.h"
#include "env.h"
#include "expand.h"
#include "jobs.h"
#include "mash.h"
#include "mask.h"
#include "mask_fd.h"
#include "signals.h"
#include "util.h"

/* Open an anonymous temp file for staging a heredoc body. Used instead of
 * a pipe so a heredoc larger than the kernel's pipe buffer cannot deadlock
 * the parent at write_all() time. Returns a writable+readable fd at offset
 * 0, or -1 on failure. The file is unlinked from the filesystem before we
 * return so it disappears on close. */
static int open_heredoc_tmp(void) {
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
    char tpl[512];
    int n = snprintf(tpl, sizeof(tpl), "%s/mash-heredoc-XXXXXX", tmpdir);
    if (n < 0 || (size_t)n >= sizeof(tpl)) return -1;
    int fd = mkstemp(tpl);
    if (fd < 0) return -1;
    /* unlink immediately - the file is anonymous from here on. */
    (void)unlink(tpl);
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    return fd;
}

/* In any forked shell-child (subshell, pipeline stage, background `&`),
 * close the saved raw stdout/stderr fds the parent shell holds. Without
 * this they remain open in the child as fd-3+ alongside the masked fd 1/2,
 * which means user shell code or sloppy programs could write directly to
 * them and bypass the mask. CLOEXEC handles the exec(2) case; this covers
 * shell code that runs inside the fork without execing. */
static void close_raw_fds_in_child(shell_t *sh) {
    if (!sh) return;
    if (sh->real_stdout >= 0) { close(sh->real_stdout); sh->real_stdout = -1; }
    if (sh->real_stderr >= 0) { close(sh->real_stderr); sh->real_stderr = -1; }
}

/* Forward decl - apply_assigns is defined further below alongside the
 * other dispatch helpers, but the pty path needs to call it from within
 * the child to honour `VAR=val cmd ...` prefix assignments. */
static int apply_assigns(shell_t *sh, assign_t *a, bool exported_temp,
                         assign_t **saved_out);

/* Allowlist of programs that genuinely need a real terminal. We only
 * route through the pty path for these - everything else (`ls`, `cat`,
 * `whoami`, `grep`, ...) keeps using the pumped-fd path, which has been
 * the default since day one, is simpler, and never has to fight with
 * raw mode / OPOST / line-discipline corner cases.
 *
 * We match on the basename of argv[0]; absolute paths like
 * `/usr/bin/vim` and bare `vim` both hit the same entry. */
static bool argv0_needs_pty(const char *cmd) {
    if (!cmd || !*cmd) return false;
    const char *base = strrchr(cmd, '/');
    base = base ? base + 1 : cmd;
    static const char *const TUI_NAMES[] = {
        /* editors */
        "vim", "vi", "nvim", "neovim", "view", "ex", "vile",
        "nano", "pico", "joe", "emacs", "mg", "ne", "ed", "jed",
        /* pagers / readers */
        "less", "more", "most", "pg", "man", "info",
        /* monitors */
        "htop", "top", "btop", "btm", "glances", "atop", "iotop",
        "iftop", "nethogs", "powertop",
        /* remote shells */
        "ssh", "slogin", "mosh", "mosh-client", "telnet", "rlogin",
        /* multiplexers */
        "tmux", "screen", "dvtm", "abduco", "dtach", "byobu",
        /* file managers */
        "mc", "ranger", "nnn", "vifm", "lf", "fff", "clifm",
        /* browsers / mail / chat */
        "w3m", "lynx", "links", "elinks", "browsh",
        "mutt", "neomutt", "alpine", "pine", "sup",
        "irssi", "weechat", "bitlbee", "profanity",
        /* git / k8s / docker tuis */
        "tig", "lazygit", "lazydocker", "k9s", "gitui",
        /* misc */
        "ncdu", "cmus", "ncmpcpp", "moc", "calcurse", "taskwarrior",
        "watch", "dialog", "whiptail",
        NULL
    };
    for (size_t i = 0; TUI_NAMES[i]; i++) {
        if (str_eq(base, TUI_NAMES[i])) return true;
    }
    return false;
}

/* ---------------------------------------------------------- pty execution
 *
 * For interactive foreground externals (no redirections) we hand the child
 * a real pseudo-terminal via openpty(3) instead of pump-piped fds. The
 * child then sees `isatty(0/1/2) == true`, full termios, and a controlling
 * tty - so vim, less, htop, ssh, and friends behave normally. The parent
 * forwards bytes between the user's real tty and the master, running every
 * byte coming back from the child through the mask engine before it lands
 * on the screen.
 *
 * Why this is safe to add even with the lockdown story: the child writes
 * only to the slave; the slave loops to the master in the parent; from
 * there bytes flow exclusively through `mask_stream_push` to real_stdout.
 * There is no path from the child's stdout to the user's terminal that
 * doesn't pass through the mask engine.
 */

/* Communicating window-size changes from the SIGWINCH handler back into
 * the forwarding loop. We don't call ioctl from the handler; we just set
 * a flag and let the loop refresh the slave's winsize the next time poll()
 * returns. */
static volatile sig_atomic_t pty_winch_flag;
static void pty_handle_winch(int sig) { (void)sig; pty_winch_flag = 1; }

/* Run an external command on a pty. Preconditions: shell is interactive,
 * the simple command has no redirections, the user's stdin/real_stdout
 * are real ttys.
 *
 * Returns the child's wait status code. The special return value -2 means
 * "this command is not eligible for the pty path - fall back to the
 * pumped-fd path" (e.g. real_stdout isn't a tty, or openpty failed in a
 * recoverable way). */
#define PTY_FALLBACK (-2)

static int run_external_via_pty(shell_t *sh, simple_t *s, char **argv) {
    int tty_fd = sh->real_stdout;
    if (tty_fd < 0 || !isatty(tty_fd))   return PTY_FALLBACK;
    if (!isatty(STDIN_FILENO))           return PTY_FALLBACK;

    struct termios saved_term;
    if (tcgetattr(tty_fd, &saved_term) < 0) return PTY_FALLBACK;

    struct winsize ws;
    bool have_ws = (ioctl(tty_fd, TIOCGWINSZ, &ws) == 0);

    /* Make sure the previous command's output has fully drained through
     * the masked-stdout pump before we start writing to real_stdout from
     * this loop. Otherwise the two write paths can interleave on screen. */
    mash_drain_output(sh);

    int master = -1, slave = -1;
    if (openpty(&master, &slave, NULL, &saved_term, have_ws ? &ws : NULL) < 0) {
        mash_err(1, "openpty: %s", strerror(errno));
        return -1;
    }
    /* CLOEXEC the master so it doesn't leak into anything we sub-fork.
     * Master stays blocking on purpose: write_all() does not understand
     * EAGAIN, so a non-blocking master would silently drop keystrokes
     * forwarded to the slave whenever the slave's input queue was even
     * briefly full - which is exactly what made vim feel "broken" (it
     * never received `:`, `i`, `q`, etc.). The parent's read side is
     * driven by poll() so blocking is fine on that side too. */
    int f = fcntl(master, F_GETFD);
    if (f >= 0) (void)fcntl(master, F_SETFD, f | FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        mash_err(1, "fork: %s", strerror(errno));
        close(master);
        close(slave);
        return -1;
    }
    if (pid == 0) {
        /* --- child --- */
        signals_reset_for_child();
        close_raw_fds_in_child(sh);
        close(master);
        if (setsid() < 0) _exit(127);
#ifdef TIOCSCTTY
        (void)ioctl(slave, TIOCSCTTY, 0);
#endif
        if (dup2(slave, STDIN_FILENO)  < 0 ||
            dup2(slave, STDOUT_FILENO) < 0 ||
            dup2(slave, STDERR_FILENO) < 0) _exit(127);
        if (slave > STDERR_FILENO) close(slave);

        apply_assigns(sh, s->assigns, true, NULL);
        for (var_t *v = sh->env->vars; v; v = v->next) {
            if (v->exported && v->value) setenv(v->name, v->value, 1);
        }
        execvp(argv[0], argv);
        /* execvp failed; the message goes through the slave -> master ->
         * mask -> screen. */
        mash_err(127, "%s: %s", argv[0], strerror(errno));
        _exit(127);
    }

    /* --- parent --- */
    close(slave);

    /* IMPORTANT: do NOT call setpgid(pid, pid) here. There is a fork
     * race: if the parent's setpgid landed before the child's setsid()
     * (which it often did on fast Linux kernels), the child became a
     * process-group leader, and POSIX requires setsid() to fail with
     * EPERM for a pgrp leader. The child would then silently _exit(127),
     * the parent's master would see EOF, and the whole pty session would
     * vanish in milliseconds - exactly the "vim Makefile -> immediately
     * back to prompt with no output" symptom.
     *
     * The child's setsid() already creates a brand-new session AND a new
     * process group (with the child as leader) atomically, and TIOCSCTTY
     * on the slave attaches the slave as the new session's controlling
     * terminal. That is sufficient for vim/less/htop/ssh to behave
     * correctly. We don't tcsetpgrp the real tty either: the child is in
     * a different session now (POSIX wouldn't let us), and Ctrl-C/Z
     * still reach the child via byte-forwarding through the slave's
     * line discipline. */

    /* Put the user's tty into FULLY raw mode (input AND output) for the
     * duration of the pty session. This is the standard pattern used by
     * tmux / screen / `ssh -t` / `script`: the slave inside the pty
     * already applies whatever output processing the running program
     * wants (cooked / raw / etc.), and the parent's job is just to
     * forward bytes byte-for-byte. Leaving OPOST/ONLCR on at the parent
     * tty would graft an extra `\n` -> `\r\n` translation on top of
     * already-translated output, which scribbles over a TUI's screen
     * drawing (vim, less, htop, ...). The reason `whoami` etc. don't
     * suffer from full raw mode is that they no longer take the pty
     * path - argv0_needs_pty() routes them through the pumped-fd path. */
    struct termios raw = saved_term;
    cfmakeraw(&raw);
    (void)tcsetattr(tty_fd, TCSANOW, &raw);

    /* Window-size forwarding. We deliberately do NOT use SA_RESTART so
     * SIGWINCH wakes poll() with EINTR, which lets us re-run the loop
     * head and forward the new winsize to the slave promptly. */
    pty_winch_flag = 0;
    struct sigaction sa, sa_old_winch;
    sa.sa_handler = pty_handle_winch;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGWINCH, &sa, &sa_old_winch);

    mask_stream_t ms;
    mask_stream_init(&ms, sh->mask);

    char buf[4096];
    bool master_eof = false;
    while (!master_eof) {
        if (pty_winch_flag) {
            pty_winch_flag = 0;
            struct winsize w;
            if (ioctl(tty_fd, TIOCGWINSZ, &w) == 0)
                (void)ioctl(master, TIOCSWINSZ, &w);
        }

        struct pollfd pfd[2];
        pfd[0].fd = STDIN_FILENO; pfd[0].events = POLLIN; pfd[0].revents = 0;
        pfd[1].fd = master;       pfd[1].events = POLLIN; pfd[1].revents = 0;

        /* Same idle-flush trick as the fd pumps: if we have buffered
         * bytes, wake every 25 ms to push out anything that's safe so a
         * line-less burst from a TUI doesn't get held. */
        int timeout = (ms.pending.len == 0) ? -1 : 25;
        int pr = poll(pfd, 2, timeout);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            strbuf_t out; strbuf_init(&out);
            mask_stream_idle_flush(&ms, &out);
            if (out.len) (void)write_all(tty_fd, out.data, out.len);
            strbuf_free(&out);
            continue;
        }

        if (pfd[0].revents & POLLIN) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n > 0) (void)write_all(master, buf, (size_t)n);
            /* If real-stdin closes the child still runs; we just stop
             * forwarding from it. */
        }
        if (pfd[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            /* Read whatever the kernel has queued. POSIX guarantees that
             * any bytes the slave wrote before disconnecting come back
             * here before read() ever returns 0 / EIO, so we don't need
             * a non-blocking drain loop - if more data is pending after
             * this read, poll() will simply wake us with POLLIN again. */
            ssize_t n = read(master, buf, sizeof(buf));
            if (n > 0) {
                strbuf_t out; strbuf_init(&out);
                mask_stream_push(&ms, buf, (size_t)n, &out);
                if (out.len) (void)write_all(tty_fd, out.data, out.len);
                strbuf_free(&out);
            } else if (n == 0) {
                master_eof = true;
            } else if (errno != EINTR) {
                /* On Linux read(master) returns -1/EIO once the slave is
                 * fully closed; treat that and other unrecoverable errors
                 * as EOF. */
                master_eof = true;
            }
        }
    }

    /* Final flush of anything held in the mask stream. */
    {
        strbuf_t out; strbuf_init(&out);
        mask_stream_finish(&ms, &out);
        if (out.len) (void)write_all(tty_fd, out.data, out.len);
        strbuf_free(&out);
    }
    mask_stream_free(&ms);

    int st = 0;
    pid_t r = waitpid(pid, &st, WUNTRACED);
    bool stopped = (r > 0 && WIFSTOPPED(st));

    /* Restore signals and terminal modes. We didn't change the
     * foreground pgrp on the real tty (the child lives in a different
     * session entirely), so there's nothing to restore there. */
    sigaction(SIGWINCH, &sa_old_winch, NULL);
    (void)tcsetattr(tty_fd, TCSANOW, &saved_term);
    close(master);

    if (stopped) {
        /* User backgrounded with Ctrl-Z. Track the stopped child as a job
         * so `jobs`, `fg`, `bg` can pick it up. */
        char jbuf[64];
        snprintf(jbuf, sizeof(jbuf), "[stopped %d]", (int)pid);
        int jid = jobs_add(sh->jobs, pid, pid, jbuf);
        for (job_t *j = sh->jobs->head; j; j = j->next)
            if (j->id == jid) { j->state = JOB_STOPPED; break; }
        mashf(stderr, "\n[%d]+  Stopped\n", jid);
        sh->last_status = 128 + WSTOPSIG(st);
        return sh->last_status;
    }

    int code = WIFEXITED(st)
             ? WEXITSTATUS(st)
             : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    sh->last_status = code;
    return code;
}

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
        /* Heredoc: the target word carries the *body*. Stage it in an
         * anonymous temp file (rather than a pipe) so arbitrarily large
         * bodies never deadlock at write time. */
        int fd = open_heredoc_tmp();
        if (fd < 0) {
            mash_err(1, "heredoc: %s", strerror(errno));
            free(target);
            return -1;
        }
        if (write_all(fd, target, strlen(target)) < 0 ||
            lseek(fd, 0, SEEK_SET) < 0) {
            mash_err(1, "heredoc: %s", strerror(errno));
            close(fd);
            free(target);
            return -1;
        }
        target_fd = fd;
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
            /* Anonymous tempfile so big heredocs don't deadlock on the
             * pre-fork write_all(). */
            int fd = open_heredoc_tmp();
            if (fd < 0) {
                mash_err(1, "heredoc: %s", strerror(errno));
                rc = -1; break;
            }
            if (write_all(fd, target, strlen(target)) < 0 ||
                lseek(fd, 0, SEEK_SET) < 0) {
                mash_err(1, "heredoc: %s", strerror(errno));
                close(fd);
                rc = -1; break;
            }
            e->src_fd = fd;
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
        /* Interactive foreground command with no redirections that is on
         * the TUI allowlist: route it through a pty so the child sees a
         * real terminal (isatty == true, full termios, controlling tty
         * for Ctrl-C/Ctrl-Z). Output still passes through the mask
         * engine before reaching the user. Everything else - the vast
         * majority of commands - stays on the pumped-fd path, which is
         * the well-tested default. We fall back to the pumped-fd path
         * if the pty path declines (e.g. real_stdout isn't a tty). */
        if (sh->opts.interactive && s->redirs == NULL &&
            argv0_needs_pty(argv[0])) {
            int rc = run_external_via_pty(sh, s, argv);
            if (rc != PTY_FALLBACK) {
                free_argv(argv);
                return rc;
            }
        }

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
            close_raw_fds_in_child(sh);
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
    bool *mfds_ok = xcalloc(count - 1, sizeof(*mfds_ok));
    pid_t *pids = xcalloc(count, sizeof(*pids));
    /* Per-stage, parent-held prep for any redirs attached to the stage's
     * simple command (e.g., `cmd > file` inside a pipeline). */
    redir_prep_t **stage_preps = xcalloc(count, sizeof(*stage_preps));

    /* Pre-init pipes[] entries to -1 so the cleanup label can tell which
     * have actually been opened. */
    for (size_t i = 0; i + 1 < count; i++) {
        pipes[2*i]     = -1;
        pipes[2*i + 1] = -1;
    }
    size_t built = 0;        /* pipes[0..built-1] fully constructed */
    size_t spawned = 0;      /* pids[0..spawned-1] are valid */
    int    setup_err = 0;

    for (size_t i = 0; i + 1 < count; i++) {
        int p[2];
        if (pipe(p) < 0) {
            mash_err(1, "pipe: %s", strerror(errno));
            setup_err = 1;
            goto pipeline_cleanup;
        }
        /* Wrap the write end so bytes flowing into stage i+1 are masked. */
        if (mask_fd_wrap_write(sh->mask, p[1], true, &mfds[i]) < 0) {
            mash_err(1, "mask_fd_wrap_write: %s", strerror(errno));
            close(p[0]);
            close(p[1]);
            setup_err = 1;
            goto pipeline_cleanup;
        }
        mfds_ok[i]     = true;
        pipes[2*i]     = p[0];
        pipes[2*i + 1] = mfds[i].write_fd; /* masked writer the child sees */
        built++;
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
        if (pid < 0) {
            mash_err(1, "fork: %s", strerror(errno));
            g_pending_child_prep = NULL;
            setup_err = 1;
            goto pipeline_cleanup;
        }
        if (pid == 0) {
            signals_reset_for_child();
            close_raw_fds_in_child(sh);
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
        spawned++;
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

    free(pipes); free(mfds); free(mfds_ok); free(pids); free(stage_preps);

    int rc = sh->opts.pipefail ? (any_nonzero ? any_nonzero : last_status)
                               : last_status;
    sh->last_status = rc;
    return rc;

pipeline_cleanup:
    /* Setup failure path. Reap whatever we did manage to fork, tear the
     * partially-built mask pumps and pipes down, and report a generic
     * error. We deliberately do NOT die() here so transient EMFILE / EAGAIN
     * doesn't take the whole shell down. */
    g_pending_child_prep = NULL;
    /* Close the pipe fds we still own so any spawned children see EOF. */
    for (size_t i = 0; i < built; i++) {
        if (pipes[2*i]     >= 0) close(pipes[2*i]);
        if (pipes[2*i + 1] >= 0) {
            close(pipes[2*i + 1]);
            mfds[i].write_fd = -1;
        }
    }
    for (size_t i = 0; i < spawned; i++) {
        int st = 0;
        (void)waitpid(pids[i], &st, 0);
    }
    for (size_t i = 0; i < built; i++) {
        if (mfds_ok[i]) mask_fd_close(&mfds[i]);
    }
    for (size_t i = 0; i < count; i++) {
        if (stage_preps[i]) redir_prep_free_parent(stage_preps[i]);
    }
    free(pipes); free(mfds); free(mfds_ok); free(pids); free(stage_preps);
    sh->last_status = setup_err ? 1 : 0;
    return sh->last_status;
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
        close_raw_fds_in_child(sh);
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
                close_raw_fds_in_child(sh);
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
