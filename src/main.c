/* main.c - entry point and REPL.
 *
 * The first act after arg parsing is to initialize the mask engine and
 * wrap the real stdout/stderr fds so *every* subsequent write - from
 * prompts to error messages to program output - passes through the mask.
 * The raw real_stdout / real_stderr saved inside shell_t are only used by
 * mash_raw_write() and should be limited to rare internal diagnostics.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

#include "env.h"
#include "executor.h"
#include "history.h"
#include "jobs.h"
#include "lexer.h"
#include "lineedit.h"
#include "mash.h"
#include "mask.h"
#include "mask_fd.h"
#include "parser.h"
#include "signals.h"
#include "util.h"

static shell_t *g_active;

shell_t *mash_active(void)            { return g_active; }
void     mash_set_active(shell_t *s)  { g_active = s; }

/* ------------------------------------------------------------------ mashf */

int mashf_fd(int fd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    strbuf_t b; strbuf_init(&b);
    strbuf_vappendf(&b, fmt, ap);
    va_end(ap);
    int rc = write_all(fd, b.data, b.len);
    strbuf_free(&b);
    return rc;
}

int mashf(FILE *stream, const char *fmt, ...) {
    shell_t *s = mash_active();
    int fd;
    if (stream == stderr) fd = s ? s->masked_stderr : STDERR_FILENO;
    else                  fd = s ? s->masked_stdout : STDOUT_FILENO;
    if (fd < 0) fd = (stream == stderr) ? STDERR_FILENO : STDOUT_FILENO;

    va_list ap;
    va_start(ap, fmt);
    strbuf_t b; strbuf_init(&b);
    strbuf_vappendf(&b, fmt, ap);
    va_end(ap);
    int rc = write_all(fd, b.data, b.len);
    strbuf_free(&b);
    return rc;
}

int mash_raw_write(int real_fd, const void *buf, size_t len) {
    return write_all(real_fd, buf, len);
}

void mash_drain_output(shell_t *s) {
    if (!s) return;
    /* Order matters: stderr first so any error message printed by the
     * just-finished command lands on the terminal before the next
     * prompt, even though stderr is mostly unbuffered in practice. */
    if (s->masked_stderr_pump) mask_fd_drain(s->masked_stderr_pump);
    if (s->masked_stdout_pump) mask_fd_drain(s->masked_stdout_pump);
}

void mash_err(int status, const char *fmt, ...) {
    shell_t *s = mash_active();
    int fd = s ? s->masked_stderr : STDERR_FILENO;
    if (fd < 0) fd = STDERR_FILENO;
    strbuf_t b; strbuf_init(&b);
    strbuf_appendz(&b, "mash: ");
    va_list ap;
    va_start(ap, fmt);
    strbuf_vappendf(&b, fmt, ap);
    va_end(ap);
    strbuf_push(&b, '\n');
    write_all(fd, b.data, b.len);
    strbuf_free(&b);
    if (s) s->last_status = status;
}

/* ------------------------------------------------------------ run helpers */

int mash_run_string(shell_t *s, const char *src, const char *origin) {
    (void)origin;
    token_list_t toks = { NULL, NULL };
    char *err = NULL;
    if (lex(src, &toks, &err) < 0) {
        mash_err(2, "%s", err ? err : "lex error");
        free(err);
        return 2;
    }
    node_t *root = NULL;
    if (parse(&toks, &root, &err) < 0) {
        mash_err(2, "%s", err ? err : "parse error");
        free(err);
        token_list_free(&toks);
        return 2;
    }
    token_list_free(&toks);
    int rc = exec_node(s, root);
    node_free(root);
    s->last_status = rc;
    return rc;
}

int mash_run_file(shell_t *s, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { mash_err(1, "%s: %s", path, strerror(errno)); return 1; }
    strbuf_t b; strbuf_init(&b);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) strbuf_append(&b, buf, n);
    /* Distinguish a clean EOF from an I/O error so we don't silently
     * execute a truncated script. */
    if (ferror(f)) {
        mash_err(1, "%s: read error: %s", path, strerror(errno));
        fclose(f);
        strbuf_free(&b);
        return 1;
    }
    if (fclose(f) != 0) {
        mash_err(1, "%s: close: %s", path, strerror(errno));
        strbuf_free(&b);
        return 1;
    }
    int rc = mash_run_string(s, b.data ? b.data : "", path);
    strbuf_free(&b);
    return rc;
}

/* ------------------------------------------------------------- REPL */

static char *build_prompt(shell_t *s) {
    const char *ps1 = env_get(s->env, "PS1");
    if (!ps1) ps1 = "mash$ ";
    /* Simple %-expansion: \u, \h, \w. These values are leak-y so we rely
     * on the masked output path to redact them. */
    strbuf_t b; strbuf_init(&b);
    for (const char *p = ps1; *p; p++) {
        if (*p == '\\' && p[1]) {
            p++;
            if      (*p == 'u') strbuf_appendz(&b, env_get(s->env, "USER") ? env_get(s->env, "USER") : "");
            else if (*p == 'h') {
                char h[256]; if (gethostname(h, sizeof(h)) == 0) strbuf_appendz(&b, h);
            } else if (*p == 'w') {
                char cwd[4096]; if (getcwd(cwd, sizeof(cwd))) strbuf_appendz(&b, cwd);
            } else if (*p == 'n') strbuf_push(&b, '\n');
            else if (*p == 't') {
                time_t t = time(NULL); struct tm tm; localtime_r(&t, &tm);
                char buf[16]; strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
                strbuf_appendz(&b, buf);
            }
            else strbuf_push(&b, *p);
        } else strbuf_push(&b, *p);
    }
    /* Run the prompt through the mask before display. */
    char *masked = NULL; size_t ml = 0;
    mask_apply(s->mask, b.data ? b.data : "", b.len, &masked, &ml);
    strbuf_free(&b);
    return masked;
}

static void repl(shell_t *s) {
    while (1) {
        jobs_cleanup(s->jobs);
        /* Wait for the masked-stdout/stderr pumps to finish forwarding
         * the previous command's output. The prompt is written directly
         * to real_stdout to bypass the pump (it's already masked and
         * carries line-editor escapes), so without this drain a long
         * builtin's output and the next prompt race on the terminal. */
        mash_drain_output(s);

        char *prompt = build_prompt(s);
        /* Write prompt directly to real stdout (it's already masked). */
        char *line = lineedit_readline(STDIN_FILENO, s->real_stdout, prompt, s->history);
        free(prompt);
        if (!line) {
            /* EOF: drain again so any trailing output is flushed before
             * we print the closing newline. */
            mash_drain_output(s);
            mashf_fd(s->real_stdout, "\n");
            break;
        }
        if (*line) {
            history_add(s->history, line);
            history_save(s->history);
            (void)mash_run_string(s, line, "stdin");
        }
        free(line);
    }
}

/* --------------------------------------------------- option parsing */

static void usage(void) {
    const char *u =
        "Usage: mash [options] [script [args...]]\n"
        "  -c CMD    execute CMD and exit\n"
        "  -i        force interactive mode\n"
        "  -l        act as a login shell\n"
        "  --norc    do not read rc files\n"
        "  -s        read commands from stdin\n"
        "  -h, --help\n";
    write_all(STDERR_FILENO, u, strlen(u));
}

int main(int argc, char **argv) {
    shell_t sh;
    memset(&sh, 0, sizeof(sh));
    sh.real_stdout = dup(STDOUT_FILENO);
    if (sh.real_stdout < 0)
        die("dup(stdout): %s", strerror(errno));
    sh.real_stderr = dup(STDERR_FILENO);
    if (sh.real_stderr < 0)
        die("dup(stderr): %s", strerror(errno));
    sh.shell_pgid  = getpgrp();
    sh.progname    = xstrdup(argv[0] ? argv[0] : "mash");
    sh.env     = env_new();
    env_import_process(sh.env);
    sh.mask    = mask_engine_new();
    sh.jobs    = jobs_new();
    sh.history = history_new(sh.mask);
    sh.last_status = 0;
    mash_set_active(&sh);

    mash_mask_init_defaults(sh.mask);

    /* Wrap stdout/stderr through the mask. After this, *everything* the
     * shell writes to fd 1 or 2 is redacted. */
    mask_fd_t mstdout, mstderr;
    bool mstdout_ok = false, mstderr_ok = false;
    if (mask_fd_wrap_write(sh.mask, sh.real_stdout, false, &mstdout) == 0) {
        if (dup2(mstdout.write_fd, STDOUT_FILENO) < 0) {
            mash_err(0, "dup2(masked stdout): %s", strerror(errno));
            mask_fd_close(&mstdout);
            sh.masked_stdout = STDOUT_FILENO;
        } else {
            sh.masked_stdout = STDOUT_FILENO;
            sh.masked_stdout_pump = &mstdout;
            mstdout_ok = true;
        }
    } else {
        mash_err(0, "failed to install masked stdout: %s", strerror(errno));
        sh.masked_stdout = STDOUT_FILENO;
    }
    if (mask_fd_wrap_write(sh.mask, sh.real_stderr, false, &mstderr) == 0) {
        if (dup2(mstderr.write_fd, STDERR_FILENO) < 0) {
            mash_err(0, "dup2(masked stderr): %s", strerror(errno));
            mask_fd_close(&mstderr);
            sh.masked_stderr = STDERR_FILENO;
        } else {
            sh.masked_stderr = STDERR_FILENO;
            sh.masked_stderr_pump = &mstderr;
            mstderr_ok = true;
        }
    } else {
        mash_err(0, "failed to install masked stderr: %s", strerror(errno));
        sh.masked_stderr = STDERR_FILENO;
    }

    /* Options */
    const char *cmd_str = NULL;
    const char *script  = NULL;
    bool force_inter = false;
    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (str_eq(a, "-c") && i + 1 < argc) { cmd_str = argv[++i]; continue; }
        if (str_eq(a, "-i")) { force_inter = true; continue; }
        if (str_eq(a, "-l") || (a[0] == '-' && a[1] == '\0')) { sh.opts.login = true; continue; }
        if (str_eq(a, "--norc")) { sh.opts.norc = true; continue; }
        if (str_eq(a, "-s")) continue;
        if (str_eq(a, "-h") || str_eq(a, "--help")) { usage(); return 0; }
        if (str_eq(a, "--")) { i++; break; }
        if (a[0] == '-') { mash_err(2, "unknown option: %s", a); return 2; }
        script = a; i++;
        break;
    }
    /* Remaining argv become positional args. */
    sh.pos_argc = (size_t)(argc - i);
    sh.pos_args = xcalloc(sh.pos_argc + 1, sizeof(*sh.pos_args));
    for (size_t k = 0; k < sh.pos_argc; k++) sh.pos_args[k] = xstrdup(argv[i + (int)k]);

    sh.opts.interactive = force_inter || (!cmd_str && !script && isatty(STDIN_FILENO));
    if (sh.opts.interactive) signals_install_interactive();

    /* Load rc unless suppressed. */
    if (sh.opts.interactive && !sh.opts.norc) {
        struct stat st;
        if (stat("/etc/mashrc", &st) == 0) mash_run_file(&sh, "/etc/mashrc");
        const char *home = env_get(sh.env, "HOME");
        if (home) {
            strbuf_t b; strbuf_init(&b);
            strbuf_appendf(&b, "%s/.mashrc", home);
            if (stat(b.data, &st) == 0) mash_run_file(&sh, b.data);
            strbuf_free(&b);
        }
    }

    /* History persistence path. */
    const char *home = env_get(sh.env, "HOME");
    if (home) {
        strbuf_t b; strbuf_init(&b);
        strbuf_appendf(&b, "%s/.mash_history", home);
        history_set_path(sh.history, b.data);
        strbuf_free(&b);
        history_load(sh.history);
    }

    int rc = 0;
    if (cmd_str) {
        rc = mash_run_string(&sh, cmd_str, "-c");
    } else if (script) {
        rc = mash_run_file(&sh, script);
    } else if (sh.opts.interactive) {
        repl(&sh);
        history_save(sh.history);
    } else {
        /* Read stdin as a script. */
        strbuf_t b; strbuf_init(&b);
        char buf[4096];
        ssize_t n;
        bool read_err = false;
        for (;;) {
            n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n > 0) {
                strbuf_append(&b, buf, (size_t)n);
                continue;
            }
            if (n == 0) break;        /* EOF */
            if (errno == EINTR) continue;
            mash_err(1, "stdin: read error: %s", strerror(errno));
            read_err = true;
            break;
        }
        if (read_err) {
            rc = 1;
        } else {
            rc = mash_run_string(&sh, b.data ? b.data : "", "stdin");
        }
        strbuf_free(&b);
    }

    /* Teardown. Close fd 1 and 2 so pumps get EOF, then join them.
     * Only close+drain wrappers we actually installed; otherwise we'd
     * close uninitialized mask_fd_t state. Clear the shell-side pump
     * pointers first so any late mash_drain_output() call (e.g. from a
     * destructor) becomes a no-op rather than touching freed state. */
    sh.masked_stdout_pump = NULL;
    sh.masked_stderr_pump = NULL;
    if (sh.masked_stdout == STDOUT_FILENO) close(STDOUT_FILENO);
    if (sh.masked_stderr == STDERR_FILENO) close(STDERR_FILENO);
    if (mstdout_ok) mask_fd_close(&mstdout);
    if (mstderr_ok) mask_fd_close(&mstderr);

    if (sh.real_stdout >= 0) close(sh.real_stdout);
    if (sh.real_stderr >= 0) close(sh.real_stderr);

    env_free(sh.env);
    mask_engine_free(sh.mask);
    jobs_free(sh.jobs);
    history_free(sh.history);
    for (size_t k = 0; k < sh.pos_argc; k++) free(sh.pos_args[k]);
    free(sh.pos_args);
    free(sh.progname);
    return rc & 0xFF;
}
