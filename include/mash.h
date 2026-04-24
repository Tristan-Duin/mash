/* mash.h - top-level shell types and the masked output API.
 *
 * Every module includes this to reach the shared shell state and to use
 * mashf() / mashf_raw() for printing, which route through the mask engine.
 */
#ifndef MASH_MASH_H
#define MASH_MASH_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "util.h"

/* Forward declarations ---------------------------------------------------- */
struct env_t;
struct mask_engine_t;
struct job_list_t;
struct history_t;

/* Shell-level options toggled via `set -o`. */
typedef struct {
    bool errexit;    /* set -e */
    bool nounset;    /* set -u */
    bool xtrace;     /* set -x */
    bool pipefail;   /* set -o pipefail */
    bool noexec;     /* set -n */
    bool verbose;    /* set -v */
    bool nomask_cmdsub; /* set -o nomask-cmdsub */
    bool interactive;   /* true when stdin is a tty and no -c / script */
    bool login;         /* -l or argv[0][0] == '-' */
    bool norc;          /* --norc */
} shell_opts_t;

/* Global shell state. A single instance lives in main; pointers to its
 * members are passed around to keep coupling explicit and to make the code
 * unit-testable without globals. A thin accessor is also exposed so
 * modules that really need the active shell can reach it. */
typedef struct shell_t {
    shell_opts_t    opts;
    int             last_status;      /* $? */
    pid_t           shell_pgid;       /* initial pgid */
    int             terminal_fd;      /* /dev/tty if interactive, else -1 */
    int             real_stdout;      /* saved pre-mask fd 1 */
    int             real_stderr;      /* saved pre-mask fd 2 */
    int             masked_stdout;    /* fd the shell writes prompts etc to */
    int             masked_stderr;
    struct env_t          *env;
    struct mask_engine_t  *mask;
    struct job_list_t     *jobs;
    struct history_t      *history;
    char           *progname;         /* argv[0] */
    char          **pos_args;         /* $1..$N (NULL terminated) */
    size_t          pos_argc;
    int             loop_depth;
    int             break_req;        /* break N */
    int             continue_req;     /* continue N */
    int             return_req;       /* function return */
} shell_t;

shell_t *mash_active(void);
void     mash_set_active(shell_t *s);

/* Printf through the masked stdout/stderr fds. */
int  mashf(FILE *stream, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int  mashf_fd(int fd, const char *fmt, ...)    __attribute__((format(printf, 2, 3)));

/* Write raw (unmasked) bytes directly to a real fd. Used for debug / when
 * we *know* the bytes are safe (never for program output). */
int  mash_raw_write(int real_fd, const void *buf, size_t len);

/* Emit an error to the masked stderr and set $? to status. */
void mash_err(int status, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Parse + run a snippet of source text. Returns the exit status of the last
 * command. Used by the REPL, -c, source, and scripts. */
int  mash_run_string(shell_t *s, const char *src, const char *origin);
int  mash_run_file(shell_t *s, const char *path);

#endif /* MASH_MASH_H */
