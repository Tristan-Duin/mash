/* mask_fd.h - pump-based masked write fds.
 *
 * mask_fd_wrap_write(engine, real_fd) creates an internal pipe and spawns a
 * background thread ("pump") that reads raw bytes from the pipe, runs them
 * through the engine's streaming mask, and writes the masked output to
 * real_fd. The write end of the internal pipe is returned to the caller;
 * anything written there (by the shell itself or by a forked child that
 * inherits a dup of it) will be masked before reaching real_fd.
 *
 * Lifetime: the pump runs until every copy of the write end is closed
 * (read() on the pipe then returns 0). At that point the pump drains any
 * buffered tail through mask_stream_finish, closes real_fd (if owned), and
 * exits. mask_fd_close() is a convenience that closes the caller-visible
 * write end and joins the pump thread.
 */
#ifndef MASH_MASK_FD_H
#define MASH_MASK_FD_H

#include <pthread.h>
#include <stdbool.h>

#include "mask.h"

typedef struct {
    int             write_fd;     /* returned to the caller */
    int             real_fd;      /* downstream target */
    bool            own_real_fd;  /* pump closes real_fd on exit */
    mask_engine_t  *engine;
    pthread_t       thread;
    bool            thread_started;
    int             internal_read; /* pump's read end (pipe) */
} mask_fd_t;

/* Wrap a writable fd. real_fd is *not* closed on success unless own_real_fd
 * is true - then the pump owns it and will close it on exit. On failure
 * returns -1 and leaves real_fd alone. */
int  mask_fd_wrap_write(mask_engine_t *e, int real_fd, bool own_real_fd,
                        mask_fd_t *out);

/* Close the caller's write_fd and join the pump thread.
 * Safe to call multiple times. */
void mask_fd_close(mask_fd_t *m);

#endif /* MASH_MASK_FD_H */
