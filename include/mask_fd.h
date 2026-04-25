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
#include <stdint.h>

#include "mask.h"

typedef struct mask_fd_t {
    int             write_fd;     /* returned to the caller */
    int             real_fd;      /* downstream target */
    bool            own_real_fd;  /* pump closes real_fd on exit */
    mask_engine_t  *engine;
    pthread_t       thread;
    bool            thread_started;
    int             internal_read; /* pump's read end (pipe) */

    /* Drain coordination. The pump runs asynchronously, so callers that
     * want to write something to real_fd via a different path (e.g. an
     * interactive prompt written directly to real_stdout) need a way to
     * wait until the pump has finished forwarding everything written so
     * far. mask_fd_drain() bumps drain_req and pokes wakeup_w; the pump
     * processes any pending bytes, flushes the mask_stream tail, and
     * advances drain_ack under drain_lock. */
    int             wakeup_r;
    int             wakeup_w;
    pthread_mutex_t drain_lock;
    pthread_cond_t  drain_cv;
    uint64_t        drain_req;
    uint64_t        drain_ack;
    bool            sync_inited;  /* drain_lock/cv have been initialised */
} mask_fd_t;

/* Wrap a writable fd. real_fd is *not* closed on success unless own_real_fd
 * is true - then the pump owns it and will close it on exit. On failure
 * returns -1 and leaves real_fd alone. */
int  mask_fd_wrap_write(mask_engine_t *e, int real_fd, bool own_real_fd,
                        mask_fd_t *out);

/* Close the caller's write_fd and join the pump thread.
 * Safe to call multiple times. */
void mask_fd_close(mask_fd_t *m);

/* Block until every byte already written to write_fd has been masked and
 * forwarded to real_fd, including any partial-line tail held inside the
 * pump's mask_stream buffer. No-op if the pump isn't running. */
void mask_fd_drain(mask_fd_t *m);

#endif /* MASH_MASK_FD_H */
