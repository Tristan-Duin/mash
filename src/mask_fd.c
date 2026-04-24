/* mask_fd.c - background pump thread that applies the mask to every byte
 * passing through its internal pipe before writing them to the real fd. */

#include "mask_fd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

/* Set FD_CLOEXEC on fd so forked children don't inherit it. */
static void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void *pump_main(void *arg) {
    mask_fd_t    *m = arg;
    mask_stream_t st;
    mask_stream_init(&st, m->engine);

    char buf[8192];
    for (;;) {
        ssize_t n = read(m->internal_read, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break; /* all writers closed */

        strbuf_t out;
        strbuf_init(&out);
        mask_stream_push(&st, buf, (size_t)n, &out);
        if (out.len) (void)write_all(m->real_fd, out.data, out.len);
        strbuf_free(&out);
    }

    /* Drain any buffered tail. */
    strbuf_t tail;
    strbuf_init(&tail);
    mask_stream_finish(&st, &tail);
    if (tail.len) (void)write_all(m->real_fd, tail.data, tail.len);
    strbuf_free(&tail);

    mask_stream_free(&st);
    close(m->internal_read);
    m->internal_read = -1;
    if (m->own_real_fd && m->real_fd >= 0) {
        close(m->real_fd);
        m->real_fd = -1;
    }
    return NULL;
}

int mask_fd_wrap_write(mask_engine_t *e, int real_fd, bool own_real_fd,
                       mask_fd_t *out) {
    if (!e || !out || real_fd < 0) { errno = EINVAL; return -1; }
    memset(out, 0, sizeof(*out));

    int p[2];
    if (pipe(p) < 0) return -1;

    /* Every fd associated with a masked write path must close on exec in
     * any child we fork. Otherwise an exec'd program would keep the pump's
     * internal pipe and/or the downstream destination open, which prevents
     * the pump (or a downstream reader) from ever seeing EOF.
     *
     *   - p[0] (pump's read end)   : only the pump thread uses it.
     *   - p[1] (caller's write_fd) : the caller dup2's it onto a real fd;
     *     dup2 clears CLOEXEC on the destination, so the dup stays open
     *     in the child while this source closes at exec.
     *   - real_fd (downstream)     : the pump owns writing to it; no
     *     exec'd child should ever inherit a live reference. (Setting
     *     CLOEXEC here is harmless when own_real_fd is false: the caller
     *     keeps the fd within the shell process, and the shell itself
     *     never execs.)
     */
    set_cloexec(p[0]);
    set_cloexec(p[1]);
    set_cloexec(real_fd);

    out->engine         = e;
    out->real_fd        = real_fd;
    out->own_real_fd    = own_real_fd;
    out->write_fd       = p[1];
    out->internal_read  = p[0];

    if (pthread_create(&out->thread, NULL, pump_main, out) != 0) {
        close(p[0]);
        close(p[1]);
        out->write_fd = out->internal_read = -1;
        return -1;
    }
    out->thread_started = true;
    return 0;
}

void mask_fd_close(mask_fd_t *m) {
    if (!m) return;
    if (m->write_fd >= 0) {
        close(m->write_fd);
        m->write_fd = -1;
    }
    if (m->thread_started) {
        pthread_join(m->thread, NULL);
        m->thread_started = false;
    }
    /* Pump owns internal_read and optionally real_fd. */
}
