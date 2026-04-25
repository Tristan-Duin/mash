/* mask_fd.c - background pump thread that applies the mask to every byte
 * passing through its internal pipe before writing them to the real fd.
 *
 * The pump waits in poll() on two read ends:
 *
 *   - internal_read : the masked-data pipe. Whenever it's readable the
 *     pump drains it non-blocking, runs the bytes through mask_stream,
 *     and writes the masked output to real_fd.
 *   - wakeup_r      : a self-pipe used by mask_fd_drain() to signal that
 *     the caller wants to wait until everything written so far has
 *     reached real_fd. After processing all currently available data,
 *     the pump flushes any partial-line tail held inside mask_stream and
 *     advances drain_ack so a waiting drainer can be released.
 */

#include "mask_fd.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

/* Set FD_CLOEXEC on fd so forked children don't inherit it. */
static void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Drain a non-blocking fd by reading and discarding all available bytes. */
static void drain_signal_fd(int fd) {
    char d[64];
    while (read(fd, d, sizeof(d)) > 0) { /* discard */ }
}

/* Read everything currently available from internal_read and feed it
 * through mask_stream. Returns true on EOF (writer side fully closed). */
static bool pump_read_available(mask_fd_t *m, mask_stream_t *st,
                                char *buf, size_t bufsz) {
    for (;;) {
        ssize_t n = read(m->internal_read, buf, bufsz);
        if (n > 0) {
            strbuf_t out;
            strbuf_init(&out);
            mask_stream_push(st, buf, (size_t)n, &out);
            if (out.len) (void)write_all(m->real_fd, out.data, out.len);
            strbuf_free(&out);
            continue;
        }
        if (n == 0) return true;                    /* EOF */
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        return true;                                /* unrecoverable */
    }
}

/* Flush bytes that are safe to emit immediately. Used both during the
 * idle window (poll timeout) and right after consuming new input, so a
 * line-less burst from a TUI like vim doesn't sit in `pending` waiting
 * for a newline. The mask_stream_idle_flush helper itself refuses to
 * split a multi-line secret block so the masking guarantee holds. */
static void pump_emit_idle(mask_fd_t *m, mask_stream_t *st) {
    strbuf_t tail; strbuf_init(&tail);
    mask_stream_idle_flush(st, &tail);
    if (tail.len) (void)write_all(m->real_fd, tail.data, tail.len);
    strbuf_free(&tail);
}

static void *pump_main(void *arg) {
    mask_fd_t    *m = arg;
    mask_stream_t st;
    mask_stream_init(&st, m->engine);

    /* Idle window: when there are buffered bytes, wake at this cadence to
     * emit anything safe. 25 ms is fast enough that vim/less feel native
     * but slow enough that the wake cost is negligible (~40 Hz). */
    static const int IDLE_FLUSH_MS = 25;

    char buf[8192];
    bool eof = false;
    while (!eof) {
        struct pollfd pfd[2];
        pfd[0].fd = m->internal_read;  pfd[0].events = POLLIN;  pfd[0].revents = 0;
        pfd[1].fd = m->wakeup_r;       pfd[1].events = POLLIN;  pfd[1].revents = 0;

        int timeout = (st.pending.len == 0) ? -1 : IDLE_FLUSH_MS;
        int pr = poll(pfd, 2, timeout);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            /* Idle: push out anything that's safe to push. */
            pump_emit_idle(m, &st);
            continue;
        }

        /* Wake-up byte (sent by mask_fd_drain); content is irrelevant. */
        if (pfd[1].revents & POLLIN) drain_signal_fd(m->wakeup_r);

        /* Process any currently buffered data. We do this even when only
         * the wakeup fired - kernel ordering guarantees that bytes a
         * caller wrote before signalling are already visible here. */
        if (pump_read_available(m, &st, buf, sizeof(buf))) eof = true;
        else if (pfd[0].revents & (POLLHUP | POLLERR)) eof = true;

        /* Service drain requests after we've consumed pending input. */
        pthread_mutex_lock(&m->drain_lock);
        if (m->drain_req > m->drain_ack) {
            strbuf_t tail; strbuf_init(&tail);
            mask_stream_finish(&st, &tail);
            if (tail.len) (void)write_all(m->real_fd, tail.data, tail.len);
            strbuf_free(&tail);
            m->drain_ack = m->drain_req;
            pthread_cond_broadcast(&m->drain_cv);
        }
        pthread_mutex_unlock(&m->drain_lock);
    }

    /* Final flush at shutdown. */
    strbuf_t tail;
    strbuf_init(&tail);
    mask_stream_finish(&st, &tail);
    if (tail.len) (void)write_all(m->real_fd, tail.data, tail.len);
    strbuf_free(&tail);

    /* Wake any drainer that arrived during/after EOF. */
    pthread_mutex_lock(&m->drain_lock);
    m->drain_ack = m->drain_req;
    pthread_cond_broadcast(&m->drain_cv);
    pthread_mutex_unlock(&m->drain_lock);

    mask_stream_free(&st);
    close(m->internal_read);
    m->internal_read = -1;
    if (m->wakeup_r >= 0) { close(m->wakeup_r); m->wakeup_r = -1; }
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
    out->wakeup_r = -1;
    out->wakeup_w = -1;

    int p[2];
    if (pipe(p) < 0) return -1;

    int wp[2];
    if (pipe(wp) < 0) {
        int saved = errno;
        close(p[0]); close(p[1]);
        errno = saved;
        return -1;
    }

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
     *   - wp[0]/wp[1] (drain self-pipe) : private to this wrapper.
     */
    set_cloexec(p[0]);
    set_cloexec(p[1]);
    set_cloexec(real_fd);
    set_cloexec(wp[0]);
    set_cloexec(wp[1]);

    /* Read ends are non-blocking so the pump can drain in a tight loop
     * down to EAGAIN before checking for drain requests. */
    set_nonblock(p[0]);
    set_nonblock(wp[0]);

    pthread_mutex_init(&out->drain_lock, NULL);
    pthread_cond_init(&out->drain_cv, NULL);
    out->sync_inited = true;

    out->engine         = e;
    out->real_fd        = real_fd;
    out->own_real_fd    = own_real_fd;
    out->write_fd       = p[1];
    out->internal_read  = p[0];
    out->wakeup_r       = wp[0];
    out->wakeup_w       = wp[1];
    out->drain_req      = 0;
    out->drain_ack      = 0;

    if (pthread_create(&out->thread, NULL, pump_main, out) != 0) {
        int saved = errno;
        close(p[0]); close(p[1]);
        close(wp[0]); close(wp[1]);
        pthread_mutex_destroy(&out->drain_lock);
        pthread_cond_destroy(&out->drain_cv);
        out->sync_inited = false;
        out->write_fd = out->internal_read = -1;
        out->wakeup_r = out->wakeup_w = -1;
        errno = saved;
        return -1;
    }
    out->thread_started = true;
    return 0;
}

void mask_fd_drain(mask_fd_t *m) {
    if (!m || !m->thread_started || !m->sync_inited) return;
    if (m->wakeup_w < 0) return;

    pthread_mutex_lock(&m->drain_lock);
    uint64_t want = ++m->drain_req;
    pthread_mutex_unlock(&m->drain_lock);

    /* Wake the pump out of poll(). One byte is enough; the pump drains
     * the wakeup pipe completely on each iteration. */
    char x = '.';
    while (write(m->wakeup_w, &x, 1) < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break; /* signal coalesced */
        break; /* pipe closed - pump has exited; loop below will see ack */
    }

    pthread_mutex_lock(&m->drain_lock);
    while (m->drain_ack < want) pthread_cond_wait(&m->drain_cv, &m->drain_lock);
    pthread_mutex_unlock(&m->drain_lock);
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
    /* Pump closes internal_read, wakeup_r, and (if owned) real_fd. The
     * caller-side wakeup_w and the sync primitives are ours to release. */
    if (m->wakeup_w >= 0) {
        close(m->wakeup_w);
        m->wakeup_w = -1;
    }
    if (m->sync_inited) {
        pthread_mutex_destroy(&m->drain_lock);
        pthread_cond_destroy(&m->drain_cv);
        m->sync_inited = false;
    }
}
