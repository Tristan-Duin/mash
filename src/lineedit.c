/* lineedit.c - minimalist line editor.
 *
 * Supports:
 *   left / right arrow
 *   Ctrl-A / Ctrl-E (start / end)
 *   Ctrl-K (kill to end)
 *   Ctrl-U (clear line)
 *   Ctrl-W (kill previous word)
 *   Ctrl-L (clear screen)
 *   Ctrl-C (abort the current line)
 *   Ctrl-D (EOF on empty line)
 *   up / down arrows (history navigation)
 *   backspace / delete
 *
 * Does not implement reverse-i-search; left as a future improvement.
 */

#include "lineedit.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "history.h"
#include "util.h"

/* --------------------------------------------------- fallback for non-TTYs */

static char *read_raw_line(int fd) {
    strbuf_t b; strbuf_init(&b);
    char c;
    ssize_t n;
    while ((n = read(fd, &c, 1)) == 1) {
        if (c == '\n') break;
        strbuf_push(&b, c);
    }
    if (n <= 0 && b.len == 0) {
        strbuf_free(&b);
        return NULL;
    }
    return strbuf_detach(&b, NULL);
}

/* -------------------------------------------------------- raw mode state */

typedef struct {
    int          fd_in, fd_out;
    const char  *prompt;
    size_t       plen;           /* prompt byte length */
    strbuf_t     line;
    size_t       cursor;         /* byte offset into line.data */
    history_t   *hist;
    size_t       hist_pos;       /* history_count when editing live */
    struct termios saved;
} ed_t;

static int enter_raw(ed_t *e) {
    struct termios t;
    if (tcgetattr(e->fd_in, &t) < 0) return -1;
    e->saved = t;
    t.c_lflag &= ~(ICANON | ECHO | IEXTEN | ISIG);
    t.c_iflag &= ~(IXON | ICRNL);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    return tcsetattr(e->fd_in, TCSANOW, &t);
}
static void leave_raw(ed_t *e) { tcsetattr(e->fd_in, TCSANOW, &e->saved); }

static void emit(ed_t *e, const char *s, size_t n) { (void)write_all(e->fd_out, s, n); }

/* Redraw current line. We keep it simple: go to beginning of the line,
 * clear to end of line, write prompt + buffer, move back to cursor. */
static void redraw(ed_t *e) {
    emit(e, "\r", 1);              /* CR */
    emit(e, "\x1b[2K", 4);          /* clear entire line */
    emit(e, e->prompt, e->plen);
    emit(e, e->line.data ? e->line.data : "", e->line.len);
    /* Move cursor back from end to cursor position. */
    if (e->cursor < e->line.len) {
        size_t back = e->line.len - e->cursor;
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "\x1b[%zuD", back);
        emit(e, buf, (size_t)n);
    }
}

static void load_history_entry(ed_t *e, size_t idx_1based) {
    strbuf_reset(&e->line);
    if (e->hist && idx_1based > 0 && idx_1based <= history_count(e->hist)) {
        const char *s = history_at(e->hist, idx_1based - 1);
        if (s) strbuf_appendz(&e->line, s);
    }
    e->cursor = e->line.len;
    redraw(e);
}

/* --------------------------------------------------- key loop */

char *lineedit_readline(int in_fd, int out_fd,
                        const char *prompt,
                        history_t *hist) {
    if (!isatty(in_fd)) {
        if (prompt) (void)write_all(out_fd, prompt, strlen(prompt));
        return read_raw_line(in_fd);
    }

    ed_t e;
    memset(&e, 0, sizeof(e));
    e.fd_in  = in_fd;
    e.fd_out = out_fd;
    e.prompt = prompt ? prompt : "";
    e.plen   = strlen(e.prompt);
    e.hist   = hist;
    e.hist_pos = hist ? history_count(hist) : 0;
    strbuf_init(&e.line);

    if (enter_raw(&e) < 0) {
        if (prompt) (void)write_all(out_fd, prompt, strlen(prompt));
        return read_raw_line(in_fd);
    }
    emit(&e, e.prompt, e.plen);

    char c;
    bool done = false, eof = false, aborted = false;
    while (!done) {
        ssize_t n = read(in_fd, &c, 1);
        if (n == 0) { eof = true; break; }
        if (n < 0) { if (errno == EINTR) continue; eof = true; break; }

        switch (c) {
        case '\r': case '\n':
            emit(&e, "\r\n", 2);
            done = true;
            break;
        case 0x04: /* Ctrl-D */
            if (e.line.len == 0) { eof = true; done = true; }
            else { /* delete under cursor */
                if (e.cursor < e.line.len) {
                    memmove(e.line.data + e.cursor, e.line.data + e.cursor + 1,
                            e.line.len - e.cursor);
                    e.line.len--;
                    e.line.data[e.line.len] = '\0';
                    redraw(&e);
                }
            }
            break;
        case 0x03: /* Ctrl-C */
            emit(&e, "^C\r\n", 4);
            strbuf_reset(&e.line);
            aborted = true;
            done = true;
            break;
        case 0x01: /* Ctrl-A */
            e.cursor = 0; redraw(&e); break;
        case 0x05: /* Ctrl-E */
            e.cursor = e.line.len; redraw(&e); break;
        case 0x0B: /* Ctrl-K */
            e.line.len = e.cursor;
            if (e.line.data) e.line.data[e.line.len] = '\0';
            redraw(&e); break;
        case 0x15: /* Ctrl-U */
            strbuf_reset(&e.line); e.cursor = 0; redraw(&e); break;
        case 0x17: /* Ctrl-W */ {
            size_t i = e.cursor;
            while (i > 0 && isspace((unsigned char)e.line.data[i-1])) i--;
            while (i > 0 && !isspace((unsigned char)e.line.data[i-1])) i--;
            memmove(e.line.data + i, e.line.data + e.cursor, e.line.len - e.cursor);
            e.line.len -= (e.cursor - i);
            e.cursor = i;
            e.line.data[e.line.len] = '\0';
            redraw(&e); break;
        }
        case 0x0C: /* Ctrl-L */
            emit(&e, "\x1b[H\x1b[2J", 7);
            redraw(&e); break;
        case 0x7f: case 0x08: /* backspace */
            if (e.cursor > 0) {
                memmove(e.line.data + e.cursor - 1, e.line.data + e.cursor,
                        e.line.len - e.cursor);
                e.cursor--;
                e.line.len--;
                e.line.data[e.line.len] = '\0';
                redraw(&e);
            }
            break;
        case 0x1b: { /* escape sequence */
            char s1, s2;
            if (read(in_fd, &s1, 1) != 1) break;
            if (s1 != '[' && s1 != 'O') break;
            if (read(in_fd, &s2, 1) != 1) break;
            if (s2 == 'A') {    /* up */
                if (e.hist && e.hist_pos > 0) { e.hist_pos--; load_history_entry(&e, e.hist_pos + 1); }
            } else if (s2 == 'B') { /* down */
                if (e.hist && e.hist_pos < history_count(e.hist)) {
                    e.hist_pos++;
                    if (e.hist_pos == history_count(e.hist)) {
                        strbuf_reset(&e.line);
                        e.cursor = 0;
                        redraw(&e);
                    } else load_history_entry(&e, e.hist_pos + 1);
                }
            } else if (s2 == 'C') { /* right */
                if (e.cursor < e.line.len) { e.cursor++; redraw(&e); }
            } else if (s2 == 'D') { /* left */
                if (e.cursor > 0) { e.cursor--; redraw(&e); }
            } else if (s2 == 'H') { e.cursor = 0; redraw(&e); }
            else if (s2 == 'F')   { e.cursor = e.line.len; redraw(&e); }
            else if (s2 == '3') { /* delete: <esc>[3~ */
                char tilde;
                if (read(in_fd, &tilde, 1) != 1) break;
                if (e.cursor < e.line.len) {
                    memmove(e.line.data + e.cursor, e.line.data + e.cursor + 1,
                            e.line.len - e.cursor);
                    e.line.len--;
                    e.line.data[e.line.len] = '\0';
                    redraw(&e);
                }
            }
            break;
        }
        default:
            if (c < 32 || c == 0x7f) break; /* ignore other control chars */
            /* insert at cursor */
            strbuf_reserve(&e.line, 1);
            memmove(e.line.data + e.cursor + 1, e.line.data + e.cursor,
                    e.line.len - e.cursor);
            e.line.data[e.cursor] = c;
            e.line.len++;
            e.cursor++;
            e.line.data[e.line.len] = '\0';
            redraw(&e);
            break;
        }
    }

    leave_raw(&e);
    if (eof && e.line.len == 0) {
        strbuf_free(&e.line);
        return NULL;
    }
    if (aborted) {
        strbuf_free(&e.line);
        char *empty = xmalloc(1);
        empty[0] = '\0';
        return empty;
    }
    return strbuf_detach(&e.line, NULL);
}
