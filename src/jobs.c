/* jobs.c - minimalist job tracking. */

#include "jobs.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "util.h"

job_list_t *jobs_new(void) {
    job_list_t *j = xcalloc(1, sizeof(*j));
    j->next_id = 1;
    return j;
}

void jobs_free(job_list_t *j) {
    if (!j) return;
    job_t *c = j->head;
    while (c) { job_t *n = c->next; free(c->cmd); free(c); c = n; }
    free(j);
}

int jobs_add(job_list_t *j, pid_t pgid, pid_t last_pid, const char *cmd) {
    job_t *x = xcalloc(1, sizeof(*x));
    x->id = j->next_id++;
    x->pgid = pgid;
    x->last_pid = last_pid;
    x->state = JOB_RUNNING;
    x->cmd = xstrdup(cmd ? cmd : "");
    x->next = j->head;
    j->head = x;
    return x->id;
}

void jobs_reap(job_list_t *j) {
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        for (job_t *c = j->head; c; c = c->next) {
            if (c->pgid == p || c->last_pid == p) {
                if (WIFEXITED(st) || WIFSIGNALED(st)) {
                    c->state = JOB_DONE;
                    c->last_status = WIFEXITED(st)
                        ? WEXITSTATUS(st)
                        : 128 + WTERMSIG(st);
                } else if (WIFSTOPPED(st)) {
                    c->state = JOB_STOPPED;
                } else if (WIFCONTINUED(st)) {
                    c->state = JOB_RUNNING;
                }
                break;
            }
        }
    }
    if (p < 0 && errno != ECHILD) {
        /* ignore */
    }
}

void jobs_cleanup(job_list_t *j) {
    jobs_reap(j);
    job_t **cur = &j->head;
    while (*cur) {
        if ((*cur)->state == JOB_DONE) {
            job_t *dead = *cur;
            *cur = dead->next;
            free(dead->cmd);
            free(dead);
            continue;
        }
        cur = &(*cur)->next;
    }
}

job_t *jobs_find(job_list_t *j, const char *spec) {
    if (!j) return NULL;
    if (!spec || !*spec || str_eq(spec, "%") || str_eq(spec, "%%") || str_eq(spec, "%+"))
        return j->head;
    const char *p = (spec[0] == '%') ? spec + 1 : spec;
    int id = atoi(p);
    for (job_t *c = j->head; c; c = c->next) if (c->id == id) return c;
    return NULL;
}
