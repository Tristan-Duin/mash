/* jobs.h - job control.
 *
 * Tracks backgrounded and suspended pipelines so `jobs`, `fg`, `bg`, and
 * `wait` can report and manipulate them. For simplicity a job holds just
 * the process group id, the command text, the last observed status, and
 * a state flag; we do not track per-process status within the pipeline.
 */
#ifndef MASH_JOBS_H
#define MASH_JOBS_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    JOB_RUNNING,
    JOB_STOPPED,
    JOB_DONE
} job_state_t;

typedef struct job_t {
    int           id;            /* 1-based */
    pid_t         pgid;
    pid_t         last_pid;      /* pid used for waitpid($!) */
    job_state_t   state;
    int           last_status;
    char         *cmd;
    struct job_t *next;
} job_t;

typedef struct job_list_t {
    job_t *head;
    int    next_id;
} job_list_t;

job_list_t *jobs_new(void);
void        jobs_free(job_list_t *j);

/* Register a new job; returns the assigned id. */
int         jobs_add(job_list_t *j, pid_t pgid, pid_t last_pid, const char *cmd);

/* Poll for exited children. For any job whose pgid has a pending
 * SIGCHLD-reported status, update state accordingly. */
void        jobs_reap(job_list_t *j);

/* Remove finished jobs; called before printing a prompt. */
void        jobs_cleanup(job_list_t *j);

/* Find by id; %N or %% or %+ forms accepted (% and empty string mean
 * current/last). */
job_t      *jobs_find(job_list_t *j, const char *spec);

#endif /* MASH_JOBS_H */
