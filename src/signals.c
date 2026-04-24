/* signals.c */

#include "signals.h"

#include <signal.h>

void signals_install_interactive(void) {
    struct sigaction ign;
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    ign.sa_flags = 0;
    /* Ignore job-control signals so typing Ctrl-C / Ctrl-Z while the
     * foreground job is running doesn't kill or suspend the shell. */
    sigaction(SIGINT,  &ign, NULL);
    sigaction(SIGQUIT, &ign, NULL);
    sigaction(SIGTSTP, &ign, NULL);
    sigaction(SIGTTIN, &ign, NULL);
    sigaction(SIGTTOU, &ign, NULL);
    /* SIGPIPE gets ignored so `yes | head` doesn't kill the shell. */
    sigaction(SIGPIPE, &ign, NULL);
}

void signals_reset_for_child(void) {
    struct sigaction dfl;
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    dfl.sa_flags = 0;
    sigaction(SIGINT,  &dfl, NULL);
    sigaction(SIGQUIT, &dfl, NULL);
    sigaction(SIGTSTP, &dfl, NULL);
    sigaction(SIGTTIN, &dfl, NULL);
    sigaction(SIGTTOU, &dfl, NULL);
    sigaction(SIGPIPE, &dfl, NULL);
    sigaction(SIGCHLD, &dfl, NULL);
}
