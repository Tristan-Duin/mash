/* signals.h - interactive signal handling. */
#ifndef MASH_SIGNALS_H
#define MASH_SIGNALS_H

/* Install handlers for an interactive shell. */
void signals_install_interactive(void);

/* Reset all handlers to SIG_DFL. Called in every forked child before
 * execvp so commands inherit a clean signal disposition. */
void signals_reset_for_child(void);

#endif /* MASH_SIGNALS_H */
