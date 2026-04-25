/* lineedit.h - termios-based line editor with history.
 *
 * On a TTY we enter raw mode, render the prompt, and interpret common
 * readline-style key bindings. When stdin is not a TTY we fall back to
 * plain getline() so scripts and pipes Just Work.
 *
 * The prompt string passed in is emitted through write(2) directly; the
 * caller is responsible for ensuring any embedded literals are safe
 * (i.e. already masked) before the string is passed in.
 */
#ifndef MASH_LINEEDIT_H
#define MASH_LINEEDIT_H

#include <stdbool.h>

struct history_t;
struct shell_t;

/* Read a single logical line from the fd (usually STDIN_FILENO).
 *
 * Returns a newly allocated string (caller frees) or NULL on EOF.
 * `prompt` is written directly to the output fd using write(); make sure
 * it's pre-masked if it may contain PII.
 *
 * If `hist` is non-NULL and the input is a TTY, up/down arrows navigate
 * its entries and the resulting line is appended to it on success.
 *
 * If `sh` is non-NULL, Tab triggers tab completion (commands on the first
 * word, files/directories elsewhere).  Pass NULL to disable completion.
 */
char *lineedit_readline(int in_fd, int out_fd,
                        const char *prompt,
                        struct history_t *hist,
                        struct shell_t *sh);

#endif /* MASH_LINEEDIT_H */
