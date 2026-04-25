/* complete.h - tab completion for the line editor.
 *
 * Given the current line buffer and cursor position, generates a sorted,
 * deduplicated, NULL-terminated list of candidate completions.
 *
 * Completion context:
 *   - First word on the line (or after |, &, ;, (, {): command completion
 *     (builtins + executables found in $PATH).
 *   - Any other position, or when the prefix contains '/', starts with '.'
 *     followed by '/', or starts with '~': pathname completion.
 *
 * Each returned string is the *full replacement* for the word under the
 * cursor (not just the suffix).  Directories end with '/'; plain files and
 * commands have no trailing character — the line editor appends a space
 * when inserting a unique match.
 */
#ifndef MASH_COMPLETE_H
#define MASH_COMPLETE_H

#include <stddef.h>

struct shell_t;

/* Return a sorted, NULL-terminated array of completions.
 *
 * *prefix_len_out is set to the byte length of the word currently under the
 * cursor — the region the caller should replace with the chosen completion. */
char **complete_generate(struct shell_t *sh,
                         const char *line, size_t cursor,
                         size_t *prefix_len_out);

/* Free a list returned by complete_generate(). */
void complete_free_list(char **list);

#endif /* MASH_COMPLETE_H */
