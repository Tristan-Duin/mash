/* highlight.h - shell-source syntax highlighter for the line editor.
 *
 * Renders a (possibly incomplete) command line into a strbuf, interleaving
 * SGR escape sequences so the output reads like a modern shell prompt:
 *   - keywords (if/then/...)         bold yellow
 *   - builtins (cd, echo, ...)        bold cyan
 *   - other commands                  bold green
 *   - operators  (| || && ; & ( ))    bold magenta
 *   - redirections (< > >> << <& >&)  cyan
 *   - assignment names (FOO=bar)      cyan
 *   - strings (' '  " ")              yellow
 *   - $VAR / ${VAR}                   magenta
 *   - $(...) / `...` / $((...))       bold magenta
 *   - IO numbers (2>file)             blue
 *   - comments (# ...)                bright black (gray)
 *
 * The highlighter is deliberately tolerant of unterminated quotes, dangling
 * backslashes, half-typed substitutions, etc. - it never errors out, since
 * the user is in the middle of typing. It does not need a working lexer.
 */
#ifndef MASH_HIGHLIGHT_H
#define MASH_HIGHLIGHT_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

/* Append a colorized rendering of src[0..len) to *out*. When color is
 * false the bytes are appended verbatim. Output always ends in a final
 * SGR-reset when color is on, so callers do not have to. */
void highlight_render(const char *src, size_t len, strbuf_t *out, bool color);

/* True if it's appropriate to emit ANSI color on the given output fd:
 *   - fd is a tty
 *   - $NO_COLOR is unset (https://no-color.org)
 *   - $TERM is non-empty and not "dumb"
 */
bool highlight_color_enabled(int fd);

#endif /* MASH_HIGHLIGHT_H */
