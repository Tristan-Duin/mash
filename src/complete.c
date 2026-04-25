/* complete.c - tab completion engine.
 *
 * Two modes:
 *   command  - first word on a line (or after a shell metacharacter):
 *              shell builtins + executable files found on $PATH.
 *   path     - any other position, or whenever the prefix contains '/',
 *              starts with './' or starts with '~':
 *              files and directories (directories get a trailing '/').
 */

#include "complete.h"

#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "builtins.h"
#include "env.h"
#include "mash.h"
#include "util.h"

/* ------------------------------------------------------------------ helpers */

typedef struct {
    char  **v;
    size_t  n, cap;
} sarr_t;

static void sarr_init(sarr_t *a) { a->v = NULL; a->n = a->cap = 0; }

static void sarr_push(sarr_t *a, char *s) {
    if (a->n + 1 >= a->cap) {
        a->cap = a->cap ? a->cap * 2 : 16;
        a->v   = xrealloc(a->v, (a->cap + 1) * sizeof(*a->v));
    }
    a->v[a->n++] = s;
    a->v[a->n]   = NULL;
}

static int sarr_cmp(const void *a, const void *b) {
    return strcmp(*(const char * const *)a, *(const char * const *)b);
}

static void sarr_sort_dedup(sarr_t *a) {
    if (a->n <= 1) return;
    qsort(a->v, a->n, sizeof(*a->v), sarr_cmp);
    size_t i = 1;
    while (i < a->n) {
        if (strcmp(a->v[i - 1], a->v[i]) == 0) {
            free(a->v[i]);
            memmove(a->v + i, a->v + i + 1, (a->n - i) * sizeof(*a->v));
            a->n--;
        } else {
            i++;
        }
    }
}

static char **sarr_detach(sarr_t *a) {
    if (!a->v) {
        char **empty = xmalloc(sizeof(*empty));
        empty[0] = NULL;
        return empty;
    }
    return a->v;
}

/* ------------------------------------------------------------------ parsing */

/* Byte offset of the start of the word that ends at `cur` in `line`.
 * Word boundaries: whitespace and shell metacharacters. */
static size_t find_word_start(const char *line, size_t cur) {
    size_t i = cur;
    while (i > 0) {
        char c = line[i - 1];
        if (isspace((unsigned char)c) ||
            c == '|' || c == '&' || c == ';' ||
            c == '(' || c == ')' ||
            c == '<' || c == '>') break;
        i--;
    }
    return i;
}

/* Return true when the word at offset `ws` is in command position:
 * nothing precedes it except whitespace and/or shell metacharacters that
 * introduce a new command. */
static bool is_command_pos(const char *line, size_t ws) {
    const char *p = line + ws;
    while (p > line && isspace((unsigned char)*(p - 1))) p--;
    if (p == line) return true;
    char c = *(p - 1);
    return c == '|' || c == '&' || c == ';' || c == '(' || c == '{';
}

/* ------------------------------------------------------------------ tilde */

static char *expand_tilde(shell_t *sh, const char *s) {
    if (s[0] != '~') return xstrdup(s);
    const char *rest = s + 1;
    const char *home = env_get(sh->env, "HOME");
    if (!home || !*home) {
        struct passwd *pw = getpwuid(getuid());
        home = (pw && pw->pw_dir) ? pw->pw_dir : "";
    }
    strbuf_t b; strbuf_init(&b);
    strbuf_appendz(&b, home);
    strbuf_appendz(&b, rest);
    return strbuf_detach(&b, NULL);
}

/* ----------------------------------------------------------- path completion */

static void complete_path(shell_t *sh, const char *prefix, sarr_t *out) {
    /* Split prefix into a directory part and a filename prefix. */
    const char *slash = strrchr(prefix, '/');
    char *dir_part;  /* directory to opendir() (tilde-expanded if needed) */
    char *orig_dir;  /* typed directory prefix (prepended when building result) */
    const char *file_pfx;

    if (slash) {
        size_t dlen = (size_t)(slash - prefix) + 1; /* include the slash */
        orig_dir  = xstrndup(prefix, dlen);
        dir_part  = expand_tilde(sh, orig_dir);
        file_pfx  = slash + 1;
    } else {
        orig_dir = xstrdup("");
        dir_part = xstrdup(".");
        file_pfx = prefix;
    }

    size_t pfx_len = strlen(file_pfx);

    DIR *dp = opendir(dir_part);
    if (!dp) { free(dir_part); free(orig_dir); return; }

    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        const char *name = ent->d_name;
        /* Hide dot-files unless the user started typing a dot. */
        if (name[0] == '.' && file_pfx[0] != '.') continue;
        if (pfx_len && strncmp(name, file_pfx, pfx_len) != 0) continue;

        /* Stat to determine if it is a directory. */
        strbuf_t full; strbuf_init(&full);
        strbuf_appendz(&full, dir_part);
        if (full.len && full.data[full.len - 1] != '/') strbuf_push(&full, '/');
        strbuf_appendz(&full, name);
        struct stat st;
        bool is_dir = (stat(full.data, &st) == 0 && S_ISDIR(st.st_mode));
        strbuf_free(&full);

        /* Build the full replacement string. */
        strbuf_t comp; strbuf_init(&comp);
        strbuf_appendz(&comp, orig_dir);
        strbuf_appendz(&comp, name);
        if (is_dir) strbuf_push(&comp, '/');

        sarr_push(out, strbuf_detach(&comp, NULL));
    }
    closedir(dp);
    free(dir_part);
    free(orig_dir);
}

/* -------------------------------------------------------- command completion */

static void complete_commands(shell_t *sh, const char *prefix, sarr_t *out) {
    size_t pfx_len = strlen(prefix);

    /* Shell built-ins. */
    size_t nb;
    const builtin_t *builtins = builtin_all(&nb);
    for (size_t i = 0; i < nb; i++) {
        if (pfx_len == 0 || strncmp(builtins[i].name, prefix, pfx_len) == 0)
            sarr_push(out, xstrdup(builtins[i].name));
    }

    /* Executable files found on $PATH. */
    const char *path_env = env_get(sh->env, "PATH");
    if (!path_env) return;

    char *path_copy = xstrdup(path_env);
    char *save      = NULL;
    for (char *dir = strtok_r(path_copy, ":", &save);
         dir; dir = strtok_r(NULL, ":", &save)) {
        DIR *dp = opendir(dir);
        if (!dp) continue;
        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            const char *name = ent->d_name;
            if (pfx_len && strncmp(name, prefix, pfx_len) != 0) continue;
            strbuf_t full; strbuf_init(&full);
            strbuf_appendz(&full, dir);
            strbuf_push(&full, '/');
            strbuf_appendz(&full, name);
            bool ok = (access(full.data, X_OK) == 0);
            strbuf_free(&full);
            if (ok) sarr_push(out, xstrdup(name));
        }
        closedir(dp);
    }
    free(path_copy);
}

/* ------------------------------------------------------------------- public */

char **complete_generate(shell_t *sh,
                         const char *line, size_t cursor,
                         size_t *prefix_len_out) {
    if (!line) line = "";

    size_t ws      = find_word_start(line, cursor);
    size_t pfx_len = cursor - ws;
    if (prefix_len_out) *prefix_len_out = pfx_len;

    char *prefix = xstrndup(line + ws, pfx_len);

    sarr_t out; sarr_init(&out);

    bool cmd_pos  = is_command_pos(line, ws);
    /* Treat as a path completion when the prefix looks like a path. */
    bool has_path = (strchr(prefix, '/') != NULL ||
                     prefix[0] == '~' ||
                     (prefix[0] == '.' && (prefix[1] == '/' || prefix[1] == '\0')));

    if (cmd_pos && !has_path) {
        complete_commands(sh, prefix, &out);
    } else {
        complete_path(sh, prefix, &out);
    }

    free(prefix);
    sarr_sort_dedup(&out);
    return sarr_detach(&out);
}

void complete_free_list(char **list) {
    if (!list) return;
    for (size_t i = 0; list[i]; i++) free(list[i]);
    free(list);
}
