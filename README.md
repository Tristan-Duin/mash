# mash &mdash; Masked Shell

A modern POSIX-style shell written in C whose distinguishing feature is a
**masking layer**: every byte written through a shell-owned file descriptor
is scanned and redacted on the way out, so sensitive values never reach a
terminal, a file, or a log. Commands run normally &mdash; pipelines,
redirections, job control, variables, functions, history. The mask just
rewrites matches to `«CATEGORY»` placeholders.

```
$ mash -c 'echo user=$USER host=$(hostname) email=ops@example.com'
user=«USER» host=«HOST» email=«EMAIL»
```

## Build

```sh
make             # build ./mash
make check       # run mask engine self-tests
make install     # install to /usr/local/bin
make clean
```

POSIX targets only (Linux, macOS, WSL, Cygwin, MSYS2). Requires a C11
compiler, pthreads, POSIX regex, termios, and `getifaddrs`.

## Run

```sh
./mash                   # interactive REPL
./mash -c 'echo hi'      # one-shot
./mash script.sh a b c   # run a script
```

Flags: `-c CMD`, `-i`, `-l`, `-s`, `--norc`, `-h`.

## How masking works

Three rule sources are merged at startup:

1. **Universal patterns** &mdash; emails, IPv4/IPv6, MACs, UUIDs, JWTs,
   AWS / GitHub / Google / Slack / Bearer tokens, IBANs, credit cards,
   SSNs, phone numbers, hex secrets (32/40/64 chars), PEM private-key
   blocks.
2. **Runtime-derived literals** &mdash; `$USER`, `$LOGNAME`, `$SUDO_USER`,
   the passwd GECOS name, `$HOME`, hostname, UID/GID, every interface
   IPv4/IPv6/MAC, and `$SSH_CLIENT`, `$SSH_TTY`, `$SSH_CONNECTION`,
   `$MAIL`, `$MAILPATH`.
3. **User rules** &mdash; added via the `mask` built-in or loaded from
   `~/.mashrc`.

Every writable descriptor the shell hands out &mdash; stdout, stderr,
files opened by `>` `>>` `&>` `2>`, and every pipe stage &mdash; is wrapped
with a pump thread in the shell process that reads, masks, and writes.
Command substitution `$(…)` masks captured output too. History is
persisted already-masked.

Use `mask show` to list rules, `mask add CAT PATTERN`, `mask literal CAT
STRING`, `mask disable N`, `mask enable N`, `mask remove N` to manage them
at runtime.

## Shell features

- Pipelines `|`, logical `&&` `||`, lists `;` `&`, background jobs.
- Redirections `< > >> 2> 2>> &> <> <& >& << <<-`.
- Quoting: single, double, backslash.
- Parameter expansion including `${VAR:-…}` `${VAR:=…}` `${VAR:?…}`
  `${VAR:+…}` `${#VAR}` `${VAR#pat}` `${VAR##pat}` `${VAR%pat}`
  `${VAR%%pat}` `${VAR/pat/rep}` `${VAR//pat/rep}`.
- Specials `$? $$ $# $@ $* $0–$9 $-`.
- Command substitution `$(…)` and backticks.
- Arithmetic `$((…))` with the C operator set, including ternary.
- Tilde and glob expansion (`*`, `?`, `[…]`, `{a,b,c}`).
- Control flow: `if/elif/else/fi`, `while`, `until`, `for`, `case`,
  subshells `(…)`, groups `{…}`, functions, `!` negation.
- Job control: `&`, `jobs`, `fg`, `bg`, `wait`.
- Line editor: cursor motion, history, `Ctrl-A/E/K/U/W/L/C/D`.
- Startup files: `/etc/mashrc`, `~/.mashrc`.

Built-ins:

```
:  cd  pwd  echo  printf  export  unset  set  alias  unalias
source  .  exit  return  shift  break  continue  true  false
test  [  type  help  history  jobs  fg  bg  kill  wait  umask
read  mask
```

## Layout

```
include/        public headers
src/            one .c per module
  mask.c        rule engine
  mask_fd.c     pump thread / fd wrapper
  lexer.c       tokenizer
  parser.c      recursive-descent parser
  expand.c      tilde, param, cmdsub, arith, glob
  executor.c    fork / exec / pipes / redirections
  builtins.c    built-in commands
  env.c         variables, aliases, functions
  jobs.c        job tracking
  signals.c     signal handling
  history.c     masked history
  lineedit.c    termios line editor
  main.c        entry point + REPL
tests/
  test_mask.c   mask engine self-tests (make check)
```

## Limitations

- No process substitution `<(…)` / `>(…)`.
- No `[[ … ]]` extended tests.
- No associative arrays.
- No multibyte-aware line editor (UTF-8 bytes still display correctly).
- No native Windows build &mdash; use WSL, Cygwin, or MSYS2.

## License

Add a license of your choice before distributing.
