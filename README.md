# mash - Masked Shell

A modern POSIX-style shell written in C whose distinguishing feature is a
**masking layer**: every byte written through a shell-owned file descriptor
is scanned and redacted on the way out, so sensitive values never reach a
terminal, a file, or a log. Commands run normally pipelines,
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

Flags: `-c CMD`, `-i`, `-l`, `-s`, `--norc`, `--mask-lock`, `-h`.

`--mask-lock` puts the masking engine into a one-way lockdown after rc
files have been processed: subsequent `mask remove`, `mask disable`, and
`set -o nomask-cmdsub` are refused. Adding more rules and re-enabling
disabled rules is still allowed (both strengthen redaction). The same
state can be reached interactively with `mask lock`.

## How masking works

Three rule sources are merged at startup:

1. **Universal patterns** emails, IPv4/IPv6, MACs, UUIDs, JWTs,
   AWS / GitHub / Google / Slack / Bearer tokens, IBANs, credit cards,
   SSNs, phone numbers, hex secrets (32/40/64 chars), PEM private-key
   blocks.
2. **Runtime-derived literals** `$USER`, `$LOGNAME`, `$SUDO_USER`,
   the passwd GECOS name, `$HOME`, hostname, UID/GID, every interface
   IPv4/IPv6/MAC, and `$SSH_CLIENT`, `$SSH_TTY`, `$SSH_CONNECTION`,
   `$MAIL`, `$MAILPATH`.
3. **User rules** added via the `mask` built-in or loaded from
   `~/.mashrc`.

Every writable descriptor the shell hands out stdout, stderr,
files opened by `>` `>>` `&>` `2>`, and every pipe stage is wrapped
with a pump thread in the shell process that reads, masks, and writes.
Command substitution `$(…)` masks captured output too. History is
persisted already-masked.

### Interactive programs and pseudo-terminals

Full-screen TUIs like `vim`, `less`, `htop`, `top`, and `ssh` need a
real terminal, not a pipe. When the shell is interactive and a
foreground external command has no redirections, mash runs it on a
pseudo-terminal opened with `openpty(3)`: the child sees `isatty(0)`,
`isatty(1)`, and `isatty(2)` all return true, has full termios control,
and owns the controlling tty so `Ctrl-C` and `Ctrl-Z` are delivered
directly to it. The parent forwards keystrokes from the user's real
tty to the master, masks every byte coming back from the child, and
then writes the redacted output to the screen. Window-size changes
(`SIGWINCH`) and `Ctrl-Z` (job control) are forwarded transparently.
Masking is therefore preserved end-to-end even for full-screen
applications. On Linux, this requires linking against `-lutil` (handled
automatically by the Makefile).

Use `mask show` to list rules, `mask add CAT PATTERN`, `mask literal CAT
STRING`, `mask disable N`, `mask enable N`, `mask remove N` to manage them
at runtime, and `mask lock` to enter the irreversible lockdown described
above.

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
- Line editor: cursor motion, history, `Ctrl-A/E/K/U/W/L/C/D`, with
  live syntax highlighting (keywords, builtins, operators, redirections,
  strings, `$VAR`, `$(...)`, comments). Auto-disabled on non-TTY output
  and when `NO_COLOR` is set or `TERM=dumb`.
- Startup files: `/etc/mashrc`, `~/.mashrc`.

Built-ins:

```
:  cd  pwd  echo  printf  export  unset  set  alias  unalias
source  .  exit  return  shift  break  continue  true  false
test  [  type  help  history  jobs  fg  bg  kill  wait  umask
read  mask
```

## Limitations

- No process substitution `<(…)` / `>(…)`.
- No `[[ … ]]` extended tests.
- No associative arrays.
- No multibyte-aware line editor (UTF-8 bytes still display correctly).
- No native Windows build use WSL, Cygwin, or MSYS2.
