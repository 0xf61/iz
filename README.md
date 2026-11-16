# iz

iz records shell commands together with their full terminal output, and makes
all of it searchable from a single SQLite database.

If you have ever re-run a five minute scan just to look at one line of its
output again, that is the problem iz solves. Commands run through iz behave
normally: colors, progress bars and interactivity all work as usual. The
difference is that afterwards the command line, exit code, duration, working
directory and the complete colored output are stored and indexed.

## Why not atuin or asciinema?

- [atuin](https://atuin.sh) stores your shell history with great search, but it
  only keeps the command line. What the command printed is gone the moment you
  close the terminal.
- [asciinema](https://asciinema.org) records the whole session, but there is no
  way to search for "that nmap run where port 443 was filtered" or "the last
  build that mentioned this warning". You scrub through video.

iz sits between the two: per-command recording like atuin, output capture like
asciinema, and full-text search over both.

## How it works

- **Capture**: `iz -- <cmd>` runs the command inside a PTY. Output is mirrored
  to your terminal while being recorded. The program still sees a tty, so
  colors and progress bars stay on.
- **Storage**: one SQLite file per machine. Run metadata (command, exit code,
  duration, hostname, cwd), the raw output gzipped (typically 10-20x smaller),
  and an FTS5 index over the plain text.
- **Cleanup**: clear-screen sequences are dropped and progress-bar redraws
  collapse to their final frame, so replayed output looks like what you
  actually saw.
- **Search**: the TUI lists one colored line per run — id, date, tool,
  directory, command — and re-runs the full-text query live as you type
  (`change:reload` + `--phony`, so fzf itself never re-filters and every
  keystroke hits the FTS index). Lowercase terms match case-insensitively;
  mixed-case terms (like `ESC8`) match verbatim. `host:`, `dir:` and `size:`
  filter on columns; exit status and size are shown in the preview, whose
  header carries the hostname. The preview highlights whatever you type.

## Install

```fish
go install github.com/0xf61/iz@latest
```

The binary lands in `$GOBIN` (default `~/go/bin/iz`); make sure it is on your
`$PATH`. Requires Go 1.24+. No cgo, so the same works on Linux.

Or build from source:

```fish
git clone https://github.com/0xf61/iz && cd iz
go build -o ~/.local/bin/iz .
echo 'iz f | source' >> ~/.config/fish/config.fish
```

Cross-compiling for another machine (a server, a VM, a container) is a single
command since there is no cgo:

```fish
GOOS=linux GOARCH=amd64 go build -o dist/iz-linux-amd64 .
```

## Quick Setup & Shell Integration

Run `iz init` to automatically configure your current shell (fish, zsh, or bash) and detect installed AI coding assistants (Claude Code, OpenCode, Gemini, Cursor):

```sh
iz init           # auto-detect shell and AI assistants and inject hooks
iz init --show    # view integration status
```

Or print integration scripts manually:
```sh
eval "$(iz init zsh)"             # zsh integration + ctrl-g (search) + ctrl-o (notes)
eval "$(iz init bash)"            # bash integration + ctrl-g + ctrl-o
iz init fish | source             # fish integration + ctrl-g + ctrl-o (alias: iz f)
```

## Usage

```fish
iz -- cargo build --release       # run + record any command
iz a cargo make pytest            # record these tools automatically via wrappers
iz init                           # auto-setup shell wrappers & AI assistants
iz                                # search runs TUI
iz sh 42                          # replay output #42, colors intact
iz e 42                           # open output #42 in $EDITOR
iz i cargo build.log              # import a log file
iz m laptop.db                    # merge a db from another machine (runs + notes)
iz d less                         # remove a wrapper

# Memory, notes & cloud sync
iz n                              # interactive notes TUI (ctrl-o in fish)
iz n machines:kali -t vpn "10.42.13.37"        # save a structured note
iz n edit 1                       # edit note #1 in $EDITOR
iz n import ./notes/              # import markdown files/directory
iz recall "kali"                  # hybrid search across notes + command runs
iz recall --json "kali"           # compact JSON for AI agents
iz sync                           # two-way sync with Turso/LibSQL ($IZ_SYNC_URL)
iz ai                             # print AI agent integration guide
```

Search examples:

```fish
iz "warning: unused" cmd:cargo    # cargo runs mentioning a warning
iz timeout host:build01           # runs on a specific machine
iz size:>1mb                      # only large outputs (kb/mb/gb, > < >= <=)
iz 'deprecated'                   # exact phrase via FTS
```

### TUI keys

| key | action |
|---|---|
| `enter` | view output with `less -R` (colors kept, query highlighted) |
| `tab` | toggle selection / insert command into the prompt (widget) |
| `ctrl-a` | select all |
| `ctrl-e` | open output / note in `$EDITOR` |
| `ctrl-n` | create a new note in `$EDITOR` (`iz n` TUI) |
| `ctrl-y` | delete selected runs / note and reload |
| `'term` | fzf exact match (e.g. `'tool:make`) |

### Pausing recording

Recording is gated on the `$IZ` environment variable, which defaults to
`~/.iz/iz.db`:

```fish
set -e IZ                 # stop recording in this session (wrappers pass through)
set -gx IZ ~/.iz/iz.db    # resume
```

## Multiple machines & Cloud Sync

Sync two-way across machines with Turso / LibSQL via `$IZ_SYNC_URL` and `$IZ_AUTH_TOKEN`:

```fish
set -gx IZ_SYNC_URL "libsql://your-db.turso.io"
set -gx IZ_AUTH_TOKEN "ey..."
iz sync
```

Or copy a database file directly and merge:

```fish
scp build01:~/.iz/iz.db b01.db
iz m b01.db
iz host:build01 failed
```

## Development

```fish
make test      # go test ./...
make build     # go build -o iz .
make linux     # static linux/amd64 + linux/arm64 into dist/
```

| file | role |
|---|---|
| `main.go` | CLI dispatch |
| `db.go` | schema, migrations, CRUD, query parsing |
| `record.go` | PTY capture, shell quoting |
| `text.go` | ANSI cleanup, gzip, UTF-8 truncation |
| `search.go` | fzf runs TUI |
| `cmds.go` | add/del/list/rm/import/merge/show/edit |
| `memory.go` | structured notes, FTS5 recall, notes TUI |
| `sync.go` | two-way LibSQL/Turso & file replication |
| `shell.go` | fish, zsh, bash & AI assistant init generator |
| `ai.go` | AI agent reference guide |
