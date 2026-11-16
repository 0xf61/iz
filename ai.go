package main

import (
	"fmt"
	"os"
)

const agentGuide = `# iz — AI Agent Memory & Execution Tool Guide

iz is a persistent second brain and terminal execution ledger for AI agents (Claude Code, Hermes, Antigravity, OpenCode, Pi, etc.).
It stores structured knowledge notes (rules, user preferences, architectures, runbooks, credentials) alongside full historical terminal command executions and their complete outputs in a local SQLite FTS5 database, with optional LibSQL/Turso cloud sync.

---

## 1. Recalling Knowledge & Past Commands (QUERY)

Always recall memory before asking the user or assuming context is missing:

  iz recall "<query>"             # Compact hybrid search (notes + command runs)
  iz recall --json "<query>"      # Compact single-line JSON output (recommended for tool calls)
  iz recall --pretty "<query>"    # Indented JSON output
  iz recall -n "<query>"          # Knowledge notes only
  iz recall -r "<query>"          # Historical command runs only

### Query syntax:
- Full-text search: matches across title, content, command and output (e.g. iz recall "kali 10.42.13.37")
- Namespace filter: iz recall "ns:machines 10.42.13.37"
- Tag filter: iz recall "tag:vpn"
- Author / Host filter: iz recall "author:alice host:kali"
- Command / Dir / Size filter: iz recall "cmd:nmap dir:eng size:>10kb"

---

## 2. Recording Notes, Facts & Findings (INGEST)

When you discover credentials, solve an infrastructure problem, learn preferences, or complete an audit step:

  iz n <namespace:title> [-t tag1,tag2] "<content>"

### Examples:
  iz n user:preferences "Prefers concise responses, CLI-first workflows, dark mode."
  iz n pentest:target-creds "Host: 10.10.138.12 | MSSQL sa:P@ssword123 | Domain: CORP"
  iz n machines:kali -t vpn "Kali box IP 10.42.13.37"
  iz n lessons:api-timeouts "Long-running jobs require API_TIMEOUT_MS=3000000."

### Piped input:
  cat /path/to/findings.md | iz n pentest:recon-summary

---

## 3. Reading & Managing Notes

  iz n list [namespace]           # List existing notes
  iz n show <id>                  # Print full markdown content of a note
  iz n del <id>                   # Delete a note

---

## 4. Viewing Historical Terminal Outputs

  iz sh <run_id>                  # View full colored output of a previous run
  iz sh <run_id> "<search_term>"  # Highlight matching terms in the output

---

## 5. Running Commands with Full Output Capture

When you run a command whose output might be needed for later reasoning or evidence:

  iz -- <command> [args...]

Example:
  iz -- nmap -sC -sV -p 1-1000 10.10.138.12
  # Exit code, timing, working dir, and full terminal output are indexed into FTS5.

---

## 6. Synchronizing Across Machines (Turso / LibSQL)

  iz sync

Two-way synchronization with Turso / LibSQL cloud using environment variables:
  - IZ_SYNC_URL (or TURSO_DATABASE_URL)
  - IZ_AUTH_TOKEN (or TURSO_AUTH_TOKEN)
`

func aiGuideCmd() int {
	fmt.Fprint(os.Stdout, agentGuide)
	return 0
}
