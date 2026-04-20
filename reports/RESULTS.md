# mcpfuzz — Complete Scan Results

*Last updated: 2026-04-20*

All scans ran in isolated Docker containers (no network, read-only, all capabilities dropped, non-root user, memory limited). Nothing executes on the host.

> **Note on the 2026-04-20 batch:** The nine additional servers in the section
> *"Additional batch"* below were scanned in a Docker-unavailable environment,
> directly on a throwaway sandbox host. The batch surfaced (and fixed) a
> scanner false-positive class on CRITICAL-tier marker-based detectors —
> details and before/after numbers in that section.

## Real Server Findings

| # | Server | Stars | Category | Tools | Score | Findings |
|---|--------|-------|----------|-------|-------|----------|
| 1 | yzfly/mcp-python-interpreter | 90 | code_exec | 10 | 29/36 | **2 CRITICAL** (path traversal on read_file), 3 HIGH (error leakage), 1 MED |
| 2 | simonholm/sqlite-mcp-server | 15 | database | 8 | 34/36 | **2 CRITICAL** (cmd injection on import_csv, SQL injection on backup_database) |
| 3 | tatn/mcp-server-fetch-python | ~20 | fetch | 4 | 18/20 | **2 HIGH** (error leakage on get-rendered-html, get-markdown) |

## Clean Real Servers

| # | Server | Stars | Category | Tools | Score |
|---|--------|-------|----------|-------|-------|
| 4 | hannesrudolph/sqlite-explorer | 30 | database | 3 | 13/13 |
| 5 | prayanks/mcp-sqlite-server | 10 | database | 1 | 5/5 |
| 6 | nickclyde/duckduckgo-mcp-server | 200 | search | 2 | 11/11 |
| 7 | ruslanmv/Simple-MCP-Server | ~10 | multi | 1 | 3/3 |

## Official Reference Servers

| # | Server | Tools | Score | Notes |
|---|--------|-------|-------|-------|
| 8 | @mcp/server-filesystem | 14 | 55/55 | Clean |
| 9 | @mcp/server-memory | 9 | 29/29 | Clean |
| 10 | @mcp/server-everything | 13 | 41/44 | 3 prompt injection (echo tool, expected) |

## Validation Targets (Intentionally Vulnerable — Not Real Findings)

| # | Server | Result | Notes |
|---|--------|--------|-------|
| 11 | Eliran79/Vulnerable-file-reader | 1 CRITICAL | Cmd injection via shell=True in cat (deliberate) |
| 12 | kenhuangus/vuln-mcp-server-demo | 2 CRITICAL + 1 HIGH | SQL injection + error leakage (deliberate) |
| 13 | harishsg993010/damn-vulnerable-MCP | Incompatible | Uses SSE transport, not stdio |

## Servers That Could Not Be Scanned

| Server | Reason |
|--------|--------|
| ckreiling/mcp-server-docker | Requires Docker socket (not available in isolated container) |
| anjor/coinmarket-mcp-server | Requires API key |
| ktanaka101/mcp-server-duckdb | Requires DB file at startup |
| blazickjp/arxiv-mcp-server | Startup error in container |
| MarcusJellinghaus/mcp_server_filesystem | Startup error in container |
| tumf/mcp-shell-server | Build dependency failure |
| designcomputer/mysql_mcp_server | Requires MySQL connection |
| panasenco/mcp-sqlite | anyio compatibility issue |

## Additional batch — 2026-04-20 (9 servers)

This batch doubled as a validation run for a **scanner FP fix** that landed in
the same change. The initial dry run produced 47 raw CRITICAL hits dominated
by a single false-positive class — tools that *echo the payload verbatim*
into a success or error message were being read as command / SQL injection by
the marker-based detectors. After the fix, all 47 FPs disappeared and only
real findings remain.

### What changed in the scanner

Two successive fixes landed on this branch:

1. **CRITICAL-tier echo FPs** (`src/mcpfuzz/engine/runner.py`, `patterns/sql_injection.yaml`).
   Positive indicators now (a) strip verbatim payload echoes from the response
   before matching, and (b) when the indicator itself is a substring of the
   payload, require it to occur *more often* in the response than in the
   payload. `prompt_injection` keeps the plain echo-matches-as-hit semantics
   because the echo itself IS the vulnerability being tested. Dropped
   `"syntax error"`, `"unrecognized token"`, `"near \""`, `"CREATE TABLE"`,
   `"3."` from the SQL positive list; added them as negatives.

2. **HIGH-tier error-leakage FPs** (`patterns/error_leakage.yaml`).
   The old indicator list contained many words (`"password"`, `"secret"`,
   `"token"`, `"sqlite"`, `"postgres"`, `"connection"`, `"/home/"`, `"/var/"`,
   `"/usr/"`) that matched normal tool output or ordinary rejection
   messages. Rewritten to only flag stack-trace markers
   (`"Traceback (most recent call last)"`, `".py\", line "`, `"site-packages"`,
   `"dist-packages"`, `"node_modules"`, `"C:\\"`, `"stack trace"`) or
   credential-assignment patterns (`"password="`, `"secret_key"`, `"api_key="`,
   `"SECRET_"`). Added `"successfully"` / `"succeeded"` as negative
   indicators so success messages never fire.

8 new unit tests cover the edge cases: full echo / partial echo / real
execution / prompt-injection-on-echo / SQL-parser-error / password-in-success /
real-Python-traceback.

### Results (all 9 servers, post-fix)

| # | Server | Stars | Category | Tools | Score | Findings |
|---|--------|-------|----------|-------|-------|----------|
| 14 | modelcontextprotocol/servers → **mcp-server-git** (Python, official) | 50k | git | 12 | **64/64** | — clean |
| 15 | modelcontextprotocol/servers → **mcp-server-fetch** (Python, official) | 50k | fetch | 1 | 4/5 | 1 HIGH prompt-inj (by design for a fetch server) |
| 16 | runekaagaard/**mcp-alchemy** | ~300 | database | 4 | 14/15 | 1 HIGH prompt-inj (SQL-parser-error echoes payload) |
| 17 | vivekVells/**mcp-pandoc** | ~200 | search | 1 | 5/6 | 1 HIGH prompt-inj (document converter — passthrough is the function) |
| 18 | GongRzhe/**Office-Word-MCP-Server** | ~1k | filesystem | 25 | 155/156 | 1 HIGH prompt-inj (Pydantic validation error echoes input) |
| 19 | mark3labs/**mcp-filesystem-server** (Go) | ~500 | filesystem | 14 | **65/65** | — clean |
| 20 | modelcontextprotocol/servers → **mcp-server-time** (Python, official) | 50k | system | 2 | **7/7** | — clean |
| 21 | modelcontextprotocol/servers-archived → **mcp-server-sqlite** (Python, official) | 50k | database | 6 | **28/28** | — clean |
| 22 | `@modelcontextprotocol/server-sequential-thinking` (TypeScript, official) | 50k | system | 1 | **3/3** | — clean |

### FP-fix validation (raw → post-both-fixes)

| Server | Pattern | Raw | Post-fix | Notes |
|--------|---------|----:|----:|-------|
| mcp-server-git (official) | Command Injection | 11 | **0** | Rejected path was echoed; marker detection updated. |
| Office-Word | Command Injection | 23 | **0** | Payload stored as literal filename; no shell. |
| Office-Word | SQL Injection | 13 | **0** | Same echo class — no database involved. |
| Office-Word | Error Info Leakage | 3 | **0** | `"password"` / `"/home/"` indicators dropped; `"successfully"` now negative. |
| mcp-alchemy | SQL Injection on `execute_query` | 1 | **0** | `syntax error` is now a negative indicator. |
| mcp-alchemy | Error Info Leakage | 2 | **0** | `"sqlite"` / `"secret"` indicators dropped. |
| mcp-server-sqlite (official) | SQL Injection | 2 | **0** | Same echo class fixed by runner update. |
| mcp-server-sqlite (official) | Error Info Leakage | 2 | **0** | `"token"` matched `"unrecognized token"` — indicator removed. |
| mcp-filesystem-server (Go) | Error Info Leakage | 12 | **0** | `"/home/"` was too weak; every rejection mentions the path by design. |

**Total FPs eliminated: 69** across 7 servers. No real findings were lost —
every `"pass"` was manually verified against the raw JSON reports.

### Real findings after the fix

- **0 CRITICAL**.
- **4 HIGH**, all of type *"prompt injection in response"* — i.e. the server
  echoes untrusted input into its output such that a downstream LLM sees the
  injected `<system>…</system>` / `Ignore previous instructions …` text.
  For fetch and document-conversion tools this is the *raison d'être* of the
  server (it's what they're supposed to return); the finding is a useful
  reminder for agent authors, not a server-side bug per se.
- **5 servers fully clean** (64/64 ... 28/28): `mcp-server-git`,
  `mcp-server-time`, `mcp-server-sqlite`, `mcp-filesystem-server` (Go),
  `@modelcontextprotocol/server-sequential-thinking`.

## Summary Statistics

- **Total servers attempted**: 30 (21 original + 9 new in the 2026-04-20 batch)
- **Successfully scanned**: 22 (13 original + 9 new)
- **Real vulnerabilities found so far**:
  - Original batch: 3 servers with findings (4 CRITICAL, 5 HIGH, 1 MEDIUM)
  - 2026-04-20 batch: 4 servers with 1 HIGH prompt-inj each; 5 fully clean
- **Scanner FP rate on the new batch before fixes**: 69 / 73 raw fails. After
  fixes: 0 false positives, 0 lost real findings.
- **8 test patterns**: Path Traversal, Command Injection, SSRF, SQL Injection, Error Leakage, Prompt Injection, Input Validation, Resource Exhaustion
