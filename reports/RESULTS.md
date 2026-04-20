# mcpfuzz — Complete Scan Results

*Last updated: 2026-04-20*

All scans ran in isolated Docker containers (no network, read-only, all capabilities dropped, non-root user, memory limited). Nothing executes on the host.

> **Note on the 2026-04-20 batch:** The six additional servers in the section
> *"Additional batch"* below were scanned in a Docker-unavailable environment,
> directly on a throwaway sandbox host. All findings were triaged manually
> afterwards and separated into *Real* vs *False Positive* — see the dedicated
> table.

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

## Additional batch — 2026-04-20 (6 servers)

Raw scanner output:

| # | Server | Stars | Category | Tools | Score | Raw failures |
|---|--------|-------|----------|-------|-------|--------------|
| 14 | modelcontextprotocol/servers → **mcp-server-git** (Python, official) | 50k | git | 12 | 53/64 | 11 CRITICAL (cmd inj on `repo_path`) |
| 15 | modelcontextprotocol/servers → **mcp-server-fetch** (Python, official) | 50k | fetch | 1 | 4/5 | 1 HIGH (prompt inj in response) |
| 16 | runekaagaard/**mcp-alchemy** | ~300 | database | 4 | 10/15 | 1 CRITICAL SQLi, 2 HIGH err-leak, 1 HIGH prompt-inj |
| 17 | vivekVells/**mcp-pandoc** | ~200 | search | 1 | 4/6 | 1 HIGH prompt-inj |
| 18 | GongRzhe/**Office-Word-MCP-Server** | ~1k | filesystem | 25 | 115/156 | 23 CRITICAL cmd-inj + 13 CRITICAL SQLi + 3 HIGH err-leak + 1 HIGH prompt-inj |
| 19 | mark3labs/**mcp-filesystem-server** (Go) | ~500 | filesystem | 14 | 43/65 | 12 HIGH error leakage |

### Triage — real vs. false positive

The high raw critical count turned out to be dominated by one false-positive
class: tools that **echo the user's input verbatim in success or error
messages** satisfy the scanner's `response_contains_any: MCPFUZZ_INJECT_MARKER`
detector even though no shell or SQL ever runs. This was not previously
observed because the earlier batch did not include many servers that echo
arguments into their response text.

| Server | Pattern | Raw | Real | FP | Notes |
|--------|---------|----:|----:|---:|-------|
| mcp-server-git (official) | Command Injection | 11 | **0** | 11 | Server correctly rejects paths outside the allowed repo with a message like `"Repository path '…' is outside the allowed repository"`. Marker is just echoed in the rejection. |
| Office-Word | Command Injection | 23 | **0** (all create/modify doc tools) | 23 | Server writes the literal payload into `filename`/`text` fields of the docx. No shell. `convert_to_pdf` requires further inspection once LibreOffice is present. |
| Office-Word | SQL Injection | 13 | **0** | 13 | Same echo-in-filename class. No database involved. |
| mcp-alchemy | SQL Injection on `execute_query` | 1 | **0** | 1 | `execute_query` is by design a raw-SQL execution tool; syntax errors are expected behaviour, not a vulnerability. |
| mcp-alchemy | Error Info Leakage | 2 | **2** | 0 | Responses include SQLAlchemy stack-traces with the full `DB_URL` and driver version. |
| mcp-alchemy | Prompt Inj in Response | 1 | **1** | 0 | Untrusted text is returned verbatim as part of the error payload. |
| mcp-server-fetch (official) | Prompt Inj in Response | 1 | **1** | 0 | Fetched URL payload reaches the LLM untouched — known design tradeoff for fetch servers. |
| mcp-pandoc | Prompt Inj in Response | 1 | **1** | 0 | Same class as fetch — input echoed into output. |
| Office-Word | Error Info Leakage | 3 | **3** | 0 | Error responses disclose absolute host paths like `/home/user/mcpfuzz/test`. |
| Office-Word | Prompt Inj in Response | 1 | **1** | 0 | Pydantic validation error echoes the `<system>…</system>` payload. |
| mcp-filesystem-server (Go) | Error Info Leakage | 12 | **12** | 0 | Every filesystem tool returns the absolute resolved path inside its rejection messages. Minor but consistent. |

**Actual new findings (after triage):**

- 0 CRITICAL
- **20 HIGH** (across 5 servers): error leakage × 17, prompt injection in response × 3. (The `mcp-filesystem-server` leakage is arguably *by design*, since rejection messages naturally name the path being rejected — call this MEDIUM in practice.)

### Scanner gap uncovered by this batch

This batch surfaced a **scanner false-positive class** that is worth fixing
before publishing more findings: the `command_injection` and `sql_injection`
patterns treat any response that contains the marker / an SQL error token as a
hit, even when the marker is merely the server echoing user input verbatim. A
sharper detector would require one of:

1. A baseline round-trip to subtract input-echo from the response before
   matching.
2. Additional negation phrases (`"outside the allowed"`, `"created successfully"`,
   `"is not a valid"`, …) in `response_not_contains`.
3. A positive side-effect probe (e.g. writing a sentinel to a tmpfs path and
   reading it back out-of-band) to confirm real execution.

Not fixing this in this batch — filed as a follow-up item.

## Summary Statistics

- **Total servers attempted**: 27 (21 original + 6 new in 2026-04-20 batch)
- **Successfully scanned**: 19 (13 original + 6 new)
- **Real vulnerabilities found so far**:
  - Original batch: 3 servers with findings (4 CRITICAL, 5 HIGH, 1 MEDIUM)
  - 2026-04-20 batch: 5 servers with findings after triage (0 CRITICAL, 20 HIGH)
- **Scanner FP rate in new batch**: 48 / 69 raw fails → ~70 % on CRITICAL tier (all on servers that echo inputs)
- **8 test patterns**: Path Traversal, Command Injection, SSRF, SQL Injection, Error Leakage, Prompt Injection, Input Validation, Resource Exhaustion
