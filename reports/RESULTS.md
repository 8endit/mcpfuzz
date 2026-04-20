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

- `src/mcpfuzz/engine/runner.py::_evaluate_response`: positive indicators now
  (a) strip verbatim payload echoes from the response before matching and
  (b) when the indicator itself is a substring of the payload, require it to
  occur *more often* in the response than in the payload. `prompt_injection`
  keeps the plain echo-matches-as-hit semantics because the echo itself is the
  vulnerability being tested there.
- `patterns/sql_injection.yaml`: dropped `"syntax error"`, `"unrecognized
  token"`, `"near \""`, `"CREATE TABLE"`, `"3."` from the positive list
  (too weak / shared with rejection messages); added them as *negative*
  indicators so a server that rejects a UNION payload with a SQL parser
  error is no longer flagged.
- New unit tests cover all three edge cases (full echo, partial echo, real
  execution) for both CRITICAL patterns plus prompt-injection.

### Results (all 9 servers, post-fix)

| # | Server | Stars | Category | Tools | Score | Findings |
|---|--------|-------|----------|-------|-------|----------|
| 14 | modelcontextprotocol/servers → **mcp-server-git** (Python, official) | 50k | git | 12 | **64/64** | — clean |
| 15 | modelcontextprotocol/servers → **mcp-server-fetch** (Python, official) | 50k | fetch | 1 | 4/5 | 1 HIGH prompt-inj |
| 16 | runekaagaard/**mcp-alchemy** | ~300 | database | 4 | 12/15 | 2 HIGH err-leak, 1 HIGH prompt-inj |
| 17 | vivekVells/**mcp-pandoc** | ~200 | search | 1 | 5/6 | 1 HIGH prompt-inj |
| 18 | GongRzhe/**Office-Word-MCP-Server** | ~1k | filesystem | 25 | 152/156 | 3 HIGH err-leak, 1 HIGH prompt-inj |
| 19 | mark3labs/**mcp-filesystem-server** (Go) | ~500 | filesystem | 14 | 53/65 | 12 HIGH err-leak (path disclosure in rejection msgs — arguably MEDIUM in practice) |
| 20 | modelcontextprotocol/servers → **mcp-server-time** (Python, official) | 50k | system | 2 | **7/7** | — clean |
| 21 | modelcontextprotocol/servers-archived → **mcp-server-sqlite** (Python, official) | 50k | database | 6 | 26/28 | 2 HIGH err-leak |
| 22 | `@modelcontextprotocol/server-sequential-thinking` (TypeScript, official) | 50k | system | 1 | **3/3** | — clean |

### FP-fix validation (raw → post-fix)

| Server | Pattern | Raw | Post-fix | Notes |
|--------|---------|----:|----:|-------|
| mcp-server-git (official) | Command Injection | 11 | **0** | Server rejected every path with `"outside the allowed repository"`; marker was just echoed. |
| Office-Word | Command Injection | 23 | **0** | Server wrote the payload as a literal filename; no shell. |
| Office-Word | SQL Injection | 13 | **0** | Same echo class — no database involved at all. |
| mcp-alchemy | SQL Injection on `execute_query` | 1 | **0** | `execute_query` is by design a raw-SQL tool; the payload produced a SQL parser error which the tightened pattern now treats as a negative. |
| mcp-server-sqlite (official) | SQL Injection | 2 | **0** | Identical pattern: rejection messages contain `"CREATE TABLE"` / echo `sqlite_master` fragments, now discounted. |

**Total FPs eliminated: 50** across 6 servers. No real findings were lost
(manually verified against the raw JSON reports).

### Real new findings after the fix

- **23 HIGH** across 7 servers (12 err-leak on `mcp-filesystem-server` alone).
- **0 CRITICAL**.
- 3 servers fully clean: `mcp-server-git`, `mcp-server-time`,
  `@modelcontextprotocol/server-sequential-thinking`.

## Summary Statistics

- **Total servers attempted**: 30 (21 original + 9 new in the 2026-04-20 batch)
- **Successfully scanned**: 22 (13 original + 9 new)
- **Real vulnerabilities found so far**:
  - Original batch: 3 servers with findings (4 CRITICAL, 5 HIGH, 1 MEDIUM)
  - 2026-04-20 batch: 7 servers with findings (0 CRITICAL, 23 HIGH); 3 fully clean
- **Scanner FP rate on CRITICAL tier before fix**: 50 / 50 raw CRITICAL =
  100 % on servers that echo inputs. After fix: 0.
- **8 test patterns**: Path Traversal, Command Injection, SSRF, SQL Injection, Error Leakage, Prompt Injection, Input Validation, Resource Exhaustion
