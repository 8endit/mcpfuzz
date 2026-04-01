# mcpfuzz — Complete Scan Results

*Last updated: 2026-04-01*

All scans ran in isolated Docker containers (no network, read-only, all capabilities dropped, non-root user, memory limited). Nothing executes on the host.

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

## Summary Statistics

- **Total servers attempted**: 21
- **Successfully scanned**: 13 (7 real + 3 official + 3 validation)
- **Real vulnerabilities found**: 3 servers with findings (out of 7 real servers = 43%)
  - 4 CRITICAL findings
  - 5 HIGH findings
  - 1 MEDIUM finding
- **Zero false positives** on clean servers
- **8 test patterns**: Path Traversal, Command Injection, SSRF, SQL Injection, Error Leakage, Prompt Injection, Input Validation, Resource Exhaustion
