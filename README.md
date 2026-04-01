# mcpfuzz

**Dynamic security testing for MCP servers.**

Existing tools scan what MCP servers *claim* to do. mcpfuzz tests what they *actually* do.

Static scanners read tool descriptions. mcpfuzz connects, sends crafted inputs, and verifies that your server handles them safely.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
# Scan a local MCP server (stdio transport)
mcpfuzz scan --stdio "python my_server.py"

# Discovery only (list tools, no testing)
mcpfuzz discover --stdio "python my_server.py"

# Run specific patterns only
mcpfuzz scan --stdio "python my_server.py" --patterns path_traversal,ssrf

# JSON output for CI/CD
mcpfuzz scan --stdio "python my_server.py" --format json --output report.json

# Markdown report
mcpfuzz scan --stdio "python my_server.py" --format md --output report.md
```

## What It Tests

mcpfuzz ships with 7 security test patterns:

| Pattern | Severity | What It Tests |
|---------|----------|---------------|
| **Path Traversal** | CRITICAL | File path parameters allow `../../etc/passwd` style access |
| **Command Injection** | CRITICAL | String parameters that land in shell commands |
| **SSRF** | CRITICAL | URL parameters allow requests to internal/metadata endpoints |
| **Error Leakage** | HIGH | Error responses leak stack traces, paths, DB connection strings |
| **Prompt Injection** | HIGH | External data returned unfiltered (LLM injection risk) |
| **Input Validation** | MEDIUM | Handling of empty strings, null bytes, oversized payloads |
| **Resource Exhaustion** | MEDIUM | Missing rate limits, timeouts, input size limits |

## How It Works

1. **Connect** to the MCP server via stdio (subprocess) or HTTP
2. **Discover** all tools and their parameter schemas via `tools/list`
3. **Match** tools to applicable test patterns based on parameter names and types
4. **Execute** crafted payloads against each tool via `tools/call`
5. **Analyze** responses for vulnerability indicators
6. **Report** results with severity, evidence, and scoring

## Pattern Matching

mcpfuzz automatically determines which patterns to run against which tools:

- A tool with a `path` parameter gets Path Traversal tests
- A tool with a `url` parameter gets SSRF tests
- A tool with a `cmd` parameter gets Command Injection tests
- Input Validation, Error Leakage, and Resource Exhaustion run against all tools

## Running Safely with Docker (Recommended)

mcpfuzz sends crafted payloads to MCP servers. If a server is vulnerable, those payloads execute on the machine running the server. **Always run scans in an isolated Docker container** — never on your host system.

```bash
# Build the container
docker compose build

# Scan demo servers (fully isolated — no network, no host access)
docker compose run --rm scan-vulnerable
docker compose run --rm scan-secure

# Run tests inside container
docker compose run --rm test

# Scan your own server (mount read-only)
docker compose run --rm -v /path/to/server:/target:ro scan-custom \
  scan --stdio "python /target/server.py"
```

The container runs with:
- `network_mode: none` — no network access
- `read_only` filesystem + `tmpfs` for temp dirs
- All Linux capabilities dropped (`cap_drop: ALL`)
- `no-new-privileges` — no privilege escalation
- Memory/CPU/PID limits — kills runaway processes
- Non-root user inside container

## Demo Servers

Two demo servers are included for development and testing:

```bash
# Via Docker (recommended)
docker compose run --rm scan-vulnerable
docker compose run --rm scan-secure

# Direct (only for development, NOT for untrusted servers)
mcpfuzz scan --stdio "python demo_servers/vulnerable_server.py"
mcpfuzz scan --stdio "python demo_servers/secure_server.py"
```

## Adding Custom Patterns

See [docs/ADDING_PATTERNS.md](docs/ADDING_PATTERNS.md) for how to write your own YAML test patterns.

## Known Limitations

- **Echo-back false positives**: Tools that echo user input in responses (e.g., `search_db` returning "Found 0 results for: <input>") may trigger Command Injection false positives when the input contains the detection marker.
- **Platform-specific payloads**: Path traversal payloads are platform-aware (Unix vs Windows), but some cross-platform edge cases may exist.
- **HTTP connector**: Requires `aiohttp` (not included in base dependencies). Install separately: `pip install aiohttp`.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
