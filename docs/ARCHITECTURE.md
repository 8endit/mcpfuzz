# Architecture

## Overview

```
mcpfuzz CLI
    |
    ├── Connector (stdio / HTTP)  ── connects to MCP server
    ├── Discovery                 ── enumerates tools + schemas
    ├── Pattern Registry          ── loads YAML test definitions
    ├── Engine (Matcher + Runner) ── matches tools to patterns, executes tests
    └── Reporter (CLI / JSON / MD)── formats and outputs results
```

## Components

### Connector (`connector/`)
Handles MCP server communication via JSON-RPC 2.0. Two transports:
- **StdioConnector**: Spawns server as subprocess, communicates via stdin/stdout
- **HttpConnector**: Sends requests to a remote HTTP endpoint (supports SSE responses)

### Discovery (`discovery/`)
Performs the MCP `initialize` handshake and calls `tools/list` to enumerate available tools and their input schemas.

### Pattern System (`patterns/`)
- **Loader**: Parses YAML pattern files into `Pattern` dataclasses
- **Registry**: Manages the set of loaded patterns, supports filtering by ID

### Engine (`engine/`)
- **Matcher**: Determines which patterns apply to which tools by matching parameter names against regex patterns
- **Runner**: Orchestrates test execution — for each tool, runs all matching patterns' payloads, evaluates responses, and collects results

### Reporter (`reporter/`)
Generates output in three formats:
- **CLI**: Rich-formatted table with colors and severity indicators
- **JSON**: Structured data for CI/CD integration
- **Markdown**: Report suitable for documentation or issue tracking

## Data Flow

1. CLI parses arguments, loads patterns from `patterns/` directory
2. Connector establishes connection to target MCP server
3. Discovery fetches tool list and schemas
4. Matcher maps tools to applicable patterns
5. Runner executes each pattern's payloads via `tools/call`
6. Response evaluator checks for vulnerability indicators
7. Reporter formats results into chosen output format
