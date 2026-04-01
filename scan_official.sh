#!/usr/bin/env bash
# scan_official.sh — Scan official MCP reference servers
#
# Phase 1: Build an image with the server pre-installed (needs network)
# Phase 2: Run the scan in that image (no network)
#
# Usage: ./scan_official.sh

set -euo pipefail

REPORTS_DIR="$(pwd)/reports"
mkdir -p "$REPORTS_DIR"
TS=$(date +%Y%m%d_%H%M%S)

# Official servers to test (only those published to npm)
SERVERS=(
    "@modelcontextprotocol/server-filesystem"
    "@modelcontextprotocol/server-memory"
    "@modelcontextprotocol/server-everything"
)

# Server-specific start commands
declare -A SERVER_CMDS
SERVER_CMDS["@modelcontextprotocol/server-filesystem"]="mcp-server-filesystem /tmp"
SERVER_CMDS["@modelcontextprotocol/server-memory"]="mcp-server-memory"
SERVER_CMDS["@modelcontextprotocol/server-everything"]="mcp-server-everything"

echo "================================================================"
echo "  mcpfuzz — Official MCP Server Scan"
echo "  Scanning ${#SERVERS[@]} servers"
echo "================================================================"
echo ""

# Phase 1: Build image with all servers pre-installed
echo "[PHASE 1] Building image with pre-installed servers..."

docker build -f - -t mcpfuzz-official-scan . <<'DOCKERFILE'
FROM mcpfuzz-scan-untrusted:latest

USER root

# Pre-install official MCP servers so we don't need network at scan time
RUN npm install -g --unsafe-perm \
    @modelcontextprotocol/server-filesystem \
    @modelcontextprotocol/server-memory \
    @modelcontextprotocol/server-everything

USER fuzzer
DOCKERFILE

echo "[PHASE 1] Image ready."
echo ""

# Phase 2: Scan each server
for SERVER in "${SERVERS[@]}"; do
    SERVER_SHORT=$(echo "$SERVER" | sed 's/@modelcontextprotocol\///')
    CMD="${SERVER_CMDS[$SERVER]}"
    REPORT="$REPORTS_DIR/${SERVER_SHORT}_${TS}.json"
    LOG="$REPORTS_DIR/${SERVER_SHORT}_${TS}.log"

    echo "================================================================"
    echo "  Scanning: $SERVER_SHORT"
    echo "  Command:  $CMD"
    echo "  Report:   $REPORT"
    echo "================================================================"

    timeout 90 docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp:size=50m,noexec,nosuid,nodev \
        --tmpfs /home/fuzzer/.cache:size=20m,noexec,nosuid,nodev \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --memory 256m \
        --cpus "1.0" \
        --pids-limit 50 \
        mcpfuzz-official-scan \
        scan --stdio "$CMD" --format json --timeout 10 \
        > "$REPORT" 2> "$LOG"

    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ] && [ -s "$REPORT" ]; then
        python3 -c "
import json
with open('$REPORT') as f:
    d = json.load(f)
s = d['score']
print(f'  Tools: {d[\"tools_discovered\"]}')
print(f'  Score: {s[\"passed\"]}/{s[\"total\"]} passed')
print(f'  Critical: {s[\"critical_fails\"]} | Fails: {s[\"failed\"]} | Warnings: {s[\"warnings\"]}')
fails = [r for r in d['results'] if r['status'] == 'fail']
if fails:
    print('  Findings:')
    for r in fails:
        print(f'    [{r[\"severity\"].upper()}] {r[\"pattern_name\"]} on {r[\"tool\"]}')
else:
    print('  No vulnerabilities found.')
" 2>/dev/null || echo "  (parse error — check $REPORT)"
    elif [ $EXIT_CODE -eq 124 ]; then
        echo "  TIMEOUT after 90s"
    else
        echo "  FAILED (exit $EXIT_CODE) — check $LOG"
    fi
    echo ""
done

echo "================================================================"
echo "  All scans complete. Reports in: $REPORTS_DIR/"
echo "================================================================"
