#!/usr/bin/env bash
# scan_community.sh — Scan community MCP servers one by one
#
# Each server gets its own Docker image (isolated dependency install)
# then scanned with network disabled.

set -euo pipefail

REPORTS_DIR="$(pwd)/reports"
mkdir -p "$REPORTS_DIR"
TS=$(date +%Y%m%d_%H%M%S)

# ================================================================
# Helper: build + scan a Python MCP server
# ================================================================
scan_python_server() {
    local NAME="$1"
    local SERVER_DIR="$2"
    local REQUIREMENTS="$3"    # pip packages to install
    local START_CMD="$4"       # command to start the server
    local ENV_ARGS="${5:-}"    # extra docker env args, e.g. "-e FOO=bar"
    local SETUP_CMD="${6:-}"   # commands to run before scan (e.g. create test DB)

    local REPORT="$REPORTS_DIR/${NAME}_${TS}.json"
    local LOG="$REPORTS_DIR/${NAME}_${TS}.log"
    local IMAGE="mcpfuzz-community-${NAME}"

    echo ""
    echo "================================================================"
    echo "  Scanning: $NAME"
    echo "  Source:   $SERVER_DIR"
    echo "  Report:   $REPORT"
    echo "================================================================"

    # Pre-scan: check for suspicious patterns
    echo "[PRE-SCAN] Checking for red flags..."
    {
        echo "=== PRE-SCAN: $NAME ==="
        echo ""
        echo "--- Suspicious patterns ---"
        grep -rn --include="*.py" -E \
            'os\.system|subprocess\.(call|run|Popen).*shell=True|eval\(|exec\(|__import__.*\(|pty\.spawn' \
            "$SERVER_DIR" 2>/dev/null || echo "(none)"
        echo ""
        echo "--- Network imports ---"
        grep -rn --include="*.py" -E \
            'import (socket|http\.client|urllib|requests|aiohttp|httpx|paramiko|ftplib|smtplib)' \
            "$SERVER_DIR" 2>/dev/null || echo "(none)"
        echo ""
    } | tee "$LOG"

    # Build image with server + deps
    echo "[BUILD] Building isolated image..."
    docker build -f - -t "$IMAGE" . <<DOCKERFILE
FROM mcpfuzz-scan-untrusted:latest

USER root

# Install server dependencies
RUN pip install --no-cache-dir $REQUIREMENTS

# Copy server code
COPY --chown=fuzzer:fuzzer $SERVER_DIR /target/

# Run any setup commands (e.g. create test DB)
${SETUP_CMD:+RUN $SETUP_CMD}

USER fuzzer
DOCKERFILE

    if [ $? -ne 0 ]; then
        echo "[ERROR] Build failed for $NAME" | tee -a "$LOG"
        return 1
    fi

    # Scan with full isolation
    echo "[SCAN] Running scan (network disabled, read-only)..."
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
        $ENV_ARGS \
        "$IMAGE" \
        scan --stdio "$START_CMD" --format json --timeout 10 \
        > "$REPORT" 2>> "$LOG"

    EXIT_CODE=$?
    echo "" >> "$LOG"
    echo "=== EXIT CODE: $EXIT_CODE ===" >> "$LOG"

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
        ev = r.get('evidence', {})
        if ev.get('input'):
            print(f'       Payload: {ev[\"input\"][:80]}')
else:
    print('  No vulnerabilities found.')
" 2>/dev/null || echo "  (could not parse report)"
    elif [ $EXIT_CODE -eq 124 ]; then
        echo "  TIMEOUT after 90s"
    else
        echo "  FAILED (exit $EXIT_CODE) — check $LOG"
    fi

    # Cleanup image
    docker rmi "$IMAGE" > /dev/null 2>&1 || true
}


# ================================================================
# Server 1: sqlite-explorer-fastmcp-mcp-server
# ================================================================
scan_python_server \
    "sqlite-explorer" \
    "targets/community/sqlite-explorer-fastmcp-mcp-server" \
    "fastmcp==0.4.1" \
    "fastmcp run /target/sqlite_explorer.py" \
    "-e SQLITE_DB_PATH=/target/test.db" \
    "python3 -c \"import sqlite3; c=sqlite3.connect('/target/test.db'); c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)'); c.execute(\\\"INSERT INTO users VALUES (1, 'Alice', 'alice@test.com')\\\"); c.commit(); c.close()\""


# ================================================================
# Summary
# ================================================================
echo ""
echo "================================================================"
echo "  All scans complete."
echo "  Reports: $REPORTS_DIR/"
echo "================================================================"
