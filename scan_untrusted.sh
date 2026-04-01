#!/usr/bin/env bash
# scan_untrusted.sh — Safely scan an untrusted MCP server in Docker
#
# Usage:
#   ./scan_untrusted.sh /path/to/server "python server.py"
#   ./scan_untrusted.sh /path/to/server "node dist/index.js"
#
# Creates a timestamped report in ./reports/

set -euo pipefail

TARGET_DIR="${1:?Usage: $0 /path/to/server \"command to start server\"}"
SERVER_CMD="${2:?Usage: $0 /path/to/server \"command to start server\"}"

# Validate target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: Target directory does not exist: $TARGET_DIR"
    exit 1
fi

# Create reports directory
REPORTS_DIR="$(pwd)/reports"
mkdir -p "$REPORTS_DIR"

# Timestamp for this scan
TS=$(date +%Y%m%d_%H%M%S)
SERVER_NAME=$(basename "$TARGET_DIR")
REPORT_JSON="$REPORTS_DIR/${SERVER_NAME}_${TS}.json"
REPORT_LOG="$REPORTS_DIR/${SERVER_NAME}_${TS}.log"

echo "================================================================"
echo "  mcpfuzz — Untrusted Server Scan"
echo "================================================================"
echo "  Target:    $TARGET_DIR"
echo "  Command:   $SERVER_CMD"
echo "  Report:    $REPORT_JSON"
echo "  Log:       $REPORT_LOG"
echo "================================================================"
echo ""
echo "  Container isolation:"
echo "    - network_mode: none (no network)"
echo "    - read_only filesystem (noexec tmpfs)"
echo "    - all capabilities dropped"
echo "    - 128MB RAM, 0.5 CPU, 30 PIDs max"
echo "    - non-root user"
echo "    - 15s force-kill timeout"
echo ""
echo "  Target mounted as: /target (read-only)"
echo "================================================================"
echo ""

# Pre-scan: check for obvious red flags in target code
echo "[PRE-SCAN] Checking target for obvious red flags..."
{
    echo "=== PRE-SCAN REPORT ==="
    echo "Target: $TARGET_DIR"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""

    # Check for suspicious patterns in Python files
    echo "--- Suspicious patterns found ---"
    grep -rn --include="*.py" -E \
        'os\.system|subprocess\.(call|run|Popen).*shell=True|eval\(|exec\(|__import__|socket\.socket|urllib\.request|requests\.(get|post)|shutil\.rmtree|os\.remove|pty\.spawn' \
        "$TARGET_DIR" 2>/dev/null || echo "(none)"
    echo ""

    # Check for network-related imports
    echo "--- Network-related imports ---"
    grep -rn --include="*.py" -E \
        'import (socket|http|urllib|requests|aiohttp|httpx|websocket|paramiko|ftplib|smtplib|telnetlib)' \
        "$TARGET_DIR" 2>/dev/null || echo "(none)"
    echo ""

    # Check for file system operations
    echo "--- Filesystem operations ---"
    grep -rn --include="*.py" -E \
        'open\(.*["\x27]/etc|open\(.*["\x27]/proc|os\.path\.expanduser|Path\.home|os\.environ' \
        "$TARGET_DIR" 2>/dev/null || echo "(none)"
    echo ""
    echo "=== END PRE-SCAN ==="
} | tee "$REPORT_LOG"

echo ""
echo "[SCAN] Starting containerized scan..."
echo ""

# Run the scan in the hardened container
# - Mount target as read-only
# - Output JSON to stdout, capture it
# - Timeout the entire docker run after 120 seconds
timeout 120 docker compose run --rm \
    -v "${TARGET_DIR}:/target:ro" \
    scan-untrusted \
    scan --stdio "$SERVER_CMD" --format json --timeout 10 \
    > "$REPORT_JSON" 2>> "$REPORT_LOG"

EXIT_CODE=$?

echo "" >> "$REPORT_LOG"
echo "=== SCAN EXIT CODE: $EXIT_CODE ===" >> "$REPORT_LOG"

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "[DONE] Scan completed successfully."
    echo ""
    # Print summary from JSON
    python3 -c "
import json, sys
with open('$REPORT_JSON') as f:
    d = json.load(f)
s = d['score']
print(f\"  Score: {s['passed']}/{s['total']} passed\")
print(f\"  Critical fails: {s['critical_fails']}\")
print(f\"  Total fails: {s['failed']}\")
print(f\"  Warnings: {s['warnings']}\")
print()
# Show failures
for r in d['results']:
    if r['status'] == 'fail':
        print(f\"  FAIL [{r['severity'].upper()}] {r['pattern_name']} on {r['tool']}\")
        if r.get('evidence', {}).get('input'):
            print(f\"       Payload: {r['evidence']['input'][:80]}\")
" 2>/dev/null || echo "  (could not parse JSON report)"
    echo ""
    echo "  Full report: $REPORT_JSON"
    echo "  Full log:    $REPORT_LOG"
elif [ $EXIT_CODE -eq 124 ]; then
    echo ""
    echo "[TIMEOUT] Scan timed out after 120 seconds."
    echo "  This could indicate the server is hanging or trying to exhaust resources."
    echo "  Log: $REPORT_LOG"
else
    echo ""
    echo "[ERROR] Scan failed with exit code $EXIT_CODE"
    echo "  Check the log: $REPORT_LOG"
fi
