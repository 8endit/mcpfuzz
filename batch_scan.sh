#!/usr/bin/env bash
# batch_scan.sh — Scan all catalog servers in isolated Docker containers
#
# Usage:
#   ./batch_scan.sh                          # All scannable servers
#   ./batch_scan.sh --type real              # Only real servers
#   ./batch_scan.sh --category database      # Only database servers
#   ./batch_scan.sh --id sqlite-explorer     # Single server by ID
#
# Every server runs in a fresh Docker container with:
#   - No network access
#   - Read-only filesystem
#   - All capabilities dropped
#   - Non-root user
#   - Memory/CPU/PID limits
#
# NOTHING runs on your host. Ever.

set -euo pipefail
cd "$(dirname "$0")"

REPORTS_DIR="reports/batch"
CATALOG="catalog/servers.yaml"
TS=$(date +%Y%m%d_%H%M%S)
TIMEOUT=15

mkdir -p "$REPORTS_DIR"

# Parse args
FILTER_TYPE=""
FILTER_CAT=""
FILTER_ID=""
for arg in "$@"; do
    case "$arg" in
        --type) shift; FILTER_TYPE="${1:-}"; shift || true ;;
        --category) shift; FILTER_CAT="${1:-}"; shift || true ;;
        --id) shift; FILTER_ID="${1:-}"; shift || true ;;
    esac
done

# Step 1: Build base image (includes mcpfuzz + patterns)
echo "================================================================"
echo "  mcpfuzz Batch Scanner"
echo "  All servers run in isolated Docker containers"
echo "  No code executes on your host"
echo "================================================================"
echo ""
echo "[BUILD] Building base scanner image..."
docker build -t mcpfuzz-base -f Dockerfile . 2>&1 | tail -3
echo "[BUILD] Base image ready."
echo ""

# Step 2: Parse catalog and scan each server
python3 -c "
import yaml, json, sys

with open('$CATALOG') as f:
    data = yaml.safe_load(f)

servers = data.get('servers', [])

# Filter
filter_type = '${FILTER_TYPE}'
filter_cat = '${FILTER_CAT}'
filter_id = '${FILTER_ID}'

if filter_type:
    servers = [s for s in servers if s.get('type') == filter_type]
if filter_cat:
    servers = [s for s in servers if filter_cat in (s.get('category') if isinstance(s.get('category'), list) else [s.get('category', '')])]
if filter_id:
    servers = [s for s in servers if s.get('id') == filter_id]

# Only servers with a command
servers = [s for s in servers if s.get('command')]

print(json.dumps(servers))
" > "$REPORTS_DIR/.batch_servers_$$.json"

SERVER_COUNT=$(python3 -c "import json; print(len(json.load(open('"$REPORTS_DIR/.batch_servers_$$.json"'))))")
echo "[SCAN] Found $SERVER_COUNT servers to scan"
echo ""

if [ "$SERVER_COUNT" = "0" ]; then
    echo "No servers matched the filter. Exiting."
    exit 0
fi

# Step 3: Scan each server
SUMMARY_FILE="$REPORTS_DIR/batch_summary_${TS}.json"
echo "[" > "$SUMMARY_FILE"
FIRST=true

python3 -c "
import json
servers = json.load(open('"$REPORTS_DIR/.batch_servers_$$.json"'))
for i, s in enumerate(servers):
    print(json.dumps(s))
" | while IFS= read -r SERVER_JSON; do
    ID=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
    NAME=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('name','?'))")
    REPO=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('repo',''))")
    CMD=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('command',''))")
    INSTALL=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('install',''))")
    SETUP=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('setup',''))")
    PATCH=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('patch',''))")
    COPY_PATH=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('copy_path',''))")
    TYPE=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('type','?'))")
    STARS=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('stars',0))")
    SDK=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('sdk','?'))")
    CATEGORY=$(echo "$SERVER_JSON" | python3 -c "import json,sys; c=json.load(sys.stdin).get('category',[]); print(','.join(c) if isinstance(c,list) else c)")
    ENV_JSON=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('env',{})))")

    REPORT_FILE="$REPORTS_DIR/${ID}_${TS}.json"
    LOG_FILE="$REPORTS_DIR/${ID}_${TS}.log"
    IMAGE_NAME="mcpfuzz-scan-${ID}"

    echo "================================================================"
    echo "  [$ID] $NAME"
    echo "  Type: $TYPE | Category: $CATEGORY | Stars: $STARS | SDK: $SDK"
    echo "================================================================"

    # Skip if no repo to clone (npm/reference servers need special handling)
    if [ -z "$REPO" ] || [ "$REPO" = "npm" ]; then
        echo "  SKIP: No git repo to clone (npm package or missing repo)"
        echo "  {\"id\":\"$ID\",\"name\":\"$NAME\",\"status\":\"skipped\",\"reason\":\"no repo\"}" >> "$SUMMARY_FILE"
        echo ""
        continue
    fi

    # Clone repo if not already cloned
    TARGET_DIR="targets/community/$(basename "$REPO")"
    if [ ! -d "$TARGET_DIR" ]; then
        echo "  [CLONE] $REPO"
        git clone --depth 1 "$REPO" "$TARGET_DIR" 2>&1 | tail -1 || {
            echo "  SKIP: Clone failed"
            echo ""
            continue
        }
    fi

    # Build Docker image for this server
    echo "  [BUILD] Building isolated container..."

    # Determine what to COPY
    if [ -n "$COPY_PATH" ]; then
        COPY_SRC="$TARGET_DIR/$COPY_PATH"
    else
        COPY_SRC="$TARGET_DIR"
    fi

    # Build Dockerfile dynamically
    DOCKERFILE_CONTENT="FROM mcpfuzz-base
USER root
"
    # Install dependencies
    if [ -n "$INSTALL" ]; then
        DOCKERFILE_CONTENT+="RUN $INSTALL
"
    fi

    # Copy server code
    DOCKERFILE_CONTENT+="COPY --chown=fuzzer:fuzzer $COPY_SRC /target/
"

    # Apply patches
    if [ -n "$PATCH" ]; then
        DOCKERFILE_CONTENT+="RUN $PATCH
"
    fi

    # Run setup (create test DBs etc.)
    if [ -n "$SETUP" ]; then
        DOCKERFILE_CONTENT+="RUN $SETUP
"
    fi

    DOCKERFILE_CONTENT+="USER fuzzer
"

    echo "$DOCKERFILE_CONTENT" | docker build -f - -t "$IMAGE_NAME" . > "$LOG_FILE" 2>&1
    BUILD_EXIT=$?

    if [ $BUILD_EXIT -ne 0 ]; then
        echo "  [ERROR] Build failed — check $LOG_FILE"
        echo ""
        continue
    fi

    # Build env args
    ENV_ARGS=""
    if [ "$ENV_JSON" != "{}" ]; then
        ENV_ARGS=$(echo "$ENV_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'-e {k}={v}') for k,v in d.items()]" | tr '\n' ' ')
    fi

    # Determine send framing — prefer explicit catalog field, fall back to SDK
    SEND_FRAMING=$(echo "$SERVER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('framing','auto'))")
    if [ "$SEND_FRAMING" = "auto" ]; then
        case "$SDK" in
            mcp_fastmcp|mcp_low) SEND_FRAMING="content-length" ;;
            custom)              SEND_FRAMING="newline" ;;
        esac
    fi

    # Run scan in fully isolated container
    echo "  [SCAN] Scanning (network=none, read-only, non-root, framing=$SEND_FRAMING)..."
    timeout 90 docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp:size=50m,nosuid,nodev \
        --tmpfs /home/fuzzer/.cache:size=20m,noexec,nosuid,nodev \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --memory 256m \
        --cpus "1.0" \
        --pids-limit 50 \
        $ENV_ARGS \
        "$IMAGE_NAME" \
        scan --stdio "$CMD" --format json --timeout "$TIMEOUT" --send-framing "$SEND_FRAMING" \
        > "$REPORT_FILE" 2>> "$LOG_FILE"

    SCAN_EXIT=$?

    if [ $SCAN_EXIT -eq 0 ] && [ -s "$REPORT_FILE" ]; then
        python3 -c "
import json
with open('$REPORT_FILE') as f:
    d = json.load(f)
s = d['score']
fails = [r for r in d['results'] if r['status'] == 'fail']
broken = [r for r in d['results'] if r.get('evidence',{}).get('broken_promise')]
print(f'  Tools: {d[\"tools_discovered\"]} | Score: {s[\"passed\"]}/{s[\"total\"]} | Fails: {s[\"failed\"]} | Critical: {s[\"critical_fails\"]}')
if broken:
    print(f'  BROKEN PROMISES: {len(broken)}')
for f in fails:
    print(f'    [{f[\"severity\"].upper()}] {f[\"pattern_name\"]} on {f[\"tool\"]}')
" 2>/dev/null || echo "  (parse error)"
    elif [ $SCAN_EXIT -eq 124 ]; then
        echo "  TIMEOUT after 90s"
    else
        echo "  FAILED (exit $SCAN_EXIT)"
    fi

    # Cleanup image
    docker rmi "$IMAGE_NAME" > /dev/null 2>&1 || true

    echo ""
done

echo "================================================================"
echo "  Batch scan complete"
echo "  Reports: $REPORTS_DIR/"
echo "================================================================"
