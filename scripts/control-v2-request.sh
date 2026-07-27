#!/bin/sh
# control-v2-request.sh — Sign and send an EtherGuard Control API v2 request.
#
# Usage:
#   CONTROL_NODE_ID=<decimal> CONTROL_PSKEY=<string> \
#     ./control-v2-request.sh [-X METHOD] [-d BODY] [-p PATH] URL
#
# The CONTROL_PSKEY is NEVER printed, logged, or persisted to disk.
# Missing CONTROL_NODE_ID or CONTROL_PSKEY causes exit 1 BEFORE any
# network request is sent.
#
# Canonical string matches Go (super_control_auth.go:312):
#   METHOD\nESCAPED_PATH\nTIMESTAMP\nNONCE\nhex(SHA-256(body))
#
# HMAC-SHA256 key is the raw PSKey string bytes (not base64-decoded).
#
# Requires: sh, curl, openssl (HMAC-SHA256), sha256sum, date, od

set -eu

# ── Usage ──────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage: CONTROL_NODE_ID=N CONTROL_PSKEY=K ./control-v2-request.sh [OPTIONS] URL

Sign and send an EtherGuard Control API v2 request.

Required environment variables (never printed or persisted):
  CONTROL_NODE_ID   Decimal node ID of the signing edge
  CONTROL_PSKEY     HMAC signing key (raw string, not base64-decoded)

Options:
  -X METHOD   HTTP method (default: GET)
  -d BODY     Request body (default: empty)
  -p PATH     URL path (default: /edge/v2/bootstrap)
  -h          Show this help

Examples:
  # Bootstrap (GET, empty body)
  CONTROL_NODE_ID=1 CONTROL_PSKEY='secret' \
    ./control-v2-request.sh http://127.0.0.1:3456

  # Custom endpoint
  CONTROL_NODE_ID=1 CONTROL_PSKEY='secret' \
    ./control-v2-request.sh -X POST -d '{}' -p /edge/v2/report \
    http://127.0.0.1:3456
EOF
}

# ── Validate required environment (BEFORE any network I/O) ─────────
if [ -z "${CONTROL_NODE_ID:-}" ]; then
    printf 'error: CONTROL_NODE_ID is required\n' >&2
    exit 1
fi
if [ -z "${CONTROL_PSKEY:-}" ]; then
    printf 'error: CONTROL_PSKEY is required\n' >&2
    exit 1
fi

# ── Defaults ────────────────────────────────────────────────────────
METHOD="GET"
BODY=""
PATH_SEG="/edge/v2/bootstrap"

# ── Parse options ───────────────────────────────────────────────────
while getopts 'X:d:p:h' opt; do
    case "$opt" in
        X) METHOD="$OPTARG" ;;
        d) BODY="$OPTARG" ;;
        p) PATH_SEG="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [ $# -lt 1 ]; then
    printf 'error: URL argument is required\n' >&2
    exit 1
fi
BASE_URL="$1"

# ── Check dependencies ─────────────────────────────────────────────
for cmd in curl openssl sha256sum date od; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$cmd" >&2
        exit 1
    fi
done

# ── Generate timestamp and nonce ───────────────────────────────────
TIMESTAMP=$(date +%s)
# 8 random bytes → 16 hex chars (matches Go's nonce format range)
NONCE=$(od -A n -t x1 -N 8 /dev/urandom | tr -d ' \n\t')

# ── Compute body hash ──────────────────────────────────────────────
BODY_HASH=$(printf '%s' "$BODY" | sha256sum | cut -d' ' -f1)

# ── Build canonical string ─────────────────────────────────────────
# Matches Go: METHOD + "\n" + r.URL.EscapedPath() + "\n" + ts + "\n" + nonce + "\n" + hex(SHA256(body))
CANONICAL=$(printf '%s\n%s\n%s\n%s\n%s' "$METHOD" "$PATH_SEG" "$TIMESTAMP" "$NONCE" "$BODY_HASH")

# ── Compute HMAC-SHA256 signature ─────────────────────────────────
SIGNATURE=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$CONTROL_PSKEY" 2>/dev/null | awk '{print $NF}')

# ── Build full URL ─────────────────────────────────────────────────
BASE_URL="${BASE_URL%/}"
FULL_URL="${BASE_URL}${PATH_SEG}"

# ── Invoke curl ────────────────────────────────────────────────────
TMPFILE=$(mktemp) || {
    printf 'error: failed to create temporary file\n' >&2
    exit 1
}
trap 'rm -f "$TMPFILE"' EXIT

set -- \
    -s -o "$TMPFILE" -w '%{http_code}' \
    --path-as-is \
    -X "$METHOD" \
    -H "X-EG-NodeID: ${CONTROL_NODE_ID}" \
    -H "X-EG-Timestamp: ${TIMESTAMP}" \
    -H "X-EG-Nonce: ${NONCE}" \
    -H "X-EG-Signature: ${SIGNATURE}"

if [ -n "$BODY" ]; then
    set -- "$@" -d "$BODY"
fi

set -- "$@" "$FULL_URL"

HTTP_CODE=$(curl "$@") || {
    printf 'error: connection to %s failed\n' "$BASE_URL" >&2
    exit 1
}

# ── Output ─────────────────────────────────────────────────────────
cat "$TMPFILE"
printf '\n__HTTP_STATUS__%s\n' "$HTTP_CODE"
