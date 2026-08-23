# Shared configuration and helpers for the Sentio e2e scripts.
# Sourced, not executed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Fixtures ────────────────────────────────────────────────────────────────
# Both domains sit under .test, which RFC 6761 reserves as never globally
# resolvable. Combined with delivery.relay this makes it impossible for a
# misconfigured run to put mail on the public internet.
SEND_DOMAIN="${SEND_DOMAIN:-sender.test}"
RECV_DOMAIN="${RECV_DOMAIN:-inbound.test}"
DKIM_SELECTOR="${DKIM_SELECTOR:-e2e}"

API_BASE="${SENTIO_API:-http://localhost:8080}"
API_KEY="${SENTIO_API_KEY:-sentio_bootstrap_admin_CHANGE_ME}"
TENANT_ID="${SENTIO_TENANT:-00000000-0000-0000-0000-000000000001}"
MAILPIT_URL="${MAILPIT_URL:-http://localhost:8025}"

# ── docker / compose ────────────────────────────────────────────────────────
# The docker group membership only takes effect after re-login, so fall back to
# sudo when the socket is not directly usable.
if docker info >/dev/null 2>&1; then
    DOCKER_BIN=(docker)
elif sudo -n docker info >/dev/null 2>&1; then
    DOCKER_BIN=(sudo -n docker)
else
    echo "error: cannot talk to the docker daemon (tried docker and sudo docker)" >&2
    exit 1
fi

# Passing -f disables auto-loading of docker-compose.override.yml, so include it
# explicitly when present or per-machine port remaps silently disappear.
_compose_files=(-f "$REPO_ROOT/docker-compose.yml" -f "$REPO_ROOT/docker-compose.test.yml")
[ -f "$REPO_ROOT/docker-compose.override.yml" ] && \
    _compose_files+=(-f "$REPO_ROOT/docker-compose.override.yml")

dc() { "${DOCKER_BIN[@]}" compose "${_compose_files[@]}" "$@"; }

# Ask the daemon which host port maps to container :25 rather than assuming.
smtp_port() {
    local hp
    hp="$(dc port sentio 25 2>/dev/null | tail -1)"
    [ -n "$hp" ] && echo "${hp##*:}" || echo 25
}
submission_port() {
    local hp
    hp="$(dc port sentio 587 2>/dev/null | tail -1)"
    [ -n "$hp" ] && echo "${hp##*:}" || echo 587
}

# ── HTTP ────────────────────────────────────────────────────────────────────
api() {
    local method="$1" path="$2"; shift 2
    curl -sS -m 20 -X "$method" \
         -H "Authorization: Bearer $API_KEY" \
         -H 'Content-Type: application/json' \
         "$@" "$API_BASE$path"
}

jqf() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

# ── Output ──────────────────────────────────────────────────────────────────
_pass=0; _fail=0
# stderr, so helpers can log while their stdout is captured by the caller.
info() { printf '\033[36m··\033[0m %s\n' "$*" >&2; }
pass() { _pass=$((_pass+1)); printf '\033[32mok\033[0m %s\n' "$*"; }
fail() { _fail=$((_fail+1)); printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; }
summary() {
    echo
    if [ "$_fail" -eq 0 ]; then
        printf '\033[32m%d passed, 0 failed\033[0m\n' "$_pass"; return 0
    fi
    printf '\033[31m%d passed, %d failed\033[0m\n' "$_pass" "$_fail"; return 1
}

# Poll until `cmd` succeeds or the deadline passes.
wait_for() {
    local desc="$1" timeout="$2"; shift 2
    local deadline=$(( SECONDS + timeout ))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "timed out after ${timeout}s waiting for: $desc" >&2
    return 1
}
