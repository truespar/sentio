#!/usr/bin/env bash
# Every check that has to pass before a change lands. Run this instead of
# relying on a hosted runner: the repo has no CI workflow, so this script is
# the gate.
#
#   ./scripts/check.sh              # everything
#   ./scripts/check.sh fmt clippy   # just those
#
# Needs a Rust toolchain, plus cargo-deny and cargo-about for the licence
# checks. Install the latter two with:
#
#   cargo install --locked cargo-deny
#   cargo install --locked --features cli --version 0.9.2 cargo-about
#
# cargo-about is pinned on purpose: a newer generator reformats the output, and
# the notices check is a diff against a committed file.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

# Builds read the committed .sqlx/ cache, so no database is needed.
export SQLX_OFFLINE=true

ABOUT_VERSION=0.9.2
failed=()
ran=()

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
head_() { printf '\n\033[36m== %s\033[0m\n' "$*"; }

# Runs a check, records the outcome, never aborts the script. Seeing all the
# failures in one pass beats fixing them one run at a time.
run() {
    local name="$1"; shift
    head_ "$name"
    ran+=("$name")
    if "$@"; then
        green "ok: $name"
    else
        red "FAILED: $name"
        failed+=("$name")
    fi
}

check_fmt()    { cargo fmt --all -- --check; }
check_clippy() { cargo clippy --workspace --all-targets -- -D warnings; }
check_test()   { cargo test --workspace; }
check_build()  { cargo build --release -p sentio-smtp -p sentio-mcp --bins; }

check_deny() {
    if ! command -v cargo-deny >/dev/null; then
        red "cargo-deny is not installed: cargo install --locked cargo-deny"
        return 1
    fi
    # Advisories included: this is what catches a RUSTSEC entry published
    # against a dependency that has not changed.
    cargo deny check
}

check_notices() {
    if ! command -v cargo-about >/dev/null; then
        red "cargo-about is not installed: cargo install --locked --features cli --version $ABOUT_VERSION cargo-about"
        return 1
    fi
    local have
    have="$(cargo about --version | awk '{print $2}')"
    if [ "$have" != "$ABOUT_VERSION" ]; then
        red "cargo-about $have is installed but the committed file was generated with $ABOUT_VERSION"
        return 1
    fi
    # tr: some licence texts carry CRLF, which .gitattributes strips on commit.
    # --workspace: releases ship sentio-mcp too, and without it the crawl
    # covers only the root package's dependencies.
    cargo about generate --fail --workspace about.hbs | tr -d '\r' > /tmp/sentio-notices.md
    if ! diff -u THIRD-PARTY-NOTICES.md /tmp/sentio-notices.md > /tmp/sentio-notices.diff; then
        red "THIRD-PARTY-NOTICES.md is stale. Regenerate with:"
        red "  cargo about generate --fail --workspace about.hbs | tr -d '\\r' > THIRD-PARTY-NOTICES.md"
        head -40 /tmp/sentio-notices.diff
        return 1
    fi
}

check_openapi() {
    cargo build --release -p sentio-smtp --bin sentio-smtp || return 1
    ./target/release/sentio-smtp openapi > /tmp/sentio-openapi.json || return 1
    if ! diff -u docs/openapi.json /tmp/sentio-openapi.json > /tmp/sentio-openapi.diff; then
        red "docs/openapi.json is stale. Regenerate with:"
        red "  cargo run -- openapi > docs/openapi.json"
        head -40 /tmp/sentio-openapi.diff
        return 1
    fi
}

ALL=(fmt clippy test build deny notices openapi)
targets=("${@:-${ALL[@]}}")

for t in "${targets[@]}"; do
    case "$t" in
        fmt|clippy|test|build|deny|notices|openapi) run "$t" "check_$t" ;;
        *) red "unknown check: $t (known: ${ALL[*]})"; exit 2 ;;
    esac
done

head_ "summary"
printf 'ran %d check(s): %s\n' "${#ran[@]}" "${ran[*]}"
if [ ${#failed[@]} -gt 0 ]; then
    red "${#failed[@]} failed: ${failed[*]}"
    exit 1
fi
green "all passed"

# The end-to-end harness is deliberately not part of this script: it needs a
# running stack. Bring one up and run it before anything that ships.
#
#   docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
#   scripts/e2e/run-e2e.sh
