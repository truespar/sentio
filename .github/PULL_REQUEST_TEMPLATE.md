## What this changes

<!-- What the change does, and why. The reasoning matters more than the diff. -->

## How it was verified

<!-- Commands run, or the scenario exercised. "cargo test" alone is rarely enough
     for behaviour changes. -->

Nothing checks this for you - there is no hosted CI on this repository, so
these are the checks a reviewer will expect you to have run.

- [ ] `./scripts/check.sh` (fmt, clippy, tests, release build, cargo-deny,
      third-party notices, OpenAPI spec)
- [ ] `scripts/e2e/run-e2e.sh` (if mail flow, delivery, or the API changed)

## Checklist

- [ ] Added or updated tests
- [ ] Updated `README.md` / `docs/` if setup or configuration changed
- [ ] Regenerated `docs/openapi.json` if an API route changed
- [ ] Regenerated `THIRD-PARTY-NOTICES.md` if dependencies changed
- [ ] Regenerated `.sqlx/` if a `sqlx::query*!` macro changed
- [ ] New migration is additive; no already-released migration was edited
