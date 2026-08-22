#!/usr/bin/env bash
# Checks the whole exit predicate for the 14-issue build in one command.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
step() {
	local name=$1
	shift
	if out=$("$@" 2>&1); then
		printf 'ok    %s\n' "$name"
	else
		printf 'FAIL  %s\n%s\n' "$name" "$out"
		fail=1
	fi
}

step "gofmt" bash -c '[ -z "$(gofmt -l .)" ] || { gofmt -l .; false; }'
step "build (cgo off)" env CGO_ENABLED=0 go build ./...
step "vet" env CGO_ENABLED=0 go vet ./...
step "static binary" bash -c 'CGO_ENABLED=0 go build -o /tmp/frank-predicate . && file /tmp/frank-predicate | grep -q "statically linked"'
step "no dependencies" bash -c '[ ! -s go.sum ]'
step "tests (race)" env CGO_ENABLED=1 go test -race ./...

# The name-and-package checks are instant; re-running all 85 named tests
# individually costs ~16s and the suite has just run them anyway, so that part
# is opt-in here and always on in CI.
step "ledger references resolve" env LEDGER_RUN_TESTS="${LEDGER_RUN_TESTS:-0}" ./scripts/verify-ledger.sh

echo
pending=$(awk -F'\t' 'NR>1 && $4!="done"' docs/acceptance.tsv | wc -l)
total=$(($(wc -l < docs/acceptance.tsv) - 1))
printf 'acceptance criteria: %d/%d done, %d pending\n' "$((total - pending))" "$total" "$pending"

open_issues=$(gh issue list --state open --limit 100 2>/dev/null | wc -l)
printf 'open issues: %d\n' "$open_issues"

if [ "$fail" -eq 0 ] && [ "$pending" -eq 0 ] && [ "$open_issues" -eq 0 ]; then
	echo "PREDICATE MET"
else
	echo "predicate not yet met"
fi
exit $fail
