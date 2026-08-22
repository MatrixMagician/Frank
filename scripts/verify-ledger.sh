#!/usr/bin/env bash
# Verifies the acceptance ledger is honest: every criterion names a test, and
# every test it names actually exists in the suite. A ledger that points at a
# renamed or deleted test is worse than no ledger, because it reads as evidence.
set -uo pipefail
cd "$(dirname "$0")/.."

missing=0
checked=0

while IFS=$'\t' read -r id issue criterion status test proven; do
	[ "$id" = "id" ] && continue

	if [ -z "$test" ] || [ "$test" = "MISSING" ]; then
		printf 'NO TEST     %-6s %s\n' "$id" "$criterion"
		missing=$((missing + 1))
		continue
	fi

	# A cell may name several tests, and may carry a parenthetical note.
	names=$(printf '%s' "$test" | grep -oE '\bTest[A-Za-z0-9_]+' || true)
	if [ -z "$names" ]; then
		# Rows that point at a script step rather than a Go test.
		continue
	fi

	for name in $names; do
		checked=$((checked + 1))
		if ! grep -rqE "^func ${name}\(" internal --include='*_test.go'; then
			printf 'STALE       %-6s names %s, which does not exist\n' "$id" "$name"
			missing=$((missing + 1))
		fi
	done
done < docs/acceptance.tsv

printf '\n%d test references checked, %d unresolved\n' "$checked" "$missing"
[ "$missing" -eq 0 ]
