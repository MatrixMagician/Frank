#!/usr/bin/env bash
# Verifies the acceptance ledger is honest.
#
# Three things, because the first two alone are not enough. A ledger pointing at
# a deleted test reads as evidence and is worse than no ledger. A ledger naming
# the wrong package hides where the check really lives. And a name that exists
# but never runs proves nothing.
#
# Note on `go test -run`: a pattern matching nothing still exits zero and prints
# "ok ... [no tests to run]". Confirming a test ran therefore means looking for
# its "--- PASS:" line, not the package's exit status.
set -uo pipefail
cd "$(dirname "$0")/.."

run_tests=${LEDGER_RUN_TESTS:-1}

missing=0
wrongpkg=0
notrun=0
checked=0

refs=$(awk -F'\t' 'NR>1 {print $5}' docs/acceptance.tsv |
	grep -oE '[a-z]+\.Test[A-Za-z0-9_]+' | sort -u)

if [ -z "$refs" ]; then
	echo "the ledger names no tests at all"
	exit 1
fi

# Every criterion must name at least one test.
while IFS=$'\t' read -r id issue criterion status test proven; do
	[ "$id" = "id" ] && continue
	if ! printf '%s' "$test" | grep -qE '\bTest[A-Za-z0-9_]+'; then
		printf 'NO TEST     %-6s %s\n' "$id" "$criterion"
		missing=$((missing + 1))
	fi
done < docs/acceptance.tsv

for ref in $refs; do
	checked=$((checked + 1))
	pkg=${ref%%.*}
	name=${ref#*.}

	# Look in the named package first: a test name can legitimately exist in
	# two packages, and a tree-wide `head -1` then picks whichever the
	# filesystem lists first, which differed between CI and local checkouts.
	location=$(grep -rl "^func ${name}(" "internal/${pkg}" --include='*_test.go' 2>/dev/null | head -1)
	[ -n "$location" ] || location=$(grep -rl "^func ${name}(" internal --include='*_test.go' 2>/dev/null | head -1)
	if [ -z "$location" ]; then
		printf 'STALE       %s does not exist\n' "$ref"
		missing=$((missing + 1))
		continue
	fi
	case "$location" in
	internal/"$pkg"/*) ;;
	*)
		printf 'WRONG PKG   %s actually lives in %s\n' "$ref" "$location"
		wrongpkg=$((wrongpkg + 1))
		continue
		;;
	esac

	[ "$run_tests" = "1" ] || continue

	# Captured rather than piped: `grep -q` exits on its first match, and the
	# resulting SIGPIPE on `go test` reads as a failure under `pipefail`, which
	# made every single test look like it had never run.
	output=$(CGO_ENABLED=1 go test -count=1 -v -run "^${name}$" "./internal/${pkg}/" 2>&1)
	case $output in
	*"--- PASS: ${name}"*) ;;
	*)
		printf 'NOT OBSERVED %s never emitted a PASS line\n' "$ref"
		notrun=$((notrun + 1))
		;;
	esac
done

printf '\n%d tests named, %d stale, %d in the wrong package, %d not observed passing\n' \
	"$checked" "$missing" "$wrongpkg" "$notrun"
[ "$((missing + wrongpkg + notrun))" -eq 0 ]
