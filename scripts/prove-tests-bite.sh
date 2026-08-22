#!/usr/bin/env bash
# Proves each acceptance test can actually fail.
#
# A test that has only ever been seen to pass is not evidence: it might assert
# nothing. For each requirement below this breaks the code the test guards,
# runs just that test, and expects a FAILURE. Then it restores the file and
# expects a PASS. A requirement whose test passes while its code is broken is
# reported as NOT PINNED.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0

# mutate <id> <requirement> <file> <python-replacement> <test-regex> <package>
mutate() {
	local id=$1 requirement=$2 file=$3 script=$4 test=$5 pkg=$6
	local backup
	backup=$(mktemp)
	cp "$file" "$backup"

	python3 - "$file" <<PY
import sys
p = sys.argv[1]
s = open(p).read()
$script
open(p, 'w').write(s)
PY

	local broke_ok=1
	if CGO_ENABLED=1 go test -count=1 -run "$test" "$pkg" >/dev/null 2>&1; then
		broke_ok=0
	fi

	cp "$backup" "$file"
	rm -f "$backup"

	local restored_ok=1
	if ! CGO_ENABLED=1 go test -count=1 -run "$test" "$pkg" >/dev/null 2>&1; then
		restored_ok=0
	fi

	if [ "$broke_ok" -eq 1 ] && [ "$restored_ok" -eq 1 ]; then
		printf 'PINNED      %-6s %s\n' "$id" "$requirement"
		pass=$((pass + 1))
	elif [ "$broke_ok" -eq 0 ]; then
		printf 'NOT PINNED  %-6s %s (test passed with the code broken)\n' "$id" "$requirement"
		fail=$((fail + 1))
	else
		printf 'BROKEN      %-6s %s (test fails even when restored)\n' "$id" "$requirement"
		fail=$((fail + 1))
	fi
}

mutate 12.6 "matrix exits 1 on a rejected cell, 4 on inconclusive, 0 otherwise" \
	internal/cli/matrix.go \
	"s = s.replace('return CodeRejection', 'return CodeAcceptance')" \
	TestMatrixExitCodes ./internal/cli/

mutate 12.5 "a rate above the default is refused before any connection" \
	internal/cli/matrix.go \
	"s = s.replace('rate, err := gate.ResolveRate(ratePtr)', 'rate, err := gate.DefaultRatePerMinute, error(nil)')" \
	TestMatrixRateCannotBeRaised ./internal/cli/

mutate 13.5 "explain exits with the usage code on unreadable input" \
	internal/cli/explain.go \
	"s = s.replace('return nil, fmt.Errorf(\"the document carries no events\")', 'return tr, nil')" \
	TestExplainUnreadableInputExitsUsage ./internal/cli/

mutate 11.3 "credentials are read from the config file" \
	internal/cli/probe.go \
	"s = s.replace('if opts.File.Username != nil {', 'if false {')" \
	TestCredentialsFromConfigNeverFromAFlag ./internal/cli/

mutate 14.7 "one report combines every section a reader needs" \
	internal/report/report.go \
	"s = s.replace('fmt.Fprintln(&b, \"\\\\n== TRANSCRIPT ==\")', 'if false { fmt.Fprintln(&b, \"\") }')" \
	TestEndToEndReportAgainstDouble ./internal/cli/

mutate 14.2 "both renderings are always written, whatever --json says" \
	internal/report/report.go \
	"s = s.replace('jsonPath = filepath.Join(dir, \"report.json\")', 'jsonPath = filepath.Join(dir, \"report.json\"); return textPath, jsonPath, nil')" \
	TestJSONFlagChangesOnlyStdout ./internal/cli/

mutate 1.2 "every verb routes to its own handler" \
	internal/cli/cli.go \
	"s = s.replace('return probeCmd(opts, verbArgs, stdout, stderr)', 'return runAuth(opts, verbArgs, stdout, stderr)')" \
	TestEveryVerbRoutesToItsOwnHandler ./internal/cli/

mutate 1.5 "no third-party dependency is added" \
	go.mod \
	"s = s + '\nrequire github.com/miekg/dns v1.1.0\n'" \
	TestGoModHasNoThirdPartyRequirements ./internal/version/

mutate 1.4 "CI runs vet and the race detector" \
	.github/workflows/ci.yml \
	"s = s.replace('go test -race ./...', 'go test ./...')" \
	TestCIRunsVetAndRace ./internal/version/

printf '\n%d pinned, %d not pinned\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
