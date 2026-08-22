#!/usr/bin/env bash
# Integration checks that only show up between separate processes.
#
# The unit suite runs everything in one process, where goroutines writing the
# same file are fast enough that an interleave rarely happens. Running real
# frank processes against one --output directory reproduced a corrupted
# report.json readily, so that case is checked here rather than pretended at
# with a goroutine.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

CGO_ENABLED=0 go build -o "$work/frank" . || exit 1

# A target that refuses instantly, so each run completes without the network.
target=127.0.0.1:1

concurrent_writes() {
	local out="$work/shared"
	rm -rf "$out"

	# A smoke pass over the real binary. The guarantee itself is asserted
	# structurally in report.TestArtefactsAreNeverTruncatedInPlace, because
	# racing writers catches the defect only most of the time and a check that
	# usually catches a defect is not a check.
	for i in $(seq 1 12); do
		"$work/frank" --dry-run --output "$out" probe \
			--target "$target" \
			--envelope-from "a$i@sender.example" \
			--helo frank.invalid \
			--header-from "a$i@sender.example" \
			--recipient rcpt@target.example </dev/null >/dev/null 2>&1 &
	done
	wait

	for name in report.json transcript.json; do
		if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out/$name" 2>/dev/null; then
			printf 'FAIL  %s is not parseable after concurrent runs\n' "$name"
			fail=1
			return
		fi
	done

	if [ "$(grep -c 'FRANK DELIVERABILITY REPORT' "$out/report.txt")" != "1" ]; then
		printf 'FAIL  report.txt carries more than one run, so two writers interleaved\n'
		fail=1
		return
	fi

	# A crashed or abandoned write must not leave its temporary file behind.
	if find "$out" -name '.*' -type f | grep -q .; then
		printf 'FAIL  a temporary file was left in the output directory\n'
		fail=1
		return
	fi

	printf 'ok    concurrent runs sharing one output directory leave parseable artefacts\n'
}

exit_codes() {
	local out="$work/codes"

	"$work/frank" --dry-run --output "$out" probe --target 192.0.2.1:25 \
		--envelope-from a@sender.example --helo frank.invalid \
		--header-from a@sender.example --recipient rcpt@target.example </dev/null >/dev/null 2>&1
	if [ $? -ne 2 ]; then
		printf 'FAIL  an unreachable target did not exit 2\n'
		fail=1
		return
	fi
	if [ ! -s "$out/transcript.txt" ]; then
		printf 'FAIL  an unreachable target left no transcript, but the spec requires a populated one\n'
		fail=1
		return
	fi

	echo '{ not json' >"$work/bad.json"
	"$work/frank" explain "$work/bad.json" </dev/null >/dev/null 2>&1
	if [ $? -ne 3 ]; then
		printf 'FAIL  unreadable explain input did not exit 3\n'
		fail=1
		return
	fi

	echo '{"targt":"x"}' >"$work/badcfg.json"
	"$work/frank" --config "$work/badcfg.json" auth --envelope-from a@b.example </dev/null >/dev/null 2>&1
	if [ $? -ne 3 ]; then
		printf 'FAIL  a mistyped config key did not exit 3\n'
		fail=1
		return
	fi

	printf 'ok    exit codes hold at the process boundary\n'
}

no_send_without_intent() {
	"$work/frank" probe --target "$target" \
		--envelope-from a@sender.example --helo frank.invalid \
		--header-from a@sender.example --recipient rcpt@target.example </dev/null >/dev/null 2>&1
	if [ $? -ne 3 ]; then
		printf 'FAIL  a run needing confirmation with no terminal did not refuse\n'
		fail=1
		return
	fi

	"$work/frank" --rate 600 --dry-run probe --target "$target" \
		--envelope-from a@sender.example --helo frank.invalid \
		--header-from a@sender.example --recipient rcpt@target.example </dev/null >/dev/null 2>&1
	if [ $? -ne 3 ]; then
		printf 'FAIL  a rate above the default was not refused\n'
		fail=1
		return
	fi

	printf 'ok    the safety gates refuse at the process boundary\n'
}

concurrent_writes
exit_codes
no_send_without_intent

exit "$fail"
