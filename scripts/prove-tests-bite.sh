#!/usr/bin/env bash
# Proves each acceptance test can actually fail.
#
# A test that has only ever been seen to pass is not evidence: it might assert
# nothing. For each requirement below this breaks the code the test guards,
# runs just that test, and expects a FAILURE. Then it restores the file and
# expects a PASS. A requirement whose test passes while its code is broken is
# reported as NOT PINNED.
#
# The mutations are chosen to be genuinely load-bearing: each removes or
# inverts the behaviour the criterion is about, not an adjacent detail. Where
# an ADR warns that a line looks removable but is not, the mutation removes
# exactly that line, so the ADR's claim is re-checked on every run.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
only=${1:-}

# mutate <id> <requirement> <file> <python-replacement> <test-regex> <package>
mutate() {
	local id=$1 requirement=$2 file=$3 script=$4 test=$5 pkg=$6

	if [ -n "$only" ] && [[ $id != $only* ]]; then
		return
	fi

	local backup
	backup=$(mktemp)
	cp "$file" "$backup"

	python3 - "$file" <<PY
import sys
p = sys.argv[1]
s = open(p).read()
before = s
$script
if s == before:
    sys.stderr.write("mutation did not apply\n")
    sys.exit(1)
open(p, 'w').write(s)
PY
	local applied=$?

	local broke_ok=1
	if [ "$applied" -ne 0 ]; then
		broke_ok=2
	elif CGO_ENABLED=1 go test -count=1 -run "$test" "$pkg" >/dev/null 2>&1; then
		broke_ok=0
	fi

	cp "$backup" "$file"
	rm -f "$backup"

	local restored_ok=1
	if ! CGO_ENABLED=1 go test -count=1 -run "$test" "$pkg" >/dev/null 2>&1; then
		restored_ok=0
	fi

	if [ "$broke_ok" -eq 2 ]; then
		printf 'STALE       %-6s %s (the mutation no longer matches the source)\n' "$id" "$requirement"
		fail=$((fail + 1))
	elif [ "$broke_ok" -eq 1 ] && [ "$restored_ok" -eq 1 ]; then
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

# --- issue 1: skeleton, routing, CI ---------------------------------------

mutate 1.2 "every verb routes to its own handler" \
	internal/cli/cli.go \
	"s = s.replace('return probeCmd(opts, verbArgs, stdout, stderr)', 'return runAuth(opts, verbArgs, stdout, stderr)')" \
	TestEveryVerbRoutesToItsOwnHandler ./internal/cli/

mutate 1.3 "an explicitly-set flag is distinguishable from an absent one" \
	internal/cli/cli.go \
	"s = s.replace('opts.Explicit[f.Name] = true', '_ = f')" \
	TestExplicitFlagsDistinguishZeroFromAbsent ./internal/cli/

mutate 1.4 "CI runs vet and the race detector" \
	.github/workflows/ci.yml \
	"s = s.replace('go test -race ./...', 'go test ./...')" \
	TestCIRunsVetAndRace ./internal/version/

mutate 1.5 "no third-party dependency is added" \
	go.mod \
	"s = s + '\nrequire github.com/miekg/dns v1.1.0\n'" \
	TestGoModHasNoThirdPartyRequirements ./internal/version/

# --- issue 2: the transcript spine ----------------------------------------

mutate 2.2 "a multiline reply is parsed as one reply" \
	internal/transcript/reply.go \
	"s = s.replace('isLast := sep == \\' \\'', 'isLast := true')" \
	TestParseReplyMultilineContinuation ./internal/transcript/

mutate 2.3 "every event carries both clocks" \
	internal/transcript/transcript.go \
	"s = s.replace('Monotonic: time.Since(t.Start),', 'Monotonic: 0,')" \
	TestEveryEventCarriesBothClocksAndOrderIsMonotonic ./internal/transcript/

mutate 2.4 "redaction masks matches in both renderings" \
	internal/transcript/redact.go \
	"s = s.replace('return redactionMask', 'return match')" \
	TestRedactMasksInBothRenderings ./internal/transcript/

mutate 2.6 "rendering never mutates the transcript" \
	internal/transcript/render.go \
	"s = s.replace('Raw:       p.mask(rawToLatin1(e.Raw)),', 'Raw: func() string { e.Raw = []byte(p.mask(rawToLatin1(e.Raw))); return string(e.Raw) }(),')" \
	TestRenderingLeavesTranscriptUnchanged ./internal/transcript/

# --- issue 3: the test double ---------------------------------------------

mutate 3.4 "the double rejects only the named identity triple" \
	internal/smtptest/rules.go \
	"s = s.replace('return want != ObservedTriple{}', 'return false')" \
	TestRejectsNamedIdentityTripleAcceptsOthers ./internal/smtptest/

mutate 3.5 "greylisting defers the first connection and accepts a later one" \
	internal/smtptest/rules.go \
	"s = s.replace('return s.Ordinal <= nth', 'return false')" \
	TestGreylistDefersFirstConnectionAcceptsSecond ./internal/smtptest/

# --- issue 4: the controlled conversation ---------------------------------

mutate 4.2 "the three identities reach the wire verbatim" \
	internal/smtpconv/conv.go \
	"s = s.replace('\\\"MAIL FROM:\\\"+cfg.Triple.EnvelopeSender.mailFromArg()', '\\\"MAIL FROM:<redacted@example.com>\\\"')" \
	TestMismatchedIdentitiesAppearVerbatimAtCorrectPhases ./internal/smtpconv/

mutate 4.3 "EHLO falls back to HELO and the fallback is recorded" \
	internal/smtpconv/conv.go \
	"s = s.replace('return verb(tr, res, conn, reader, transcript.PhaseEHLO, \\\"HELO \\\"+helo)', 'return reply, true')" \
	TestEHLOFallsBackToHELOAndRecordsIt ./internal/smtpconv/

mutate 4.5 "a body line beginning with a dot is stuffed" \
	internal/smtpconv/message.go \
	"s = s.replace(\"b.WriteByte('.')\", '')" \
	TestDotStuffingAndTermination ./internal/smtpconv/

mutate 4.6 "DATA and end-of-data are separate phases" \
	internal/smtpconv/conv.go \
	"s = s.replace('res.Outcome = mustOutcome(transcript.PhaseEndOfData, *reply)', 'res.Outcome = mustOutcome(transcript.PhaseData, *reply)')" \
	TestDataAndEndOfDataAreSeparatePhases ./internal/smtpconv/

mutate 4.8 "QUIT is sent on every exit path" \
	internal/smtpconv/conv.go \
	"s = s.replace('quit(tr, res, conn, reader)', '_ = quit')" \
	TestQuitOnEveryExitPathIncludingErrors ./internal/smtpconv/

# --- issue 5: TLS captured, not trusted -----------------------------------

mutate 5.1 "tls=require aborts when STARTTLS is unavailable" \
	internal/smtpconv/conv.go \
	"s = s.replace('res.Err = fmt.Errorf(\\\"smtpconv: starttls required but the target does not advertise it\\\")', '_ = cfg')" \
	TestTLSModePolicy ./internal/smtpconv/

mutate 5.4 "tls-verify aborts but the chain is still captured" \
	internal/smtpconv/tls.go \
	"s = s.replace('if verifyErr != nil && cfg.TLSVerify {', 'if false {')" \
	TestSelfSignedAbortsWithVerifyEnabledAndKeepsChain ./internal/smtpconv/

mutate 5.5 "session tickets stay disabled so the chain is captured every time" \
	internal/smtpconv/tls.go \
	"s = s.replace('sessionTicketsDisabled := true', 'sessionTicketsDisabled := false')" \
	TestStartTLSDisablesSessionResumption ./internal/smtpconv/

mutate 5.6 "the server name used for verification is explicit and recorded" \
	internal/smtpconv/tls.go \
	"s = s.replace('ServerName:         serverName,', 'ServerName:         \\\"\\\",')" \
	TestServerNameIsExplicitAndRecorded ./internal/smtpconv/

# --- issue 6: send gating and rate limiting -------------------------------

mutate 6.3 "confirm-send with dry-run is a usage error" \
	internal/gate/gate.go \
	"s = s.replace('return Decision{}, ErrConfirmSendWithDryRun', 'return Decision{Disposition: DispositionDryRun}, nil')" \
	TestConfirmSendWithDryRunIsUsageError ./internal/gate/

mutate 6.4 "a run needing confirmation with no terminal errors" \
	internal/gate/gate.go \
	"s = s.replace('return Decision{}, ErrConfirmationNeedsTerminal', 'return Decision{Disposition: DispositionDryRun}, nil')" \
	TestConfirmationWithoutTTYIsAnErrorNotAPrompt ./internal/gate/

mutate 6.5 "the rate limiter defaults to six per minute" \
	internal/gate/rate.go \
	"s = s.replace('const DefaultRatePerMinute = 6', 'const DefaultRatePerMinute = 60')" \
	TestDefaultRateIsSixPerMinute ./internal/gate/

mutate 6.6 "a rate above the default is refused, not clamped" \
	internal/gate/rate.go \
	"s = s.replace('if *requested > DefaultRatePerMinute {', 'if false {')" \
	TestRateAboveDefaultIsRefused ./internal/gate/

mutate 6.7 "repeated deferrals back off and then abort" \
	internal/gate/rate.go \
	"s = s.replace('if attempt > cfg.Threshold {', 'if false {')" \
	TestBackoffAbortsPastThreshold ./internal/gate/

# --- issue 7: the resolver seam -------------------------------------------

mutate 7.3 "a multi-string TXT record arrives concatenated" \
	internal/resolve/fixture.go \
	"s = s.replace(\"strings.Join(parts, '')\", \"strings.Join(parts, ' ')\").replace('strings.Join(parts, \\\"\\\")', 'strings.Join(parts, \\\" \\\")')" \
	TestFixtureMultiStringTXTArrivesConcatenated ./internal/resolve/

mutate 7.4 "NXDOMAIN and NODATA are distinguishable" \
	internal/resolve/fixture.go \
	"s = s.replace('Kind: KindNoRecords', 'Kind: KindNotFound')" \
	TestNotFoundAndNoRecordsAreDistinguishable ./internal/resolve/

mutate 7.6 "the suite cannot reach real DNS" \
	internal/resolve/system.go \
	"s = s.replace('Dial: dialDNS}', '}')" \
	TestForbidNetworkAlsoBlocksTheSystemResolver ./internal/resolve/

# --- issue 8: SPF ----------------------------------------------------------

mutate 8.3 "an over-limit record is reported as a record defect" \
	internal/spf/eval.go \
	"s = s.replace('Kind:    DefectLookupLimitExceeded,', 'Kind:    DefectKind(99),')" \
	TestLookupLimitExceededIsARecordDefect ./internal/spf/

mutate 8.4 "addresses are normalised before matching (ADR-0006)" \
	internal/spf/spf.go \
	"s = s.replace('addr: addr.Unmap()', 'addr: addr')" \
	TestAddressNormalisedBeforeMatching ./internal/spf/

mutate 8.5 "an address carrying a zone is rejected" \
	internal/spf/spf.go \
	"s = s.replace('if addr.Zone() != \\\"\\\" {', 'if false {')" \
	TestZonedAddressRejected ./internal/spf/

mutate 8.8 "auth opens no tcp connection" \
	internal/cli/auth.go \
	"s = s.replace('\"net/netip\"', '\"net\"\\n\\t\"net/netip\"').replace('res, err := spf.Evaluate(ctx, r, req)', 'if c, e := net.Dial(\"tcp\", a.helo); e == nil { c.Close() }\\n\\t\\tres, err := spf.Evaluate(ctx, r, req)')" \
	TestAuthOpensNoTCPConnection ./internal/cli/

# --- issue 9: DKIM ---------------------------------------------------------

mutate 9.2 "a revoked key is reported as a fault" \
	internal/dkim/parse.go \
	"s = s.replace('FaultRevoked', 'FaultNone', 1)" \
	TestKeyFaultsReported ./internal/dkim/

mutate 9.6 "discovery query volume is bounded and the bound is stated" \
	internal/dkim/discover.go \
	"s = s.replace('if res.QueriesMade >= bound {', 'if false {')" \
	TestDiscoveryQueryVolumeBoundedAndStated ./internal/dkim/

# --- issue 10: DMARC -------------------------------------------------------

mutate 10.2 "alignment is computed in both relaxed and strict modes" \
	internal/dmarc/align.go \
	"s = s.replace('a.Strict = strings.EqualFold(authenticated, headerFrom)', 'a.Strict = a.Relaxed')" \
	TestAlignment ./internal/dmarc/

mutate 10.4 "the sampling rate is reported, never applied" \
	internal/dmarc/align.go \
	"s = s.replace('if policy.Pct < 100 {', 'if false {')" \
	TestSamplingRateReportedNotApplied ./internal/dmarc/

# --- issue 11: SMTP AUTH ---------------------------------------------------

mutate 11.2 "AUTH is refused over a plaintext connection (ADR-0007)" \
	internal/smtpconv/auth.go \
	"s = s.replace('if !overTLS {', 'if false {')" \
	TestAuthRefusedWithoutTLS ./internal/smtpconv/

mutate 11.3 "credentials are read from the config file" \
	internal/cli/probe.go \
	"s = s.replace('if opts.File.Username != nil {', 'if false {')" \
	TestCredentialsFromConfigNeverFromAFlag ./internal/cli/

mutate 11.4 "a credential never reaches either rendering" \
	internal/smtpconv/auth.go \
	"s = s.replace('r.AddLiteral(base64.StdEncoding.EncodeToString([]byte(creds.Password)))', '')" \
	TestCredentialNeverReachesEitherRendering ./internal/smtpconv/

# --- issue 12: the matrix --------------------------------------------------

mutate 12.1 "the rejected triple is isolated from the accepted ones" \
	internal/matrix/matrix.go \
	"s = s.replace('sawRejection = true', 'sawRejection = false')" \
	TestRejectedTripleIsolated ./internal/matrix/

mutate 12.2 "a fresh connection per cell (ADR-0003)" \
	internal/matrix/run.go \
	"s = s.replace('for _, cell := range m.Cells {', 'for ci, cell := range m.Cells { if ci > 0 { cell.reached = true; cell.Probes = m.Cells[0].Probes; continue }')" \
	TestFreshConnectionPerCell ./internal/matrix/

mutate 12.4 "an unrun cell is distinct from an inconclusive one" \
	internal/matrix/matrix.go \
	"s = s.replace('if !c.reached {\n\t\treturn Unrun\n\t}', '')" \
	TestAbortedSweepLeavesUnrunCellsRenderedDistinctly ./internal/matrix/

mutate 12.5 "a rate above the default is refused before any connection" \
	internal/cli/matrix.go \
	"s = s.replace('rate, err := gate.ResolveRate(ratePtr)', 'rate, err := gate.DefaultRatePerMinute, error(nil)')" \
	TestMatrixRateCannotBeRaised ./internal/cli/

mutate 12.6 "matrix exits 1 on a rejected cell, 4 on inconclusive, 0 otherwise" \
	internal/cli/matrix.go \
	"s = s.replace('return CodeRejection', 'return CodeAcceptance')" \
	TestMatrixExitCodes ./internal/cli/

# --- issue 13: explain -----------------------------------------------------

mutate 13.2 "observed outcomes and computed verdicts stay distinguishable" \
	internal/explain/explain.go \
	"s = s.replace('return \\\"observed: \\\" + e.Text', 'return e.Text')" \
	TestObservedAndComputedAreDistinguishable ./internal/explain/

mutate 13.3 "an ambiguous case names the disambiguating probe" \
	internal/explain/diagnose.go \
	"s = s.replace('NextProbe:  \\\"probe again varying one identity slot at a time, or run frank matrix to find the boundary\\\",', '')" \
	TestAmbiguousCaseNamesDisambiguatingProbe ./internal/explain/

mutate 13.5 "explain exits with the usage code on unreadable input" \
	internal/cli/explain.go \
	"s = s.replace('return nil, fmt.Errorf(\\\"the document carries no events\\\")', 'return tr, nil')" \
	TestExplainUnreadableInputExitsUsage ./internal/cli/

mutate 13.6 "no diagnosis ever claims delivery" \
	internal/explain/diagnose.go \
	"s = s.replace('which establishes that it took responsibility for it and not that it was delivered', 'which means the message was delivered')" \
	TestNoDiagnosisClaimsDelivery ./internal/explain/

# --- issue 14: config and the combined report ------------------------------

mutate 14.2 "both renderings are always written, whatever --json says" \
	internal/report/report.go \
	"s = s.replace('jsonPath = filepath.Join(dir, \\\"report.json\\\")', 'jsonPath = filepath.Join(dir, \\\"report.json\\\"); return textPath, jsonPath, nil')" \
	TestJSONFlagChangesOnlyStdout ./internal/cli/

mutate 14.4 "a mistyped config key is an error naming the key" \
	internal/report/config.go \
	"s = s.replace('dec.DisallowUnknownFields()', '')" \
	TestUnknownConfigKeyIsErrorNamingKey ./internal/report/

mutate 14.5 "a key set to zero is distinguishable from an absent key (ADR-0005)" \
	internal/report/config.go \
	"s = s.replace('Rate         *int     ' + chr(96) + 'json:\\\"rate,omitempty\\\"' + chr(96), 'Rate         int      ' + chr(96) + 'json:\\\"rate,omitempty\\\"' + chr(96)).replace('if set.Rate == nil', 'if false').replace('*set.Rate', 'set.Rate')" \
	TestZeroValueDistinctFromAbsent ./internal/report/

mutate 14.6 "an explicit flag beats a config value" \
	internal/report/config.go \
	"s = s.replace('func StringOr(explicit bool, flagValue string, configValue *string) string {\n\tif explicit {', 'func StringOr(explicit bool, flagValue string, configValue *string) string {\n\tif false {')" \
	TestExplicitFlagBeatsConfigValue ./internal/report/

mutate 14.7 "one report combines every section a reader needs" \
	internal/report/report.go \
	"s = s.replace('fmt.Fprintln(&b, \\\"\\\\n== TRANSCRIPT ==\\\")', 'if false { fmt.Fprintln(&b, \\\"\\\") }')" \
	TestEndToEndReportAgainstDouble ./internal/cli/

mutate 14.8 "artefacts are replaced by a rename, never truncated in place" \
	internal/report/atomic.go \
	"s = s.replace('tmp, err := os.CreateTemp(dir, \".\"+filepath.Base(path)+\".*\")', '_ = dir; tmp, err := os.Create(path)').replace('if err := os.Rename(tmpName, path); err != nil {', 'if false {')" \
	TestArtefactsAreNeverTruncatedInPlace ./internal/report/

printf '\n%d pinned, %d not pinned\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
