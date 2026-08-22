package smtpconv

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/smtptest"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

const (
	testUsername = "probe@sender.example"
	testPassword = "correct-horse-battery-staple"
)

func authProbe(t *testing.T, srv *smtptest.Server, mode TLSMode, creds Credentials) *Result {
	t.Helper()
	pool := x509.NewCertPool()
	if cert := srv.Certificate(); cert != nil {
		pool.AddCert(cert)
	}
	return Run(Config{
		TargetHost: srv.Addr(),
		Identities: Identities{
			EnvelopeSender: NewEnvelopeSender("bounce@sender.example"),
			HeloIdentity:   "frank.invalid",
			HeaderFrom:     "author@sender.example",
		},
		Recipient:     "rcpt@target.example",
		DryRun:        true,
		TLSMode:       mode,
		TLSServerName: smtptest.CertHostname,
		TLSRootCAs:    pool,
		Credentials:   creds,
	})
}

func TestAuthMechanisms(t *testing.T) {
	for _, mech := range []string{"PLAIN", "LOGIN"} {
		t.Run(mech, func(t *testing.T) {
			srv := smtptest.Start(t,
				smtptest.WithSTARTTLS(),
				smtptest.WithAuthOverTLSOnly(),
				smtptest.WithExtensions("AUTH "+mech),
			)

			res := authProbe(t, srv, TLSRequire, Credentials{testUsername, testPassword})
			if res.Err != nil {
				t.Fatalf("probe failed: %v", res.Err)
			}

			creds := srv.Credentials()
			if len(creds) != 1 {
				t.Fatalf("server saw %d credentials, want 1", len(creds))
			}
			if creds[0].Mechanism != mech {
				t.Errorf("mechanism = %q, want %q", creds[0].Mechanism, mech)
			}
			if creds[0].Username != testUsername || creds[0].Password != testPassword {
				t.Errorf("server saw %q/%q, want %q/%q", creds[0].Username, creds[0].Password, testUsername, testPassword)
			}
			if !noteContains(res.Transcript, "authenticated with "+mech) {
				t.Error("the transcript does not record which mechanism authenticated")
			}
		})
	}
}

// TestAuthRefusedWithoutTLS is ADR-0007's rule. Frank refuses to authenticate
// in the clear whatever --tls says, because a host offering AUTH only in
// plaintext has a worse problem than the one Frank was called in to diagnose.
func TestAuthRefusedWithoutTLS(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithExtensions("AUTH PLAIN LOGIN"))

	res := authProbe(t, srv, TLSNone, Credentials{testUsername, testPassword})

	if res.Err == nil {
		t.Fatal("probe authenticated over a plaintext connection")
	}
	if !errors.Is(res.Err, ErrAuthWithoutTLS) {
		t.Errorf("err = %v, want ErrAuthWithoutTLS", res.Err)
	}
	if len(srv.Credentials()) != 0 {
		t.Error("credentials reached the server over a plaintext connection")
	}
	if !noteContains(res.Transcript, "not tls-protected") {
		t.Error("the transcript does not record why authentication was refused")
	}
}

// TestCredentialNeverReachesEitherRendering is why the redaction hook stops
// being decorative. The Transcript in memory is lossless and does contain the
// AUTH exchange; what must never carry the credential is either rendered
// artefact, because those are what reach disk.
func TestCredentialNeverReachesEitherRendering(t *testing.T) {
	for _, mech := range []string{"PLAIN", "LOGIN"} {
		t.Run(mech, func(t *testing.T) {
			srv := smtptest.Start(t,
				smtptest.WithSTARTTLS(),
				smtptest.WithAuthOverTLSOnly(),
				smtptest.WithExtensions("AUTH "+mech),
			)

			res := authProbe(t, srv, TLSRequire, Credentials{testUsername, testPassword})
			if res.Err != nil {
				t.Fatalf("probe failed: %v", res.Err)
			}

			redactor, err := transcript.NewRedactor(nil)
			if err != nil {
				t.Fatalf("NewRedactor: %v", err)
			}
			RegisterCredentials(redactor, Credentials{testUsername, testPassword})

			var text, jsonOut bytes.Buffer
			if err := transcript.RenderText(&text, res.Transcript, redactor); err != nil {
				t.Fatalf("RenderText: %v", err)
			}
			if err := transcript.RenderJSON(&jsonOut, res.Transcript, redactor); err != nil {
				t.Fatalf("RenderJSON: %v", err)
			}

			for name, out := range map[string]string{"text": text.String(), "json": jsonOut.String()} {
				if strings.Contains(out, testPassword) {
					t.Errorf("the %s rendering contains the password verbatim", name)
				}
				if strings.Contains(out, base64Of(testPassword)) {
					t.Errorf("the %s rendering contains the base64-encoded password", name)
				}
				if strings.Contains(out, base64Of("\x00"+testUsername+"\x00"+testPassword)) {
					t.Errorf("the %s rendering contains the encoded AUTH PLAIN payload", name)
				}
			}
		})
	}
}

func TestAdvertisedMechanismsRecordedAndUnsupportedReported(t *testing.T) {
	srv := smtptest.Start(t,
		smtptest.WithSTARTTLS(),
		smtptest.WithAuthOverTLSOnly(),
		smtptest.WithExtensions("AUTH CRAM-MD5 GSSAPI"),
	)

	res := authProbe(t, srv, TLSRequire, Credentials{testUsername, testPassword})

	if res.Err == nil {
		t.Fatal("probe authenticated with a mechanism Frank does not implement")
	}
	if !strings.Contains(res.Err.Error(), "CRAM-MD5") {
		t.Errorf("err = %v, want it to name what the target advertised", res.Err)
	}
	if !noteContains(res.Transcript, "advertised auth mechanisms: CRAM-MD5, GSSAPI") {
		t.Error("the transcript does not record the advertised mechanism list")
	}
}

func TestNoCredentialsMeansNoAuthAttempt(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS(), smtptest.WithExtensions("AUTH PLAIN"))

	res := authProbe(t, srv, TLSRequire, Credentials{})
	if res.Err != nil {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if len(srv.Credentials()) != 0 {
		t.Error("an AUTH exchange happened without credentials being configured")
	}
	for _, e := range res.Transcript.Events {
		if e.Phase == transcript.PhaseAuth {
			t.Errorf("an AUTH phase event exists without credentials: %q", e.Note)
		}
	}
}

func TestCredentialsFromEnv(t *testing.T) {
	t.Setenv(EnvUsername, testUsername)
	t.Setenv(EnvPassword, testPassword)

	got, ok := CredentialsFromEnv()
	if !ok {
		t.Fatal("CredentialsFromEnv reported nothing set")
	}
	if got.Username != testUsername || got.Password != testPassword {
		t.Errorf("got %q/%q, want %q/%q", got.Username, got.Password, testUsername, testPassword)
	}
}

func TestCredentialsAbsentFromEnvIsNotAnError(t *testing.T) {
	t.Setenv(EnvUsername, "")
	t.Setenv(EnvPassword, "")

	if _, ok := CredentialsFromEnv(); ok {
		t.Error("CredentialsFromEnv reported credentials with neither variable set")
	}
}

func TestAuthFailureIsRecordedAsAnOutcome(t *testing.T) {
	srv := smtptest.Start(t,
		smtptest.WithSTARTTLS(),
		smtptest.WithAuthOverTLSOnly(),
		smtptest.WithExtensions("AUTH PLAIN"),
		smtptest.Reject(smtptest.PhaseAuth, 535, "5.7.8", "authentication credentials invalid"),
	)

	res := authProbe(t, srv, TLSRequire, Credentials{testUsername, testPassword})

	if res.Outcome == nil {
		t.Fatal("a rejected AUTH produced no Outcome")
	}
	if res.Outcome.Phase() != transcript.PhaseAuth {
		t.Errorf("Outcome phase = %v, want auth", res.Outcome.Phase())
	}
	if res.Outcome.Reply().Code != 535 {
		t.Errorf("Outcome code = %d, want 535", res.Outcome.Reply().Code)
	}
}

func base64Of(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
