//go:build darwin || linux

package registration_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Fixture configuration is public test data. Updating its public selection
// creates no native item, sidecar authority, signing permission or consent.
func processProfile(t *testing.T, mode, slot string, sel namecoinpsbt.Selection) []byte {
	t.Helper()
	phase := "reservation"
	if slot == "C" || slot == "D" {
		phase = "reveal"
	}
	raw := read(t, filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", "native-selection", mode+"-"+phase+".json"))
	config, err := namecoinpsbt.DecodeNativeSelection(raw)
	if err != nil {
		t.Fatal(err)
	}
	config.Selection = sel
	return jsonBytes(t, config)
}

func processArgs(t *testing.T, dir, mode, group, account string, profile, pin []byte, extra ...string) namecoinprocess.Args {
	t.Helper()
	profilePath, pinPath := filepath.Join(dir, "native-profile.json"), filepath.Join(dir, "native-pin.json")
	write(t, profilePath, profile)
	write(t, pinPath, pin)
	argv := []string{"namecoin", mode, "--process-contract", "1", "--group", group, "--account", account,
		"--profile", profilePath, "--profile-sha256", digest(profile), "--account-pin", pinPath,
		"--output", filepath.Join(dir, "absent-result.json"), "--timeout-seconds", "60"}
	a, err := namecoinprocess.ParseArgs(append(argv, extra...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Each actual-clock CLI emission docks into the accepted file-preparation API
// and single-attempt runner context, with no helper or protected store access.
func dockFreshProcess(t *testing.T, mode, slot, requestDir string, pin []byte, sel namecoinpsbt.Selection) {
	t.Helper()
	dir := freshDir(t)
	requestPath := filepath.Join(requestDir, "request.json")
	raw := read(t, requestPath)
	extra := []string{"--request", requestPath, "--request-sha256", digest(raw)}
	if slot == "C" || slot == "D" {
		reveal := filepath.Join(dir, "reveal-pin.json")
		write(t, reveal, sel.RevealValuesPin)
		extra = append(extra, "--reveal-values-pin", reveal)
	}
	a := processArgs(t, dir, "sign-psbt", sel.Group, sel.Account, processProfile(t, mode, slot, sel), pin, extra...)
	p, err := namecoinprocess.PrepareSigningFiles(a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.InputBytes(), raw) || !bytes.Equal(p.Attempt().ReviewFrame(), read(t, filepath.Join(requestDir, "review-frame.bin"))) {
		t.Fatal("process docking changed exact CLI request/frame")
	}
	if _, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerSign, Attempt: p.Attempt()}, a.Timeout); err != nil {
		t.Fatal(err)
	}
	a.RequestSHA256 = strings.Repeat("f", 64)
	empty, err := namecoinprocess.PrepareSigningFiles(a, time.Now())
	code(t, err, namecoinwire.InvalidRequest)
	if len(empty.InputBytes()) != 0 || len(empty.Attempt().Descriptor()) != 0 {
		t.Fatal("hash refusal retained partial attempt")
	}
	if _, err := os.Stat(a.OutputPath); err == nil {
		t.Fatal("public preparation created result")
	}
}

// A canonical public descriptor is a codec fixture, never claimed to have come
// from protected storage. This avoids calling fresh admission at a fake clock.
func historicalDescriptor(t *testing.T, request, pin []byte, sel namecoinpsbt.Selection) []byte {
	t.Helper()
	var req namecoinwire.Request
	decode(t, request, &req)
	raw := []byte("KVND1\x00")
	for _, b := range [][]byte{jsonBytes(t, req), pin, jsonBytes(t, sel)} {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(b)))
		raw = append(raw, b...)
	}
	if _, err := namecoinpsbt.DecodeAttempt(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// All eight genuine Core signatures still verify after expiry through the
// public reconcile context. Missing native completion stays UNKNOWN and emits
// no transaction, even with the correct ACK and modeled exit/reap observations.
// These reducer observations are policy fixtures, not native execution proof.
func TestRegistrationProcessHistoricalDocking(t *testing.T) {
	for _, mode := range modes {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				raw, pin := wireFixture(t, mode, slot+"-request.json"), psbtFixture(t, mode, "account-pin.json")
				s, c := publicCandidate(t, raw, pin)
				sel := selected(t, s.Plan(), pin)
				if slot == "C" || slot == "D" {
					sel.RevealValuesPin = wireFixture(t, mode, "trusted-reveal-values-pin.json")
				}
				if time.Now().Unix() <= int64(s.Request().ExpiresAt) {
					t.Fatal("fixture is not expired")
				}
				desc := historicalDescriptor(t, raw, pin, sel)
				dir := freshDir(t)
				query := filepath.Join(dir, "query.json")
				write(t, query, wireFixture(t, mode, slot+"-reconcile-query.json"))
				a := processArgs(t, dir, "reconcile", sel.Group, sel.Account, processProfile(t, mode, slot, sel), pin, "--query", query)
				input, err := namecoinprocess.PrepareReconcileFiles(a)
				if err != nil {
					t.Fatal(err)
				}
				p, err := input.WithDescriptor(desc)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := c.ReviewContext(sel)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := s.ReviewFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(p.Attempt().ReviewFrame(), expected) {
					t.Fatal("reconcile frame differs")
				}
				result, ack := wireFixture(t, mode, slot+"-result.json"), wireFixture(t, mode, slot+"-ack.stdout")
				if namecoinwire.VerifyAcknowledgement(ack, result) != nil {
					t.Fatal("Core ACK mismatch")
				}
				if _, err := p.Attempt().Candidate().VerifyResult(result, p.Attempt().ReviewDigest()); err != nil {
					t.Fatal(err)
				}
				r, err := namecoinprocess.NewRunner(namecoinprocess.RunnerContext{Mode: namecoinprocess.RunnerReconcile, Attempt: p.Attempt()}, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				events := []namecoinprocess.RunnerEvent{
					{Kind: namecoinprocess.RunnerBegin}, {Kind: namecoinprocess.RunnerStarted, Child: 7},
					{Kind: namecoinprocess.RunnerAdmitted, Child: 7}, {Kind: namecoinprocess.RunnerStdout, Child: 7, Data: ack},
					{Kind: namecoinprocess.RunnerEOF, Child: 7}, {Kind: namecoinprocess.RunnerExited, Child: 7, Normal: true, Exit: 0},
					{Kind: namecoinprocess.RunnerReaped, Child: 7},
				}
				for _, e := range events {
					actions, o := r.Step(e)
					if o.Done() || len(o.Result()) != 0 || len(o.FinalTransaction()) != 0 {
						t.Fatal("public ACK released an unauthenticated outcome")
					}
					for _, action := range actions {
						if action.Kind == namecoinprocess.RunnerReadResult {
							t.Fatal("public ACK requested unauthenticated readback")
						}
					}
				}
				r.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerTick, At: time.Minute})
				_, o := r.Step(namecoinprocess.RunnerEvent{Kind: namecoinprocess.RunnerClosed, At: time.Minute, OK: true})
				f, err := namecoinwire.DecodeFailure(o.Line())
				if err != nil || !o.Done() || o.Success() || f.Code() != namecoinwire.OutcomeUnknown || len(o.Result()) != 0 || len(o.FinalTransaction()) != 0 {
					t.Fatal("missing native completion was not UNKNOWN without bytes")
				}
				broken := append(bytes.Clone(desc), 0)
				empty, err := input.WithDescriptor(broken)
				code(t, err, namecoinwire.OutcomeUnknown)
				if len(empty.Attempt().Descriptor()) != 0 {
					t.Fatal("corrupt descriptor retained partial context")
				}
				q := input.Query()
				q.RequestID = strings.Repeat("f", 64)
				write(t, query, jsonBytes(t, q))
				wrong, err := namecoinprocess.PrepareReconcileFiles(a)
				if err != nil {
					t.Fatal(err)
				}
				_, err = wrong.WithDescriptor(desc)
				code(t, err, namecoinwire.IntentMismatch)
				if _, err := os.Stat(a.OutputPath); err == nil {
					t.Fatal("reconcile preparation created output")
				}
			})
		}
	}
}
