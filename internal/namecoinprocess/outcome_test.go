package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func publicFile(t *testing.T, pkg, mode, leaf string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", pkg, "testdata", mode, leaf))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func publicContext(t *testing.T, mode, slot string) (RunnerContext, []byte, []byte) {
	t.Helper()
	raw := publicFile(t, "namecoinwire", mode, slot+"-request.json")
	s, err := namecoinwire.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Plan()
	// Explicit existing public fixture selection only. This is not a production
	// admission rule deriving authority from an untrusted manifest.
	selection := namecoinpsbt.Selection{Network: p.Network, Genesis: p.Genesis, Group: p.Group,
		Account: p.Account, AccountPinSHA256: p.AccountPinSHA256, Policy: p.Policy}
	if slot == "C" || slot == "D" {
		selection.RevealValuesPin = publicFile(t, "namecoinwire", mode, "trusted-reveal-values-pin.json")
	}
	a, err := namecoinpsbt.PrepareAttempt(raw, publicFile(t, "namecoinpsbt", mode, "account-pin.json"),
		selection, time.Unix(int64(p.Policy.CreatedAt)+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return RunnerContext{Mode: RunnerSign, Attempt: a},
		publicFile(t, "namecoinwire", mode, slot+"-result.json"),
		publicFile(t, "namecoinwire", mode, slot+"-ack.stdout")
}

func assertUnknown(t *testing.T, o Outcome) {
	t.Helper()
	f, err := namecoinwire.DecodeFailure(o.Line())
	exit, done := o.Exit()
	if !done || !o.Done() || o.Success() || err != nil || f.Code() != namecoinwire.OutcomeUnknown ||
		f.Status() != "UNKNOWN" || exit != 1 || len(o.Result()) != 0 || len(o.FinalTransaction()) != 0 || o.TxID() != "" {
		t.Fatalf("expected closed UNKNOWN without usable output, got done=%v exit=%d line=%s", done, exit, o.Line())
	}
}

// The eight unchanged Core fixtures reproduce their exact ACK and finalized
// witness bytes through existing public verification. No native proof is made.
func TestPublicResultVerification(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				c, result, ack := publicContext(t, mode, slot)
				o, err := verifyProcessResult(c, ack, result)
				if err != nil || !o.Success() || !bytes.Equal(o.Line(), ack) || !bytes.Equal(o.Result(), result) {
					t.Fatalf("valid result refused: %v", err)
				}
				final, err := hex.DecodeString(strings.TrimSpace(string(publicFile(t, "namecoinpsbt", mode, slot+"-final.hex"))))
				if err != nil || !bytes.Equal(final, o.FinalTransaction()) || o.TxID() != c.Attempt.Candidate().View().UnsignedTxID {
					t.Fatal("final transaction differs from independent Core output", err)
				}
				// Owned buffers cannot be changed through caller or accessor aliases.
				line, saved, tx := o.Line(), o.Result(), o.FinalTransaction()
				wantLine, wantResult := bytes.Clone(line), bytes.Clone(saved)
				line[0] ^= 255
				saved[0] ^= 255
				tx[0] ^= 255
				result[0] ^= 255
				ack[0] ^= 255
				if !bytes.Equal(o.Line(), wantLine) || !bytes.Equal(o.Result(), wantResult) || !bytes.Equal(o.FinalTransaction(), final) {
					t.Fatal("mutable outcome alias")
				}
			})
		}
	}
}

// Changed bindings/signatures and canonical transport violations must fail
// independently of their freshly recomputed outer ACK hash, beside a valid case.
func TestPublicResultRefusals(t *testing.T) {
	c, result, ack := publicContext(t, "all-four-before-release", "A")
	if _, err := verifyProcessResult(c, ack, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"review", "request", "pin", "receipt", "signature", "signed-map", "selection", "ack", "extra-line", "missing-lf"} {
		t.Run(name, func(t *testing.T) {
			context, raw, line := c, bytes.Clone(result), bytes.Clone(ack)
			var r namecoinwire.Result
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "review":
				r.Receipt.ReviewSHA256 = strings.Repeat("a", 64)
			case "request":
				r.Receipt.RequestID = strings.Repeat("a", 64)
			case "pin":
				r.Receipt.AccountPinSHA256 = strings.Repeat("a", 64)
			case "receipt":
				r.Receipt.InputSignatures[0].PublicKey = "02" + strings.Repeat("a", 64)
			case "signature":
				r.Receipt.InputSignatures[0].Signature = "3006020101020101"
			case "signed-map":
				psbt, err := base64.StdEncoding.DecodeString(r.SignedPSBT)
				if err != nil {
					t.Fatal(err)
				}
				psbt[len(psbt)-1] ^= 1
				r.SignedPSBT = base64.StdEncoding.EncodeToString(psbt)
				hash := sha256.Sum256(psbt)
				r.Receipt.SignedPSBTSHA256 = hex.EncodeToString(hash[:])
			case "selection":
				context, _, _ = publicContext(t, "all-four-before-release", "B")
			case "ack":
				line[1] ^= 1
			case "extra-line":
				line = append(line, '\n')
			case "missing-lf":
				line = line[:len(line)-1]
			}
			if name == "review" || name == "request" || name == "pin" || name == "receipt" || name == "signature" || name == "signed-map" {
				encoded, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(encoded, '\n')
				line = namecoinwire.Acknowledgement(sha256.Sum256(raw))
			}
			if _, err := verifyProcessResult(context, line, raw); err == nil {
				t.Fatal("known violation passed")
			}
		})
	}
}

// Valid whitespace-padded transport results reach the independent 6 MiB gate.
// This is a consumer limit witness, not a maximum canonical producer shape.
func TestProcessResultSizeBoundary(t *testing.T) {
	c, result, _ := publicContext(t, "all-four-before-release", "A")
	for _, size := range []int{MaxProcessResultBytes - 1, MaxProcessResultBytes, MaxProcessResultBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			raw := append(bytes.Repeat([]byte{' '}, size-len(result)), result...)
			if len(raw) != size {
				t.Fatal("control missed size predicate")
			}
			// The existing wire decoder and signature verifier accept all three;
			// rejection must come from the tighter independent process ceiling.
			if _, err := c.Attempt.Candidate().VerifyResult(raw, c.Attempt.ReviewDigest()); err != nil {
				t.Fatal("invalid size control", err)
			}
			o, err := verifyProcessResult(c, namecoinwire.Acknowledgement(sha256.Sum256(raw)), raw)
			if (err == nil) != (size <= MaxProcessResultBytes) || (err == nil && !o.Success()) {
				t.Fatal("wrong process size verdict", err)
			}
		})
	}
}

// The closed C5 table is independently transcribed from the accepted contract;
// matching a formatter alone is not the oracle for status/exit semantics.
func TestClosedRefusalOracle(t *testing.T) {
	for _, row := range refusalRows {
		f := namecoinwire.NewFailure(row.code, false)
		wantStatus := "REFUSED"
		if row.code == namecoinwire.OutcomeUnknown {
			wantStatus = "UNKNOWN"
		}
		if f.Status() != wantStatus || f.Exit() != row.exit {
			t.Fatalf("C5 mismatch for %s", row.code)
		}
		frozen := publicFile(t, "namecoinwire", "errors", string(row.code)+".stdout")
		if !bytes.Equal(f.Bytes(), frozen) {
			t.Fatalf("frozen refusal changed: %s", row.code)
		}
		parsed, err := namecoinwire.DecodeFailure(frozen)
		if err != nil || parsed.Code() != row.code {
			t.Fatal("closed codec refused frozen control", err)
		}
	}
	for _, bad := range [][]byte{[]byte("1"), []byte("auth_refused\n"), []byte("{\"no_effect\":true}\n")} {
		if _, err := namecoinwire.DecodeFailure(bad); err == nil {
			t.Fatal("unproven refusal admitted")
		}
	}
}

var refusalRows = []struct {
	code namecoinwire.Code
	exit int
}{
	{namecoinwire.InvalidRequest, 2}, {namecoinwire.UnsupportedPSBT, 2}, {namecoinwire.UnsupportedScript, 2},
	{namecoinwire.DisplayRefused, 3}, {namecoinwire.AccountMismatch, 3}, {namecoinwire.PathRefused, 3},
	{namecoinwire.PrevoutMismatch, 3}, {namecoinwire.IntentMismatch, 3}, {namecoinwire.SighashRefused, 3},
	{namecoinwire.FeeRefused, 3}, {namecoinwire.RequestExpired, 3}, {namecoinwire.ReplayRefused, 3},
	{namecoinwire.AccountBusy, 1}, {namecoinwire.AuthRefused, 3}, {namecoinwire.PresenceUnavailable, 1},
	{namecoinwire.AdoptionRequired, 3}, {namecoinwire.HelperNotAdmitted, 3}, {namecoinwire.PolicyRefused, 3},
	{namecoinwire.OutcomeUnknown, 1}, {namecoinwire.JournalUnavailable, 1}, {namecoinwire.OutputUnavailable, 1},
}

// Invalid/empty context and invalid transport deadlines cannot authorize start.
func TestRunnerConstructionRefusesEmptyContext(t *testing.T) {
	c, _, _ := publicContext(t, "all-four-before-release", "A")
	if _, err := NewRunner(c, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(RunnerContext{Mode: RunnerInitialize}, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, context := range []RunnerContext{{}, {Mode: RunnerSign}, {Mode: RunnerReconcile}, {Mode: RunnerInitialize, Attempt: c.Attempt}, {Mode: RunnerMode(255), Attempt: c.Attempt}} {
		_, err := NewRunner(context, time.Minute)
		var f namecoinwire.Failure
		if !errors.As(err, &f) || f.Code() != namecoinwire.InvalidRequest {
			t.Fatal("empty context authorized", err)
		}
	}
	for _, deadline := range []time.Duration{0, -1, time.Hour + 1} {
		if _, err := NewRunner(c, deadline); err == nil {
			t.Fatal("invalid deadline authorized")
		}
	}
}
