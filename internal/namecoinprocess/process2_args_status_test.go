package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func process2ArgsFixture() []string {
	argv := argvFixture(SignPSBT)
	for i := 2; i < len(argv)-1; i += 2 {
		if argv[i] == "--process-contract" {
			argv[i+1] = "2"
		}
	}
	return argv
}

// Claim: contract/2 accepts only the existing closed sign-psbt vocabulary and
// derives the attempt binding from canonical selected arguments. Limit: parser
// and public hashes only; no file or helper identity is admitted here.
func TestParseProcess2ArgsAndAttemptBinding(t *testing.T) {
	argv := process2ArgsFixture()
	invocation, err := ParseProcess2Args(argv)
	if err != nil {
		t.Fatal("valid explicit process2 sign-psbt refused", err)
	}
	args := invocation.Args()
	if args.Mode != SignPSBT || args.Group != "fixture/recovery@1" || args.Account != "fixture/namecoin@1" || args.Timeout != time.Second {
		t.Fatal("process2 parser changed the selected public arguments")
	}
	profile, _ := hex.DecodeString(args.ProfileSHA256)
	request, _ := hex.DecodeString(args.RequestSHA256)
	var profileHash, requestHash [32]byte
	copy(profileHash[:], profile)
	copy(requestHash[:], request)
	inputs := Process2AttemptInputs{Mode: SignPSBT, Group: args.Group, Account: args.Account,
		ProfileSHA256: profileHash, OperationInputSHA256: requestHash}
	h := sha256.New()
	_, _ = h.Write([]byte("keyvault-namecoin-process-observation/1\x00"))
	for _, field := range [][]byte{[]byte("sign-psbt"), []byte(args.Group), []byte(args.Account), profile, request} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		_, _ = h.Write(n[:])
		_, _ = h.Write(field)
	}
	var want [32]byte
	copy(want[:], h.Sum(nil))
	if inputs.binding() != want {
		t.Fatal("attempt binding differs from the independent five-field construction")
	}
	inputs.Account = "fixture/other@1"
	if inputs.binding() == want {
		t.Fatal("attempt binding ignored an independently selected field")
	}
	copyArgv := invocation.Argv()
	copyArgv[1] = "reconcile"
	if got := invocation.Argv(); got[1] != "sign-psbt" {
		t.Fatal("invocation exposed mutable argv ownership")
	}
}

// Claim: process2 rejects process1 fallback, other modes, duplicate/unknown
// flags and malformed required values while retaining a nearby valid control.
func TestParseProcess2ArgsRefusesInvalidSelectorsAndFlags(t *testing.T) {
	good := process2ArgsFixture()
	controls := []struct {
		name string
		argv []string
	}{
		{"wrong-contract", replaceArg(good, "--process-contract", "1")},
		{"wrong-mode", func() []string { a := append([]string(nil), good...); a[1] = "reconcile"; return a }()},
		{"missing-contract", func() []string { a := append([]string(nil), good...); return append(a[:2], a[4:]...) }()},
		{"duplicate-contract", append(append([]string(nil), good...), "--process-contract", "2")},
		{"unknown-flag", append(append([]string(nil), good...), "--unexpected", "value")},
		{"missing-request-digest", func() []string {
			a := append([]string(nil), good...)
			for i := 2; i < len(a)-1; i += 2 {
				if a[i] == "--request-sha256" {
					return append(a[:i], a[i+2:]...)
				}
			}
			return a
		}()},
		{"noncanonical-timeout", replaceArg(good, "--timeout-seconds", "01")},
		{"bad-profile-hash", replaceArg(good, "--profile-sha256", strings.Repeat("A", 64))},
	}
	for _, test := range controls {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseProcess2Args(test.argv); !errors.Is(err, errInvalidProcess2) {
				t.Fatalf("invalid process2 args accepted: %v", err)
			}
		})
	}
}

// Claim: status-r3 encodes the fixed 80-byte frame and only accepts the exact
// ordered, attempt-bound two-frame success transcript with the result digest.
func TestProcess2StatusR3ExactSuccessAndForbiddenVariants(t *testing.T) {
	attempt := sha256.Sum256([]byte("public attempt"))
	result := []byte("public result fixture")
	digest := sha256.Sum256(result)
	started, err := EncodeProcess2StatusFrame(Process2StatusFrame{Event: Process2EffectStarted, AttemptBinding: attempt})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := EncodeProcess2StatusFrame(Process2StatusFrame{Event: Process2NativeCompleted, AttemptBinding: attempt, ResultSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	valid := append(bytes.Clone(started), completed...)
	if err := ValidateProcess2SuccessStatus(valid, attempt, result); err != nil {
		t.Fatal("valid status-r3 control refused", err)
	}
	mutants := map[string]func([]byte) []byte{
		"partial":    func(b []byte) []byte { return b[:len(b)-1] },
		"extra-byte": func(b []byte) []byte { return append(bytes.Clone(b), 0) },
		"reordered": func(b []byte) []byte {
			return append(bytes.Clone(b[Process2StatusFrameBytes:]), b[:Process2StatusFrameBytes]...)
		},
		"duplicate-start": func(b []byte) []byte {
			return append(bytes.Clone(b[:Process2StatusFrameBytes]), b[:Process2StatusFrameBytes]...)
		},
		"wrong-attempt":       func(b []byte) []byte { x := bytes.Clone(b); x[Process2StatusFrameBytes+8] ^= 1; return x },
		"wrong-result-digest": func(b []byte) []byte { x := bytes.Clone(b); x[Process2StatusFrameBytes+40] ^= 1; return x },
		"reserved-byte":       func(b []byte) []byte { x := bytes.Clone(b); x[7] = 1; return x },
		"wrong-version":       func(b []byte) []byte { x := bytes.Clone(b); x[5] = 2; return x },
		"unknown-event":       func(b []byte) []byte { x := bytes.Clone(b); x[6] = 3; return x },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			if err := ValidateProcess2SuccessStatus(mutate(valid), attempt, result); err == nil || !errors.Is(err, errInvalidProcess2Status) {
				t.Fatal("invalid status-r3 bytes accepted")
			}
		})
	}
	if _, err := EncodeProcess2StatusFrame(Process2StatusFrame{Event: Process2EffectStarted, AttemptBinding: attempt, ResultSHA256: digest}); !errors.Is(err, errInvalidProcess2Status) {
		t.Fatal("effect-started accepted a result digest")
	}
	if err := namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(digest), result); err != nil {
		t.Fatal("status test ACK control invalid", err)
	}
}
