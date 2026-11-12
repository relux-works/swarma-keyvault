package namecoinwire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// The public counterpart's eight literal result/ack pairs prove byte-level
// correlation and exact stdout formatting, not protected SIGNED provenance.
func TestFrozenAcknowledgements(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				result := fixture(t, mode, slot+"-result.json")
				ack := fixture(t, mode, slot+"-ack.stdout")
				hash := sha256.Sum256(result)
				if !bytes.Equal(Acknowledgement(hash), ack) {
					t.Fatal("ack differs from frozen counterpart")
				}
				if err := VerifyAcknowledgement(ack, result); err != nil {
					t.Fatal("matching result refused", err)
				}
				changed := bytes.Clone(result)
				changed[len(changed)-1] ^= 1
				if !errors.Is(VerifyAcknowledgement(ack, changed), ErrInvalidRequest) ||
					!errors.Is(VerifyAcknowledgement(ack, nil), ErrInvalidRequest) {
					t.Fatal("ack admitted different or absent exact result bytes")
				}
			})
		}
	}
}

// The wrong-hash control remains valid ack syntax, so its intended rejection
// is a result-byte mismatch. The other frozen controls violate framing/schema.
func TestFrozenAcknowledgementRefusals(t *testing.T) {
	good := fixture(t, "all-four-before-release", "A-ack.stdout")
	result := fixture(t, "all-four-before-release", "A-result.json")
	if err := VerifyAcknowledgement(good, result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong-hash", "extra-field", "extra-line", "truncated"} {
		t.Run(name, func(t *testing.T) {
			raw := fixture(t, "bad-acks", name+".stdout")
			_, syntaxErr := DecodeAcknowledgement(raw)
			if name == "wrong-hash" && syntaxErr != nil {
				t.Fatal("hash control never reached correlation check", syntaxErr)
			}
			if name != "wrong-hash" && !errors.Is(syntaxErr, ErrInvalidRequest) {
				t.Fatal("malformed ack syntax admitted")
			}
			if !errors.Is(VerifyAcknowledgement(raw, result), ErrInvalidRequest) {
				t.Fatal("bad ack accepted")
			}
		})
	}
	for _, raw := range [][]byte{bytes.TrimSuffix(good, []byte{'\n'}), append(bytes.Clone(good), '\n'),
		bytes.Replace(good, []byte(`"SIGNED"`), []byte(`"UNKNOWN"`), 1),
		bytes.Replace(good, []byte(`"schema"`), []byte(`"Schema"`), 1)} {
		if _, err := DecodeAcknowledgement(raw); !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("noncanonical stdout admitted")
		}
	}
}

// Every frozen refusal code has an independent literal counterpart and exit
// class. Possible private effect must convert every code to UNKNOWN/exit1.
func TestFrozenErrorTableAndUncertainEffects(t *testing.T) {
	classes := map[int][]Code{
		2: {InvalidRequest, UnsupportedPSBT, UnsupportedScript},
		1: {AccountBusy, PresenceUnavailable, OutcomeUnknown, JournalUnavailable, OutputUnavailable},
		3: {DisplayRefused, AccountMismatch, PathRefused, PrevoutMismatch, IntentMismatch,
			SighashRefused, FeeRefused, RequestExpired, ReplayRefused, AuthRefused,
			AdoptionRequired, HelperNotAdmitted, PolicyRefused},
	}
	unknown := fixture(t, "errors", "outcome_unknown.stdout")
	for exit, codes := range classes {
		for _, code := range codes {
			t.Run(string(code), func(t *testing.T) {
				raw := fixture(t, "errors", string(code)+".stdout")
				f := NewFailure(code, false)
				if f.Exit() != exit || !bytes.Equal(f.Bytes(), raw) {
					t.Fatal("error differs from frozen code/exit table")
				}
				decoded, err := DecodeFailure(raw)
				if err != nil || decoded != f {
					t.Fatal("fixed error refused", err)
				}
				uncertain := NewFailure(code, true)
				if uncertain.Exit() != 1 || uncertain.Status() != "UNKNOWN" || !bytes.Equal(uncertain.Bytes(), unknown) {
					t.Fatal("possible private effect was downgraded to refusal")
				}
				changed := bytes.Replace(raw, []byte("Namecoin signing "), []byte("platform detail: "), 1)
				if _, err := DecodeFailure(changed); !errors.Is(err, ErrInvalidRequest) {
					t.Fatal("raw/platform error text admitted")
				}
			})
		}
	}
	for _, f := range []Failure{{}, NewFailure("foreign_code", false)} {
		if !bytes.Equal(f.Bytes(), unknown) || f.Exit() != 1 {
			t.Fatal("unknown internal failure did not fail closed")
		}
	}
}
