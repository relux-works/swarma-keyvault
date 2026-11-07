package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Claim: Both projection ports require canonical payload encodings, preserving
// canonical bytes and refusing CR/LF even when a decoder would ignore them.
func TestProjectionBase64CanonicalCarriage(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$canonical-carriage")
	parsers := map[string]func([]byte, string, string) (MUEnvelopeEvent, error){
		"linux": ParseLinuxProjection,
		"mu":    ParseMUProjection,
	}
	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			good, err := parse(linuxProjectionBytes(t, linuxProjectionMap(e)), e.Room, e.EventID)
			if err != nil || !bytes.Equal(good.Text, e.Text) || !bytes.Equal(good.Envelope, e.Envelope) {
				t.Fatalf("canonical control: %v", err)
			}
			for _, field := range []string{"body_text_base64", "envelope_base64"} {
				for _, carriage := range []struct{ name, value string }{{"prefix-lf", "\n"}, {"interior-cr", "\r"}, {"suffix-crlf", "\r\n"}} {
					t.Run(field+"/"+carriage.name, func(t *testing.T) {
						m := linuxProjectionMap(e)
						value := m[field].(string)
						at := 0
						if carriage.name == "interior-cr" {
							at = len(value) / 2
						} else if carriage.name == "suffix-crlf" {
							at = len(value)
						}
						m[field] = value[:at] + carriage.value + value[at:]
						// A projection is JSON, so carriage is escaped inside its string.
						raw, err := json.Marshal(m)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := parse(append(raw, '\n'), e.Room, e.EventID); !errors.Is(err, ErrMUProjection) {
							t.Fatalf("noncanonical encoding admitted: %v", err)
						}
					})
				}
			}
		})
	}
}

// Claim: Noncanonical projection encoding refuses before verification, journal
// writes or effects; correcting only the encoding admits the same nonce once.
func TestLinuxProjectionBase64BeforeAdmission(t *testing.T) {
	for _, field := range []string{"body_text_base64", "envelope_base64"} {
		t.Run(field, func(t *testing.T) {
			g := newLinuxRig(t)
			e := g.event(t, "$carriage-admission")
			before := g.journal(t)
			m := linuxProjectionMap(e)
			m[field] = "\n" + m[field].(string)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			_, err = g.r.HandleProjection(context.Background(), append(raw, '\n'), e.Room, e.EventID)
			if !errors.Is(err, ErrMUProjection) || g.v.calls.Load() != 0 || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatalf("carriage refusal: err=%v verifier_calls=%d effects=%d journal_equal=%t", err, g.v.calls.Load(), g.calls.Load(), bytes.Equal(before, g.journal(t)))
			}
			g.reopen()
			canonical := linuxProjectionBytes(t, linuxProjectionMap(e))
			out, err := g.r.HandleProjection(context.Background(), canonical, e.Room, e.EventID)
			if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
				t.Fatalf("corrected encoding: out=%v err=%v effects=%d", out, err, g.calls.Load())
			}
			g.reopen()
			if _, err := g.r.HandleProjection(context.Background(), canonical, e.Room, e.EventID); err == nil || g.calls.Load() != 1 {
				t.Fatalf("replay: err=%v effects=%d", err, g.calls.Load())
			}
		})
	}
}
