package grants

import (
	"fmt"
	"strings"
	"testing"
)

// The verifier measurement records outcome metadata, never opaque receipt bytes.
func linuxVerifierOutcomeTelemetry(out *MUOutcome) string {
	if out == nil {
		return `outcome_present=false state="" receipt_present=false receipt_bytes=0`
	}
	return fmt.Sprintf("outcome_present=true state=%q receipt_present=%t receipt_bytes=%d", out.State, out.Receipt != nil, len(out.Receipt))
}

// Capture the exact formatter used by the timing test. Valid success, unknown,
// empty and absent outcomes preserve metadata without either raw or decimal
// receipt encodings. The original whole-outcome format is a bounded negative
// control; these synthetic bytes are not a journal or live receipt.
func TestLinuxVerifierReceiptTelemetry(t *testing.T) {
	payload := []byte("opaque-receipt-fixture-only")
	leaksPayload := func(s string) bool {
		return strings.Contains(s, string(payload)) || strings.Contains(s, fmt.Sprint(payload))
	}
	for _, tc := range []struct {
		name string
		out  *MUOutcome
		want string
	}{
		{"nil", nil, `outcome_present=false state="" receipt_present=false receipt_bytes=0`},
		{"unknown", &MUOutcome{State: "unknown"}, `outcome_present=true state="unknown" receipt_present=false receipt_bytes=0`},
		{"empty", &MUOutcome{State: "unknown", Receipt: []byte{}}, `outcome_present=true state="unknown" receipt_present=true receipt_bytes=0`},
		{"success", &MUOutcome{State: "succeeded", Receipt: payload}, fmt.Sprintf(`outcome_present=true state="succeeded" receipt_present=true receipt_bytes=%d`, len(payload))},
		{"unknown-with-receipt", &MUOutcome{State: "unknown", Receipt: payload}, fmt.Sprintf(`outcome_present=true state="unknown" receipt_present=true receipt_bytes=%d`, len(payload))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := fmt.Sprintf("%s", linuxVerifierOutcomeTelemetry(tc.out))
			if captured != tc.want || leaksPayload(captured) {
				t.Fatalf("receipt metadata boundary violated: got %q, want %q", captured, tc.want)
			}
		})
	}
	control := fmt.Sprintf("outcome=%v", &MUOutcome{State: "succeeded", Receipt: payload})
	if !leaksPayload(control) {
		t.Fatal("original whole-outcome control did not expose the known decimal receipt encoding")
	}
}
