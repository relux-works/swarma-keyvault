package grants

import (
	"testing"
)

// Claim: the receiver admits exactly the Source projection framing (one JSON
// object plus one LF) and refuses every other framing of the same valid record,
// including the leading-whitespace form that was admitted before. The positive
// control is the identical record with correct framing. Limit: whitespace
// between tokens inside the object is not framing and stays admitted; NB6
// does not require byte-compact JSON.
func TestA2AObservationRecordFraming(t *testing.T) {
	f, r, x, w, p := a2aObservedFixture(t, false)
	good := a2aObservedBytes(t, w, p)
	e, err := ParseA2AObservation(good, x)
	if err != nil {
		t.Fatal("exact Source framing refused", err)
	}
	if _, err := r.Verify(e, f.now); err != nil {
		t.Fatal("framed record does not verify", err)
	}
	record := good[:len(good)-1]
	for name, bad := range map[string][]byte{
		"no-terminal-lf":   record,
		"two-lf":           append(append([]byte{}, good...), '\n'),
		"crlf":             append(append([]byte{}, record...), '\r', '\n'),
		"leading-space":    append([]byte(" "), good...),
		"leading-lf":       append([]byte("\n"), good...),
		"old-lenient-form": append(append([]byte(" \n"), good...), '\n'),
		"trailing-space":   append(append([]byte{}, record...), ' ', '\n'),
		"trailing-tab":     append(append([]byte{}, record...), '\t', '\n'),
		"two-records":      append(append([]byte{}, good...), good...),
		"array-record":     append(append([]byte("["), record...), ']', '\n'),
		"lf-only":          []byte("\n"),
		"empty":            {},
	} {
		if _, err := ParseA2AObservation(bad, x); err == nil {
			t.Fatal("non-Source framing admitted", name)
		}
	}
}
