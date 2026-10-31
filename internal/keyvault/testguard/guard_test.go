package testguard

import "testing"

// Every non-empty value enables the gate; the empty value leaves explicit integration runs available.
func TestEnabled(t *testing.T) {
	for _, value := range []string{"", "1", "0", "false"} {
		t.Setenv(SkipEnv, value)
		if Enabled() != (value != "") {
			t.Fatalf("gate for %q", value)
		}
	}
}
