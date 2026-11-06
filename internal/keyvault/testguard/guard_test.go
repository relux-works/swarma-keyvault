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

// Claim: Require skips exactly when the gate is set or the build has no real
// backend; with the gate unset on darwin with cgo it returns without skipping.
// Require itself never touches the Keychain, so the unset case is safe to run.
// Limit: one build per run; hosted Linux CI and a CGO_ENABLED=0 run cover the
// unsupported side.
func TestRequireSkipsWithoutRealBackend(t *testing.T) {
	for _, value := range []string{"", "1"} {
		t.Run("gate="+value, func(t *testing.T) {
			t.Setenv(SkipEnv, value)
			var skipped bool
			t.Run("require", func(t *testing.T) {
				defer func() { skipped = t.Skipped() }()
				Require(t)
			})
			if want := value != "" || !realBackend; skipped != want {
				t.Fatalf("skipped=%t, want %t (realBackend=%t)", skipped, want, realBackend)
			}
		})
	}
}
