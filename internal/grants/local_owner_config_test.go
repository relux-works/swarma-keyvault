package grants

import "testing"

// The compatibility fixture is explicit test configuration, not a runtime default.
const LocalOwnerMXID = "@fixture-owner:example.invalid"

// Independent enrollment selects the owner principal/pin. Certificates cannot
// cross to a different enrolled owner; absent/invalid principals never default.
func TestLocalEnrollmentExplicitOwner(t *testing.T) {
	for _, principal := range []string{LocalOwnerMXID, "@second:example.invalid"} {
		f := localTestFixture(t)
		f.config["owner_mxid"] = principal
		f.certificate["issuer"].(map[string]any)["owner_mxid"] = principal
		enrollment, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
		if err != nil {
			t.Fatal("configured owner refused", err)
		}
		cert, req := f.envelopes(t)
		if _, err := enrollment.Verify(cert, req, f.now); err != nil {
			t.Fatal("configured owner did not verify", err)
		}
		f.config["owner_mxid"] = "@other:example.invalid"
		other, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
		if err != nil {
			t.Fatal("other enrollment fixture", err)
		}
		if _, err := other.Verify(cert, req, f.now); err == nil {
			t.Fatal("certificate crossed enrolled owner")
		}
		for _, bad := range []string{"", "owner", "@owner:", "@owner:bad host"} {
			f.config["owner_mxid"] = bad
			if _, err := ParseLocalEnrollment(requestTestBytes(t, f.config)); err == nil {
				t.Fatal("missing or malformed owner defaulted")
			}
		}
	}
}
