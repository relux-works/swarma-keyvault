package mugrant

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Claim: the attestation Touch ID reasons name exactly the kind, the agent
// MXID and generation (agent only), the window in MSK and the last six digest
// bytes, in this fixed order; an MXID that makes the reason longer than the
// limit refuses instead of truncating, beside a valid one.
func TestAttestationReasons(t *testing.T) {
	_, root := testKey(t)
	k, _ := testKey(t)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nb, ex := time.Date(2026, 11, 5, 17, 0, 0, 0, time.UTC), time.Date(2027, 11, 6, 17, 0, 0, 0, time.UTC)
	const mxid = "@fixture-principal-7:example.invalid"
	p, _, err := BuildMacAgentAttestation(root, spki, mxid, 2, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Digest()
	r, err := MacAgentAttestationReason(p, mxid, 2, nb, ex)
	if want := fmt.Sprintf("ключ агента · %s · поколение 2 · 05.11.2026 20:00–06.11.2027 20:00 MSK · SHA256 %x", mxid, d[26:]); err != nil || r != want {
		t.Fatalf("agent reason %q %v", r, err)
	}
	pp, _, err := BuildPublisherAttestation(root, spki, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	pd := pp.Digest()
	r, err = PublisherAttestationReason(pp, nb, ex)
	if want := fmt.Sprintf("ключ отзыва грантов · 05.11.2026 20:00–06.11.2027 20:00 MSK · SHA256 %x", pd[26:]); err != nil || r != want {
		t.Fatalf("publisher reason %q %v", r, err)
	}
	long := "@" + strings.Repeat("a", 120) + ":gr.relux.works"
	lp, _, err := BuildMacAgentAttestation(root, spki, long, 1, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := MacAgentAttestationReason(lp, long, 1, nb, ex); !errors.Is(err, ErrReasonOverflow) || r != "" {
		t.Fatal("overlong reason admitted", r)
	}
}
