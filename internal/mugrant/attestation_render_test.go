package mugrant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// Claim (R1, N2): the attestation rendering is read back from the body bytes
// and shows, for each kind, the subject key id, the subject fingerprint in
// the encoding mac-keyvault prints (checked against its own encoder), the
// window in UTC and in MSK, the content id and the full digest; the agent
// kind also shows the MXID and generation. A non-attestation plan refuses.
func TestAttestationRendering(t *testing.T) {
	_, root := testKey(t)
	k, subject := testKey(t)
	spki := spkiOf(t, k)
	nb, ex := time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC), time.Date(2027, 11, 6, 13, 0, 0, 0, time.UTC)
	agent, _, err := BuildMacAgentAttestation(root, spki, metaMXID, 3, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	publisher, _, err := BuildPublisherAttestation(root, spki, nb, ex)
	if err != nil {
		t.Fatal(err)
	}
	common := []string{
		"issuer: " + root,
		"subject key: " + subject,
		"subject key fingerprint (as mac-keyvault prints it): " + signerclient.Fingerprint(spki),
		"window UTC: 2026-11-05T13:00:00Z – 2027-11-06T13:00:00Z",
		"window MSK: 05.11.2026 16:00–06.11.2027 16:00 MSK",
	}
	for name, c := range map[string]struct {
		p     *Plan
		extra []string
	}{
		"agent":     {agent, []string{"agent: " + metaMXID, "generation: 3", "profile mac-se-1"}},
		"publisher": {publisher, []string{"profile grant-revocation-1"}},
	} {
		r, err := AttestationRendering(c.p)
		if err != nil {
			t.Fatal(name, err)
		}
		d := c.p.Digest()
		for _, want := range append(append(common, c.extra...), "content id: "+c.p.ContentID(), "signing digest: "+strings.ToLower(hexOf(d[:]))) {
			if !strings.Contains(r, want) {
				t.Error(name, "rendering misses", want)
			}
		}
		if name == "publisher" && strings.Contains(r, "agent: ") {
			t.Error("publisher rendering names an agent")
		}
	}
	if _, err := AttestationRendering(nil); !errors.Is(err, ErrAttestation) {
		t.Error("nil plan rendered")
	}
	g, err := BuildGrant(metaSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AttestationRendering(g.Plan()); !errors.Is(err, ErrAttestation) {
		t.Error("grant plan rendered as an attestation")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// Claim: the attestation window cap is exactly 366 days for both kinds:
// 366 days are admitted, one second more refuses.
func TestAttestationWindowEdge(t *testing.T) {
	_, root := testKey(t)
	k, _ := testKey(t)
	spki := spkiOf(t, k)
	nb := time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ex       time.Time
		admitted bool
	}{
		{time.Date(2027, 11, 6, 13, 0, 0, 0, time.UTC), true},  // exactly 366 days
		{time.Date(2027, 11, 6, 13, 0, 1, 0, time.UTC), false}, // one second more
	} {
		_, _, errA := BuildMacAgentAttestation(root, spki, metaMXID, 1, nb, c.ex)
		_, _, errP := BuildPublisherAttestation(root, spki, nb, c.ex)
		if (errA == nil) != c.admitted || (errP == nil) != c.admitted {
			t.Error("window edge", c.ex, errA, errP)
		}
	}
}
