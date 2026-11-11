package ownerkey

import (
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// An admitted description for a short configured address may overflow the
// actual native reason with a longer address or generation. Never truncate.
func TestCompletePresenceReasonBudget(t *testing.T) {
	short := signerclient.Address{Kind: signerclient.KindKey, Service: "short", Purpose: GrantPurpose, Version: 1}
	long := short
	long.Service = strings.Repeat("a", 40)
	long.Version = 2147483647
	desc := strings.Repeat("x", 155)
	if err := CheckPresenceReason(short, desc); err != nil {
		t.Fatal("valid short address refused", err)
	}
	for _, tc := range []struct {
		address signerclient.Address
		reason  string
	}{{long, desc}, {short, "reason\nmore"}, {short, ""}} {
		if err := CheckPresenceReason(tc.address, tc.reason); err != ErrPresenceReason {
			t.Fatal("truncating or altered reason admitted", err)
		}
	}
}

// The review shows the supplied canonical service and exact generation;
// unsupported kind, service, purpose or latest-generation selector refuses.
func TestConfiguredOwnerDisplay(t *testing.T) {
	a := signerclient.Address{Kind: signerclient.KindKey, Service: "fixture-owner", Purpose: GrantPurpose, Version: 7}
	if got, err := Display(a); err != nil || got != "fixture-owner/grants-owner-v1 v7" {
		t.Fatal("unexpected configured key display", got, err)
	}
	for _, bad := range []signerclient.Address{
		{}, {Kind: signerclient.KindKey, Service: a.Service, Purpose: GrantPurpose, Version: 0},
		{Kind: signerclient.KindKey, Service: a.Service, Purpose: "grants-owner-v2", Version: 7},
		{Kind: signerclient.KindKey, Service: "bad/service", Purpose: GrantPurpose, Version: 7},
	} {
		if got, err := Display(bad); err != ErrAddress || got != "" {
			t.Fatal("noncanonical owner key displayed", err)
		}
	}
}

// The enrollment line carries the full address/generation and public DER hash.
// Reusing one DER at another configured address changes the trusted association.
func TestPublicPinBindsAddressAndDER(t *testing.T) {
	a := signerclient.Address{Kind: signerclient.KindKey, Service: "north", Purpose: GrantPurpose, Version: 7}
	first := PublicPin(a, []byte("public DER fixture"))
	if !strings.HasPrefix(first, "key/north/grants-owner-v1@7 sha256:") || !strings.HasSuffix(first, "\n") {
		t.Fatal("missing exact public address")
	}
	other := a
	other.Service = "south"
	if PublicPin(other, []byte("public DER fixture")) == first || PublicPin(a, []byte("other public DER fixture")) == first {
		t.Fatal("association ignored address or public key")
	}
	other = a
	other.Version++
	if PublicPin(other, []byte("public DER fixture")) == first {
		t.Fatal("association ignored generation")
	}
}
