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
