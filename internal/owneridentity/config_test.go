package owneridentity

import (
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

// Explicit owners, including historical Matrix localpart forms and supported
// DNS/IPv4/IPv6 server representations, retain the existing account grammar.
// This proves representation compatibility, not enrollment or authentication.
func TestExplicitOwnerConfiguration(t *testing.T) {
	for _, principal := range []string{"@owner:example.invalid", "@other:example.invalid:8448", "@Legacy.Owner:127.0.0.1", "@owner:[::1]:8448"} {
		c, err := New(principal, "north", ownerkey.GrantPurpose, 3)
		if err != nil || c.Principal != principal || c.Address.Service != "north" || c.Address.Version != 3 {
			t.Fatal("explicit supported owner refused", err)
		}
	}
	first, err := New("@owner:example.invalid", "north", ownerkey.GrantPurpose, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New("@other:example.invalid", "south", ownerkey.GrantPurpose, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.Principal == second.Principal || first.Address == second.Address {
		t.Fatal("configured owners collapsed")
	}
	for _, bad := range []Config{
		{}, {Principal: "@owner:example.invalid"}, {Address: first.Address},
		{Principal: "owner", Address: first.Address}, {Principal: "@owner:", Address: first.Address},
		{Principal: "@owner name:example.invalid", Address: first.Address},
		{Principal: "@owner:example.invalid\n", Address: first.Address},
	} {
		if err := bad.Validate(); err != ErrConfig {
			t.Fatal("missing/invalid owner received a default")
		}
	}
	for _, change := range []func(*signerclient.Address){
		func(a *signerclient.Address) { a.Kind = "secret" }, func(a *signerclient.Address) { a.Service = "" }, func(a *signerclient.Address) { a.Service = "bad/name" },
		func(a *signerclient.Address) { a.Purpose = "grants-owner-v2" }, func(a *signerclient.Address) { a.Purpose = "other" }, func(a *signerclient.Address) { a.Version = 0 }, func(a *signerclient.Address) { a.Version = 2147483648 },
	} {
		bad := first
		change(&bad.Address)
		if bad.Validate() != ErrConfig {
			t.Fatal("unsupported owner key admitted")
		}
	}
}
