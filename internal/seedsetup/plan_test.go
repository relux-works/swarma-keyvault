package seedsetup

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// The public plan may select omitted generations, but cannot substitute either
// identity, an explicit generation, an address or the advisory schema/flag.
func TestPublicPlanBinding(t *testing.T) {
	c := Config{NostrIdentity: "north", NamecoinIdentity: "south"}
	want := publicTarget{"north", "south", 3, 5, 7}
	p := publicPlan{"keyvault-recovery-plan/1", true, "north", "south", 3, 5, 7, want.group(), want.nostr(), want.namecoin()}
	raw, _ := json.Marshal(p)
	if got, err := acceptPlan(raw, c); err != nil || got != want {
		t.Fatal("valid advisory plan refused", err)
	}
	c.Version, c.NostrVersion, c.NamecoinVersion = 3, 5, 7
	if got, err := acceptPlan(raw, c); err != nil || got != want {
		t.Fatal("valid explicit plan refused", err)
	}
	for _, change := range []func(*publicPlan){
		func(p *publicPlan) { p.NostrIdentity = "south" }, func(p *publicPlan) { p.NamecoinIdentity = "north" },
		func(p *publicPlan) { p.Version++ }, func(p *publicPlan) { p.NostrVersion++ }, func(p *publicPlan) { p.NamecoinVersion++ },
		func(p *publicPlan) { p.Group = "other/recovery@3" }, func(p *publicPlan) { p.NostrRecord = "north/nostr@6" }, func(p *publicPlan) { p.NamecoinRecord = "north/namecoin@7" },
		func(p *publicPlan) { p.Schema = "unknown" }, func(p *publicPlan) { p.Advisory = false }, func(p *publicPlan) { p.Version = 0 },
	} {
		bad := p
		change(&bad)
		b, _ := json.Marshal(bad)
		if got, err := acceptPlan(b, c); err == nil || got != (publicTarget{}) {
			t.Fatal("changed public plan accepted")
		}
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"namecoin_identity":"south",`), nil, 1),
		bytes.Replace(raw, []byte(`"namecoin_identity":"south"`), []byte(`"namecoin_identity":"south","namecoin_identity":"other"`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"private_key":"forbidden","schema":`), 1),
	} {
		if _, err := acceptPlan(bad, c); err == nil {
			t.Fatal("open or incomplete plan schema accepted")
		}
	}
	args := want.mutationArguments()
	if !reflect.DeepEqual(args, []string{"--nostr-identity", "north", "--namecoin-identity", "south", "--version", "3", "--nostr-version", "5", "--namecoin-version", "7"}) {
		t.Fatal("confirmed mutation targets changed")
	}
}
