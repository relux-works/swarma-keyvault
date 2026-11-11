package seedsetup

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
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

type plannerFunc func(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error)

func (f plannerFunc) Plan(q keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) { return f(q) }

func fixturePlan(target publicTarget) keyvault.RecoveryPlan {
	return keyvault.RecoveryPlan{Schema: "keyvault-recovery-plan/1", Advisory: true,
		NostrIdentity: target.NostrIdentity, NamecoinIdentity: target.NamecoinIdentity,
		Version: target.Version, NostrVersion: target.NostrVersion, NamecoinVersion: target.NamecoinVersion,
		Group: target.group(), NostrRecord: target.nostr(), NamecoinRecord: target.namecoin()}
}

type emptyInventory struct{}

func (emptyInventory) List() ([]keyvault.NostrRecord, error)            { return nil, nil }
func (emptyInventory) RecoveryList() ([]keyvault.RecoveryRecord, error) { return nil, nil }

type trackingReadLock struct {
	held  bool
	reads int
}

func (l *trackingReadLock) LockReadOnly() (func(), error) {
	if l.held {
		panic("overlapping plan lock")
	}
	l.held = true
	l.reads++
	return func() { l.held = false }, nil
}

// Both plans are produced in-process and release the shared read lock before
// either public identity prompt. The runner cannot execute a source binary.
func TestInProcessPlanReleasesBeforeIdentityInput(t *testing.T) {
	lock := &trackingReadLock{}
	w := workflow{planner: keyvault.NewRecoveryPlanner(emptyInventory{}, lock), run: func(string, ...string) invocation { t.Fatal("planner launched a child"); return invocation{} }}
	actual, err := w.plan(Config{NostrIdentity: "north", NamecoinIdentity: "south"})
	if err != nil || lock.held {
		t.Fatal("actual plan retained lock", err)
	}
	qual, err := w.plan(Config{NostrIdentity: "fixture-north", NamecoinIdentity: "fixture-south", Version: 1, NostrVersion: 1, NamecoinVersion: 1})
	if err != nil || lock.held || lock.reads != 2 {
		t.Fatal("qualification plan retained lock", err)
	}
	prompts := 0
	w.prompt = func(string, int) (string, error) {
		if lock.held {
			t.Fatal("human input under vault lock")
		}
		prompts++
		if prompts == 1 {
			return actual.NostrIdentity, nil
		}
		return actual.NamecoinIdentity, nil
	}
	if err := w.confirm(installation{}, actual, qual); err != nil || prompts != 2 {
		t.Fatal("valid confirmation refused", err)
	}
}
