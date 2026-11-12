package keyvault

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Claim: the public preflight retains ONE existing guard before the future
// attended private phase and transfers it to commit without a release/relock
// gap. Value copies share cancellation and terminal UNKNOWN state. Limits:
// fake public store only, no tty/helper, native locks, ACL or authentic sealing.
func TestRootGrantsAttach13PreflightSameGuard(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		plan, fake, r := rootGrantsAttachFixture13(t, "keyvault-recovery/2")
		fake.preAddReads = 3 // initial preflight + commit's two complete checks
		preflight, err := beginRootGrantsAttach(context.Background(), fake, plan.state.item.address, r.Pair)
		if err != nil || preflight == nil || !fake.held || fake.locks != 1 || fake.releases != 0 {
			t.Fatal("preflight did not retain the existing guard")
		}
		defer preflight.cancel()
		alias := *preflight
		// The future private helper phase runs HERE while the same guard is
		// retained. These public assertions do not simulate attended derivation.
		if !reflect.DeepEqual(fake.calls, []string{"lock-existing", "pair-public", "collision"}) {
			t.Fatal("preflight did not check exact retained public state first")
		}
		if unknown {
			fake.addError = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
			fake.applyOnError = true
		}
		result, err := preflight.commit(context.Background(), plan)
		if unknown {
			rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "commit", "unknown")
		} else if err != nil || result.Outcome != "stored" {
			t.Fatal("same-guard commit failed")
		}
		want := []string{"lock-existing", "pair-public", "collision", "pair-public", "collision", "pair-public", "add-only"}
		if !unknown {
			want = append(want, "root-public", "pair-public")
		}
		want = append(want, "release")
		if !reflect.DeepEqual(fake.calls, want) || fake.locks != 1 || fake.releases != 1 || fake.held || fake.adds != 1 {
			t.Fatal("preflight introduced a lock gap, extra add or leaked guard")
		}
		result, err = alias.commit(context.Background(), plan)
		if unknown {
			rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "commit", "unknown")
		} else {
			rootGrantsAttachFailure13(t, result, err, "operation_unavailable", "preflight", "not_applied")
		}
		alias.cancel()
		preflight.cancel()
		if fake.locks != 1 || fake.adds != 1 || fake.releases != 1 {
			t.Fatal("preflight alias replayed or released ownership twice")
		}
	}
}

// Claim: canceled/missing/changed/colliding public preflight performs no add;
// mismatched destination or pair cannot reuse a held guard, and an abandoned
// guard is released exactly once through aliases. Limits: no real backend.
func TestRootGrantsAttach13PreflightRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code, phase string
		configure         func(*rootGrantsVault13)
	}{
		{"missing-guard", "lock_unavailable", "lock", func(f *rootGrantsVault13) { f.lockError = true }},
		{"error-with-guard", "lock_unavailable", "lock", func(f *rootGrantsVault13) { f.guardWithLockError = true }},
		{"changed-pair", "retained_record_mismatch", "preflight", func(f *rootGrantsVault13) { f.pairChangedAt = 1 }},
		{"unreadable-pair", "retained_record_mismatch", "preflight", func(f *rootGrantsVault13) { f.pairErrorAt = 1 }},
		{"collision", "duplicate", "preflight", func(f *rootGrantsVault13) { f.collision = true }},
		{"inventory", "inventory_changed", "preflight", func(f *rootGrantsVault13) { f.inventoryError = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, fake, r := rootGrantsAttachFixture13(t, "keyvault-recovery/1")
			tc.configure(fake)
			p, err := beginRootGrantsAttach(context.Background(), fake, plan.state.item.address, r.Pair)
			rootGrantsAttachFailure13(t, RootGrantsAttachResult{}, err, tc.code, tc.phase, "not_applied")
			if p != nil || fake.held || fake.adds != 0 {
				t.Fatal("failed preflight leaked a guard or made an add")
			}
		})
	}
	for _, mode := range []string{"cancel-alias", "nil-plan", "wrong-target", "wrong-pair", "canceled-commit", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			plan, fake, r := rootGrantsAttachFixture13(t, "keyvault-recovery/2")
			p, err := beginRootGrantsAttach(context.Background(), fake, plan.state.item.address, r.Pair)
			if err != nil {
				t.Fatal(err)
			}
			defer p.cancel()
			alias := *p
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			code, phase := "public_pin_mismatch", "prepare"
			switch mode {
			case "cancel-alias":
				alias.cancel()
				code, phase = "operation_unavailable", "preflight"
			case "nil-plan":
				plan = nil
			case "wrong-target":
				plan.state.item.address.Version++
			case "wrong-pair":
				plan.state.public.Pair.Version++
			case "canceled-commit":
				cancel()
				code, phase = "canceled", "lock"
			case "nil-context":
				ctx = nil
				code, phase = "invalid_arguments", "prepare"
			}
			result, err := p.commit(ctx, plan)
			rootGrantsAttachFailure13(t, result, err, code, phase, "not_applied")
			alias.cancel()
			p.cancel()
			if fake.held || fake.releases != 1 || fake.locks != 1 || fake.adds != 0 {
				t.Fatal("abandoned/invalid preflight retained a guard or added")
			}
		})
	}
	for _, mode := range []string{"nil-context", "nil-vault", "canceled", "invalid-pair", "invalid-target"} {
		plan, fake, r := rootGrantsAttachFixture13(t, "keyvault-recovery/1")
		ctx, cancel := context.WithCancel(context.Background())
		var vault rootGrantsAttachVault = fake
		target := plan.state.item.address
		switch mode {
		case "nil-context":
			ctx = nil
		case "nil-vault":
			vault = nil
		case "canceled":
			cancel()
		case "invalid-pair":
			r.Pair.Schema = "unknown"
		case "invalid-target":
			target.Version = 0
		}
		p, err := beginRootGrantsAttach(ctx, vault, target, r.Pair)
		cancel()
		if err == nil || p != nil || len(fake.calls) != 0 {
			t.Fatal("invalid preflight reached a storage boundary")
		}
	}
}
