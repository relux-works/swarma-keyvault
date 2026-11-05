package main

import (
	"encoding/json"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

// Claim: an owner-root revocation prepared by the CLI, signed by the root and
// assembled as revocation/1 is admitted by the receiver's root revocation
// check with exactly its entry; a foreign signature does not assemble; empty
// entries, an unknown member, a non-exact time and an unknown entry kind
// refuse before any plan, beside the valid control.
func TestMUCLIRootRevocation(t *testing.T) {
	rk, root := muCLIKey(t)
	spec := map[string]any{"issuer": root, "issued_at": "2026-11-05T18:00:00Z", "entries": []any{map[string]any{"kind": "record", "id": "sha256:abcd", "from": "2026-11-05T17:00:00Z"}}}
	code, out, errText := muCLIRun("grants", "mu-root-revocation-prepare", "--spec", muCLIWrite(t, "spec.json", spec))
	if code != 0 {
		t.Fatal(code, errText)
	}
	var p map[string]string
	if err := json.Unmarshal([]byte(out), &p); err != nil || p["kind"] != "revocation/1" || p["key"] != root {
		t.Fatal("prepared", err, out)
	}
	code, wire, errText := muSignAndAssemble(t, p, rk)
	if code != 0 {
		t.Fatal("assemble", code, errText)
	}
	got, err := grants.VerifyRootRevocations(root, [][]byte{[]byte(wire)})
	if err != nil || len(got) != 1 || got[0] != (grants.MURevocation{Kind: "record", ID: "sha256:abcd"}) {
		t.Fatal("receiver refused the owner-root revocation", err, got)
	}
	other, _ := muCLIKey(t)
	if code, _, _ := muSignAndAssemble(t, p, other); code == 0 {
		t.Fatal("foreign signature assembled")
	}
	for name, mutate := range map[string]func(map[string]any){
		"no-entries":     func(m map[string]any) { m["entries"] = []any{} },
		"unknown-member": func(m map[string]any) { m["complete"] = false },
		"non-exact-time": func(m map[string]any) { m["issued_at"] = "2026-11-05 18:00:00" },
		"bad-entry-kind": func(m map[string]any) {
			m["entries"] = []any{map[string]any{"kind": "everything", "id": "sha256:abcd", "from": "2026-11-05T17:00:00Z"}}
		},
	} {
		m := map[string]any{}
		for k, v := range spec {
			m[k] = v
		}
		mutate(m)
		if code, out, _ := muCLIRun("grants", "mu-root-revocation-prepare", "--spec", muCLIWrite(t, "s.json", m)); code != 1 || out != "" {
			t.Error("refusal expected", name, code)
		}
	}
}
