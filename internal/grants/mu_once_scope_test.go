package grants

import (
	"errors"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// The second existing adapter uses the same accounting restriction. These
// controls retain its existing synthetic assurance premise; they qualify no
// protected time, consent source, native custody or installation.
func TestMUPlatformOnceScope(t *testing.T) {
	for _, shape := range []string{"single", "actions", "targets"} {
		t.Run(shape, func(t *testing.T) {
			g := newMUDock(t)
			p := g.receiver.verifier.(*MUPlatform)
			envelope, err := muParseEnvelope(g.grant)
			if err != nil {
				t.Fatal(err)
			}
			body := envelope["body"].(map[string]any)
			body["actions"] = []any{"work.assign"}
			body["targets"] = []any{map[string]any{"kind": "product", "id": "swarma-platform"}}
			body["caveats"].(map[string]any)["use"] = "once"
			if shape == "actions" {
				body["actions"] = []any{"work.assign", "work.require"}
			}
			if shape == "targets" {
				body["targets"] = []any{map[string]any{"kind": "product", "id": "swarma-platform"}, map[string]any{"kind": "product", "id": "another-product"}}
			}
			raw, err := record.Canonical(body)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := mugrant.Prepare("grant/1", g.root.id, raw)
			if err != nil {
				t.Fatal(err)
			}
			p.config.Grants = [][]byte{g.root.sign(t, plan)}
			g.request("$once-scope", "work.assign", "product", "swarma-platform", map[string]string{"module": "swarma-keyvault"}, "lab request")
			_, err = g.handle("$once-scope")
			if shape == "single" {
				if err != nil || g.effect.calls != 1 {
					t.Fatal("single right refused", err, g.effect.calls)
				}
			} else if !errors.Is(err, ErrMUState) || g.effect.calls != 0 {
				t.Fatal("multi-right once grant admitted", err, g.effect.calls)
			}
		})
	}
}
