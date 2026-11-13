//go:build darwin && cgo

package keyvault

import (
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// Claim: every stage id compiled into the native unit equals the id of the same
// stage in the Go table, with no missing, extra or shifted entry. This is what
// keeps the printed stage number and name in agreement with the code that records
// it. Negative control: the reserved id and the internal projection ids are not in
// the native map of reported stages. Limit: ids only; where each id is recorded is
// proven by the kvqfault injection tests.
func TestNativeStageIDsEqualTheGoTable(t *testing.T) {
	native := nativeStageIDs()
	stages := rootqualification.Stages()
	if len(native) != len(stages) {
		t.Fatalf("native defines %d reported stages, the Go table has %d", len(native), len(stages))
	}
	seen := map[int]rootqualification.Stage{}
	for _, stage := range stages {
		id, ok := native[stage]
		if !ok || id != int(stage) {
			name, _ := stage.Name()
			t.Fatalf("stage %s: Go id %d, native id %d (present %v)", name, int(stage), id, ok)
		}
		if other, dup := seen[id]; dup {
			t.Fatalf("native id %d is used by stages %d and %d", id, int(other), int(stage))
		}
		seen[id] = stage
	}
	for stage, id := range native {
		if _, ok := stage.Name(); !ok {
			t.Fatalf("native stage %d (id %d) is not a reported stage", int(stage), id)
		}
	}
	for _, never := range []int{70, 71, 72, 73, 74, int(rootqualification.StageReserved)} {
		if _, used := seen[never]; used {
			t.Fatalf("id %d must never be a reported stage", never)
		}
	}
}
