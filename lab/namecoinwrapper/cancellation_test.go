package namecoinwrapper

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestFinalSealCallbackCancellation(t *testing.T) {
	// The existing signed-certificate fixture and actual verifier CLI must
	// succeed before the same final callback cancels an otherwise valid reply.
	f := fresh(t)
	f.verify(t, &Verifier{}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seals := 0
	f.n.mutate = func(method string, args []any) {
		if method == "gettxout" {
			seals++
			if seals == 2 {
				cancel()
			}
		}
	}
	v := new(Verifier)
	observation, err := v.Verify(ctx, f.n, f.p, f.certificate, f.request, f.at)
	if seals != 2 || observation != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("final callback: seals=%d observation=%v error=%v", seals, observation, err)
	}
	entries, err := os.ReadDir(f.p.PrivateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "observation-") {
			t.Fatal("canceled observation left temporary files")
		}
	}
	f.n.mutate = nil
	// Cancellation after a successful seal reply proves no lifecycle change.
	// The current attempt refused, but healthy fresh requests can recover.
	f.operation["request_id"] = "fresh-valid-after-final-callback-cancellation"
	f.resign(t)
	f.verify(t, v, true)
	f.verify(t, new(Verifier), true)
}
