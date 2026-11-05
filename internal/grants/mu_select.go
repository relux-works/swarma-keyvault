package grants

import (
	"errors"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrMUAmbiguous refuses a request that more than one pinned grant covers.
// Interim rule until an explicit grant id exists (Meta X8, 2026-11-05).
var ErrMUAmbiguous = errors.New("mu-ambiguous-grant")

// ErrMUNoGrant refuses a request that no pinned grant covers.
var ErrMUNoGrant = errors.New("mu-no-applicable-grant")

// muSelectGrant picks the single pinned leaf grant whose subject is the
// request author and whose actions and targets cover the request exactly
// (targets compared by kind and id; no pattern matching here). Zero matches
// refuse ErrMUNoGrant and more than one refuse ErrMUAmbiguous. Malformed
// registry entries refuse ErrMUState rather than being skipped. Selection
// grants nothing: the platform verifier still checks the whole chain.
func muSelectGrant(registry [][]byte, author, action, kind, id string) ([]byte, error) {
	var found []byte
	matches := 0
	for _, raw := range registry {
		parsed, err := record.Parse(raw, 65536, 16)
		if err != nil {
			return nil, ErrMUState
		}
		e, ok := parsed.(map[string]any)
		if !ok {
			return nil, ErrMUState
		}
		b, ok := e["body"].(map[string]any)
		if !ok || b["type"] != "grant/1" {
			return nil, ErrMUState
		}
		if b["subject"] != author {
			continue
		}
		actions, _ := b["actions"].([]any)
		hasAction := false
		for _, a := range actions {
			hasAction = hasAction || a == action
		}
		targets, _ := b["targets"].([]any)
		hasTarget := false
		for _, t := range targets {
			m, _ := t.(map[string]any)
			hasTarget = hasTarget || (m != nil && m["kind"] == kind && m["id"] == id)
		}
		if hasAction && hasTarget {
			matches++
			found = raw
		}
	}
	switch {
	case matches == 0:
		return nil, ErrMUNoGrant
	case matches > 1:
		return nil, ErrMUAmbiguous
	}
	return found, nil
}
