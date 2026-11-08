package namecoinwrapper

import (
	"strings"
	"unicode"
)

func (p *point) UnmarshalJSON(raw []byte) error {
	*p = point{}
	return exactProjection(raw, map[string]any{"txid": &p.TxID, "vout": &p.Vout})
}

type sealOutput struct {
	Bestblock     string
	Confirmations int
	Script        script
}

func (s *sealOutput) UnmarshalJSON(raw []byte) error {
	*s = sealOutput{}
	return exactProjection(raw, map[string]any{
		"bestblock": &s.Bestblock, "confirmations": &s.Confirmations, "scriptPubKey": &s.Script,
	})
}

// An orphan header need not be confirmed. Its hash and height must still be
// independently spelled, present and typed before they can establish closure.
type displacedHeader struct {
	Hash   string
	Height *int
}

func (h *displacedHeader) UnmarshalJSON(raw []byte) error {
	*h = displacedHeader{}
	return exactProjection(raw, map[string]any{"hash": &h.Hash, "height": &h.Height})
}

// Match Unicode simple-fold equivalence (as encoding/json does), including
// long-s and Kelvin sign. A canonical representative keeps scanning linear in
// key bytes instead of comparing every member with all previous members.
func foldJSONKey(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, s)
}
