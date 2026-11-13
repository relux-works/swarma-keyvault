package namecoinprocess

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const (
	MaxProcessRequestBytes = 2 << 20
	MaxProcessPSBTBytes    = 1 << 20
)

// CheckRequestLimits checks the raw ceiling before JSON allocation, then
// strictly decodes at most the PSBT ceiling plus one byte before any request
// semantics. It is not closed-wire or transaction admission: the existing
// decoder and engine must still validate the exact original bytes afterward.
func CheckRequestLimits(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxProcessRequestBytes {
		return namecoinwire.ErrInvalidRequest
	}
	var sizing struct {
		PSBT string `json:"psbt"`
	}
	if json.Unmarshal(raw, &sizing) != nil {
		return namecoinwire.ErrInvalidRequest
	}
	// The raw request already bounds encoded input. Limit decoded allocation
	// and reading to one byte beyond the inclusive process ceiling; an
	// oversized decoded prefix needs no further allocation or semantic work.
	decoded := make([]byte, min(base64.StdEncoding.DecodedLen(len(sizing.PSBT)), MaxProcessPSBTBytes+1))
	n, err := io.ReadFull(base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(sizing.PSBT)), decoded)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		// Preserve the existing closed decoder's syntax/error precedence.
		// Failed decoding establishes no decoded-size verdict and grants
		// no admission: the original request still must pass that decoder.
		return nil
	}
	if n > MaxProcessPSBTBytes {
		return namecoinwire.ErrInvalidRequest
	}
	// Strict decoding still tolerates line breaks; the wire requires exact
	// canonical base64, including padding and unused trailing bits.
	if base64.StdEncoding.EncodeToString(decoded[:n]) != sizing.PSBT {
		return nil // The existing wire decoder rejects this representation.
	}
	return nil
}
