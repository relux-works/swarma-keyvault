package grants

import (
	"crypto/sha256"
	"errors"
)

type digestDomain uint8

const (
	certificateDomain digestDomain = iota + 1
	revocationDomain
	requestDomain
	resultDomain
)

var errUnknownDigestDomain = errors.New("unsupported grant digest domain")

// domainDigest calculates SHA256(domain + LF + exact received bytes). It does
// not validate encoding/schema, enforce input bounds, verify signatures or
// authenticate a result. Callers must separately qualify those requirements;
// the calculated value alone conveys no authority. Received bytes are never
// normalized, reserialized or changed by this function.
func domainDigest(domain digestDomain, exact []byte) ([sha256.Size]byte, error) {
	var prefix string
	switch domain {
	case certificateDomain:
		prefix = "swarma-grants/certificate/1"
	case revocationDomain:
		prefix = "swarma-grants/revocation/1"
	case requestDomain:
		prefix = "swarma-grants/request/1"
	case resultDomain:
		prefix = "swarma-grants/result/1"
	default:
		return [sha256.Size]byte{}, errUnknownDigestDomain
	}
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write([]byte{'\n'})
	h.Write(exact)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
