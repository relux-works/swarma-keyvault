package main

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// signDescription, set by sign for the data it hashed, words the presence
// prompt of an enclave key; nil keeps the store's generic sha256 text.
var signDescription func(digest []byte) string

// describedEnclave words store's presence prompts from signDescription.
func describedEnclave(store *keyvault.EnclaveStore) *keyvault.EnclaveStore {
	store.Describe = func(digest []byte) string {
		if signDescription == nil {
			return ""
		}
		return signDescription(digest)
	}
	return store
}

// describeData returns a prompt description for data whose sha256 is the
// digest being signed: the action and package digest prefix of a vpn-core
// authorization statement, so the owner matches what the agent announced.
// Anything else, or a statement that does not parse exactly, returns "".
func describeData(data []byte) func(digest []byte) string {
	sum := sha256.Sum256(data)
	what := describeVPNCoreAuthorization(data)
	return func(digest []byte) string {
		if !bytes.Equal(digest, sum[:]) {
			return ""
		}
		return what
	}
}

// describeVPNCoreAuthorization recognises the first lines of the
// works.relux.vpn-core.authorize/v1 statement that mac-infra-core issues.
// The root helper, not this parser, decides whether a statement is valid.
func describeVPNCoreAuthorization(data []byte) string {
	lines := strings.Split(string(data), "\n")
	if len(lines) != 7 || lines[0] != "works.relux.vpn-core.authorize/v1" || lines[2] != "target=vpn-core" || lines[6] != "" {
		return ""
	}
	action, okAction := strings.CutPrefix(lines[1], "action=")
	digest, okDigest := strings.CutPrefix(lines[3], "digest=")
	nonce, okNonce := strings.CutPrefix(lines[4], "nonce=")
	expires, okExpires := strings.CutPrefix(lines[5], "expires=")
	if !okAction || !okDigest || !okNonce || !okExpires || (action != "install" && action != "rollback") ||
		!isLowerHex(digest, 64) || !isLowerHex(nonce, 64) {
		return ""
	}
	// Canonical expiry only: time.Parse also accepts fractional seconds.
	if t, err := time.Parse("2006-01-02T15:04:05Z", expires); err != nil || t.Format("2006-01-02T15:04:05Z") != expires {
		return ""
	}
	return "authorize vpn-core " + action + " " + digest[:8]
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
