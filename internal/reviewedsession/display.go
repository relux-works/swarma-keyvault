package reviewedsession

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const ownerKeyDisplay = "alexis/grants-owner-v1 v1"
const reasonPrefix = "mac-keyvault: "
const digestLabel = "[ХЕШ-ПОДПИСИ "

// shortDigest is a 64-bit human cue only. All machine comparisons use all
// 32 bytes. Chosen-pair work for this cue is approximately 2^32, not 2^64.
func shortDigest(d [32]byte) string {
	h := hex.EncodeToString(d[:8])
	return h[:4] + " " + h[4:8] + " " + h[8:12] + " " + h[12:]
}

func displayData(s string) error {
	if len(s) > reviewMax || !ascii(s) {
		return errDisplay
	}
	lower := strings.ToLower(s)
	for _, marker := range []string{"signing_digest_sha256=", "short_signing_digest=", "plan_snapshot_sha256=", "session_nonce="} {
		if strings.Contains(lower, marker) {
			return errDisplay
		}
	}
	return nil
}

func titleToken(s string) bool {
	if s == "" || displayData(s) != nil {
		return false
	}
	for _, r := range s {
		if !safeTokenRune(r) {
			return false
		}
	}
	return true
}

func safeTokenRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@._:/+-", r)
}

// safeString is reversible display, not a transformation of signing bytes.
// It never emits caller-controlled whitespace, Markdown or trailer syntax.
func safeString(s string) (string, error) {
	if err := displayData(s); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		// Reserve this scalar's escape and the closing quote. Reject
		// expansion before the builder can exceed the whole-body cap.
		needed := 1
		if r == '"' || r == '\\' {
			needed = 2
		} else if !safeTokenRune(r) {
			needed = 6
		}
		if b.Len()+needed+1 > reviewMax {
			return "", errDisplay
		}
		switch {
		case safeTokenRune(r):
			b.WriteRune(r)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

type titleFacts struct {
	profile profile
	// Counts/policy must eventually come from the exact typed MU body, never
	// its original entry pairs. This formatter asserts no validation of a body.
	actions, targets int
	use              string
	optionalToken    string
}

func (f titleFacts) core() (string, error) {
	if f.profile != muGrantMac && (f.actions != 0 || f.targets != 0 || f.use != "") {
		return "", errDisplay
	}
	switch f.profile {
	case repository:
		return "Грант репозитория: 2 записи; CREATE+DELETE", nil
	case localRepository:
		return "Локальный грант: 2 записи; CREATE+DELETE", nil
	case a2aCertificate:
		return "Грант A2A: 1 CREATE", nil
	case muGrantMac:
		if f.actions < 1 || f.targets < 1 {
			return "", errDisplay
		}
		var policy string
		switch f.use {
		case "once":
			policy = "однократно на действие/цель"
		case "until_expiry":
			policy = "до истечения срока"
		default:
			return "", errDisplay
		}
		return "Грант MU: " + strconv.Itoa(f.actions) + " действий; " + strconv.Itoa(f.targets) + " целей; " + policy, nil
	}
	return "", errDisplay
}

func renderReason(f titleFacts, digest [32]byte, resolvedKey string) (string, error) {
	if resolvedKey != ownerKeyDisplay {
		return "", errBinding
	}
	core, err := f.core()
	if err != nil {
		return "", err
	}
	title := core
	if f.optionalToken != "" {
		if !titleToken(f.optionalToken) {
			return "", errDisplay
		}
		title += "; " + f.optionalToken
	}
	protected := digestLabel + shortDigest(digest) + "]"
	suffix := " with " + resolvedKey
	budget := 200 - utf8.RuneCountInString(reasonPrefix+" | "+protected+suffix)
	if utf8.RuneCountInString(core) > budget {
		return "", errDisplay
	}
	if utf8.RuneCountInString(title) > budget {
		if utf8.RuneCountInString(core) >= budget {
			return "", errDisplay
		}
		title = string([]rune(title)[:budget-1]) + "…"
	}
	reason := reasonPrefix + title + " | " + protected + suffix
	if !reasonAlphabet(reason) || utf8.RuneCountInString(reason) > 200 || strings.Count(reason, protected) != 1 {
		return "", errDisplay
	}
	return reason, nil
}

// Restrict output to printable ASCII, the exact static Cyrillic template
// alphabet and the renderer's ellipsis. Every admitted scalar survives the
// checked-in Swift control filter and 200-scalar prefix unchanged. This says
// nothing about actual native visibility, fonts, helper identity or adoption.
func reasonAlphabet(s string) bool {
	const static = "Грант репозитория Локальный грант записи действий целей однократно на действие/цель до истечения срока ХЕШ-ПОДПИСИ …"
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			continue
		}
		if !strings.ContainsRune(static, r) {
			return false
		}
	}
	return true
}

// checkFinalReason is a pure pre-dispatch contract component. It cannot install
// a policy in EnclaveStore or turn a callback into authorization. A future
// internal SignReviewed handoff must bind this check to its one-use permit.
func checkFinalReason(f titleFacts, owned [32]byte, actualDigest []byte, resolvedKey, actual string) error {
	if len(actualDigest) != 32 {
		return errBinding
	}
	var got [32]byte
	copy(got[:], actualDigest)
	if got != owned {
		return errBinding
	}
	want, err := renderReason(f, owned, resolvedKey)
	if err != nil {
		return err
	}
	if actual == "" || actual != want {
		return errBinding
	}
	return nil
}
