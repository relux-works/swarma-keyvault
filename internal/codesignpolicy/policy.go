// Package codesignpolicy defines the finite certificate release policy shared
// by the matched builder and its artifact verifier. It performs no OS calls.
package codesignpolicy

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

type Role uint8

const (
	Vault Role = iota + 1
	Helper
	Seed
	Qualification
)

const (
	LeafSHA1   = "d71190abe54185f908169ee9ca538d4066942c0f"
	LeafSHA256 = "b315ed0ac55f58d4dbcfc3ce4f7937f6ed058277feba7e4aa3e64bd10b17d3a1"
	Team       = "262RZ595FP"
)

var ErrPolicy = errors.New("certificate release policy refused")

func Identifier(role Role) (string, error) {
	switch role {
	case Vault:
		return "works.relux.keyvault", nil
	case Helper:
		return "works.relux.keyvault.enclave", nil
	case Seed:
		return "works.relux.keyvault.seed", nil
	case Qualification:
		return "works.relux.keyvault.qualification-foreign", nil
	default:
		return "", ErrPolicy
	}
}

// Requirement is fixed by role, never a caller-selected requirement expression.
func Requirement(role Role) (string, error) {
	id, err := Identifier(role)
	if err != nil {
		return "", err
	}
	return `designated => identifier "` + id + `" and anchor apple generic and certificate leaf = H"` + LeafSHA1 + `" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */`, nil
}

// SigningArgs selects one exact certificate and embeds the explicit requirement.
// Calling this pure constructor neither signs nor authorizes an OS operation.
func SigningArgs(role Role, artifact string) ([]string, error) {
	id, err := Identifier(role)
	if err != nil || !filepath.IsAbs(artifact) || filepath.Clean(artifact) != artifact || strings.ContainsRune(artifact, '\x00') {
		return nil, ErrPolicy
	}
	r, _ := Requirement(role)
	return []string{"-s", LeafSHA1, "--force", "--options", "runtime", "--timestamp=none", "--identifier", id, "-r=" + r, artifact}, nil
}

// Leaf checks the complete extracted certificate bytes. Chain/signature validity
// must separately pass the native verifier against the fixed requirement.
func Leaf(der []byte) error {
	if len(der) == 0 || len(der) > 32768 {
		return ErrPolicy
	}
	a, b := sha1.Sum(der), sha256.Sum256(der)
	if hex.EncodeToString(a[:]) != LeafSHA1 || hex.EncodeToString(b[:]) != LeafSHA256 {
		return ErrPolicy
	}
	return nil
}

var directoryFlags = regexp.MustCompile(`\bflags=(0x[0-9a-f]+)\([^\r\n]*\)`)
var codeHash = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// CodeInfo checks only the readback metadata shape, not certificate trust.
// Strict native signature/requirement verification and Leaf are also required.
func CodeInfo(role Role, info, entitlements []byte) (string, error) {
	id, err := Identifier(role)
	if err != nil || len(info) == 0 || len(info) > 65536 || len(entitlements) > 65536 {
		return "", ErrPolicy
	}
	fields := make(map[string][]string)
	var flags [][]byte
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(line, "CodeDirectory ") {
			matches := directoryFlags.FindAllSubmatch([]byte(line), -1)
			if len(matches) != 1 {
				return "", ErrPolicy
			}
			flags = append(flags, matches[0][1])
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = append(fields[key], value)
		}
	}
	one := func(key, want string) bool { return len(fields[key]) == 1 && fields[key][0] == want }
	if !one("Identifier", id) || !one("TeamIdentifier", Team) || len(flags) != 1 || string(flags[0]) != "0x10000" ||
		len(fields["Signature"]) != 0 || len(fields["CDHash"]) != 1 || !codeHash.MatchString(fields["CDHash"][0]) || EmptyEntitlements(entitlements) != nil {
		return "", ErrPolicy
	}
	return fields["CDHash"][0], nil
}

// RequirementReadback accepts only the one explicit fixed expression. The lexer
// admits whitespace and the known exists annotation, never alternate clauses.
func RequirementReadback(role Role, output []byte) error {
	want, err := Requirement(role)
	if err != nil || len(output) == 0 || len(output) > 65536 {
		return ErrPolicy
	}
	var actual string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Executable=") {
			continue
		}
		if actual != "" {
			return ErrPolicy
		}
		actual = line
	}
	a, err := requirementTokens(actual)
	if err != nil {
		return err
	}
	b, _ := requirementTokens(want)
	if len(a) != len(b) {
		return ErrPolicy
	}
	for i := range a {
		if a[i] != b[i] {
			return ErrPolicy
		}
	}
	return nil
}

func requirementTokens(s string) ([]string, error) {
	var out []string
	for len(s) > 0 {
		if strings.ContainsRune(" \t\r\n", rune(s[0])) {
			s = s[1:]
			continue
		}
		if strings.HasPrefix(s, "/* exists */") {
			// The sole native annotation may appear only after the final ].
			if len(out) == 0 || out[len(out)-1] != "]" || strings.TrimSpace(s[len("/* exists */"):]) != "" {
				return nil, ErrPolicy
			}
			s = s[len("/* exists */"):]
			continue
		}
		if strings.HasPrefix(s, "=>") {
			out, s = append(out, "=>"), s[2:]
			continue
		}
		if strings.ContainsRune("[]=", rune(s[0])) {
			out, s = append(out, s[:1]), s[1:]
			continue
		}
		if s[0] == '"' {
			n := strings.IndexByte(s[1:], '"')
			if n < 0 || strings.ContainsAny(s[1:n+1], "\\\r\n\x00") {
				return nil, ErrPolicy
			}
			n += 2
			out, s = append(out, s[:n]), s[n:]
			continue
		}
		n := 0
		for n < len(s) && (s[n] >= 'a' && s[n] <= 'z' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= '0' && s[n] <= '9' || s[n] == '.' || s[n] == '-' || s[n] == '_') {
			n++
		}
		if n == 0 {
			return nil, ErrPolicy
		}
		out, s = append(out, s[:n]), s[n:]
	}
	return out, nil
}

// EmptyEntitlements preserves the existing empty-plist admission. A false-valued
// entitlement is still an entitlement and is refused.
func EmptyEntitlements(raw []byte) error {
	if len(raw) > 65536 {
		return ErrPolicy
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth, root, dict := 0, false, false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrPolicy
		}
		switch v := token.(type) {
		case xml.StartElement:
			if v.Name.Space != "" || depth >= 2 {
				return ErrPolicy
			}
			if depth == 0 {
				if root || v.Name.Local != "plist" || len(v.Attr) != 1 || v.Attr[0].Name.Space != "" || v.Attr[0].Name.Local != "version" || v.Attr[0].Value != "1.0" {
					return ErrPolicy
				}
				root = true
			} else {
				if dict || v.Name.Local != "dict" || len(v.Attr) != 0 {
					return ErrPolicy
				}
				dict = true
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return ErrPolicy
			}
		}
	}
	if depth != 0 || !dict {
		return ErrPolicy
	}
	return nil
}
