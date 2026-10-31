package kek

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

const fixtureCertificate = "0123456789abcdef0123456789abcdef01234567"
const fixtureIdentifier = "works.relux.network-proxy"

func certificateIdentity(hash string) CodeIdentity {
	id := hardened(hash)
	id.Identifier, id.CertificateSHA1 = fixtureIdentifier, fixtureCertificate
	return id
}

// Both binding modes recheck the actual peer after decryption, including
// hardening and stable code facts. Fake observations exercise the server gate;
// they do not establish native exec detection or eliminate a later exec race.
func TestPeerRevalidationBeforeAnswer(t *testing.T) {
	for _, certificate := range []bool{false, true} {
		for name, mutate := range map[string]func(*CodeIdentity){
			"unchanged":             nil,
			"changed build":         func(id *CodeIdentity) { id.CDHash = newHash },
			"changed identifier":    func(id *CodeIdentity) { id.Identifier = "other" },
			"changed certificate":   func(id *CodeIdentity) { id.CertificateSHA1 = strings.Repeat("f", 40) },
			"invalid signature":     func(id *CodeIdentity) { id.Valid = false },
			"no runtime":            func(id *CodeIdentity) { id.Runtime = false },
			"no library validation": func(id *CodeIdentity) { id.LibraryValidation = false },
			"get task allow":        func(id *CodeIdentity) { id.GetTaskAllow = true },
			"lookup failure":        nil,
		} {
			t.Run(map[bool]string{false: "cdhash", true: "certificate"}[certificate]+"/"+name, func(t *testing.T) {
				f := newFixture(t, nil)
				if certificate {
					f = certificateFixture(t)
				}
				next := f.inspect.peer
				if mutate != nil {
					mutate(&next)
				}
				f.inspect.nextPeer = &next
				if name == "lookup failure" {
					f.inspect.nextPeerErr = errors.New("peer unavailable")
				}
				resp, raw := f.unwrap()
				if f.inspect.peerCalls != 2 {
					t.Fatalf("peer observations = %d; want 2", f.inspect.peerCalls)
				}
				if name == "unchanged" {
					if !resp.OK || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK) {
						t.Fatalf("stable peer refused: %s", raw)
					}
				} else {
					requireRefused(t, resp, raw, kekclient.CodeCallerRefused)
				}
				log, err := os.ReadFile(f.audit.Path)
				if err != nil {
					t.Fatal(err)
				}
				requireNoKEK(t, log)
			})
		}
	}
}

func certificateFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, nil)
	req, err := kekclient.RequirementForCertificate(fixtureIdentifier, fixtureCertificate)
	if err != nil {
		t.Fatal(err)
	}
	f.envelope, err = kekclient.Wrap(kekclient.WrapSpec{SPKI: f.key.SPKI, Fingerprint: f.key.Fingerprint(), Address: address, Generation: f.key.Record.Version, Requirement: req, InstallPath: installPath}, testKEK)
	if err != nil {
		t.Fatal(err)
	}
	f.inspect.peer = certificateIdentity(proxyHash)
	f.inspect.files[installPath] = certificateIdentity(newHash)
	return f
}

// Fake-vault socket conformance requires both explicit certificate and signed
// identifier with the existing hardening gates. Two independently observed
// builds sharing those pins can unwrap the same envelope; this does not prove
// native certificate extraction or actual signed-proxy adoption.
func TestCertificateUnwrapConformance(t *testing.T) {
	cases := map[string]func(*CodeIdentity){
		"exact":                   nil,
		"successive build":        func(id *CodeIdentity) { id.CDHash = newHash },
		"other certificate":       func(id *CodeIdentity) { id.CertificateSHA1 = strings.Repeat("f", 40) },
		"other identifier":        func(id *CodeIdentity) { id.Identifier = "other.identifier" },
		"identifier case differs": func(id *CodeIdentity) { id.Identifier = strings.ToUpper(fixtureIdentifier) },
		"ad hoc":                  func(id *CodeIdentity) { id.CertificateSHA1 = "" },
		"invalid signature":       func(id *CodeIdentity) { id.Valid = false },
		"no runtime":              func(id *CodeIdentity) { id.Runtime = false },
		"no library validation":   func(id *CodeIdentity) { id.LibraryValidation = false },
		"get task allow":          func(id *CodeIdentity) { id.GetTaskAllow = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := certificateFixture(t)
			if change != nil {
				change(&f.inspect.peer)
			}
			resp, raw := f.unwrap()
			if name == "exact" || name == "successive build" {
				if !resp.OK || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK) {
					t.Fatalf("valid certificate caller refused: %s", raw)
				}
			} else {
				requireRefused(t, resp, raw, kekclient.CodeCallerRefused)
			}
			log, err := os.ReadFile(f.audit.Path)
			if err != nil {
				t.Fatal(err)
			}
			requireNoKEK(t, log)
		})
	}
}

// Rebind never changes certificate pins, identifiers or mode. An installed
// same-pin next build already matches; invalid and different targets refuse
// too, always without publishing an envelope or KEK.
func TestCertificateRebindNeverConverts(t *testing.T) {
	for _, name := range []string{"same pins", "other certificate", "other identifier", "ad hoc", "invalid", "no runtime", "no library validation", "get task allow", "missing"} {
		t.Run(name, func(t *testing.T) {
			f := certificateFixture(t)
			id := f.inspect.files[installPath]
			switch name {
			case "other certificate":
				id.CertificateSHA1 = strings.Repeat("f", 40)
			case "other identifier":
				id.Identifier = "other"
			case "ad hoc":
				id.CertificateSHA1 = ""
			case "invalid":
				id.Valid = false
			case "no runtime":
				id.Runtime = false
			case "no library validation":
				id.LibraryValidation = false
			case "get task allow":
				id.GetTaskAllow = true
			}
			f.inspect.files[installPath] = id
			if name == "missing" {
				delete(f.inspect.files, installPath)
			}
			resp, raw := f.call(kekclient.OpRebind, request(kekclient.OpRebind, f.envelope))
			requireRefused(t, resp, raw, kekclient.CodeRebindRefused)
			resp, raw = f.unwrap()
			if !resp.OK || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK) {
				t.Fatalf("held certificate envelope stopped working: %s", raw)
			}
		})
	}
}

// Even a matching certificate caller receives no KEK if durable audit cannot
// be established. The neighboring conformance test is the valid positive.
func TestCertificateAuditFailureWithholdsKEK(t *testing.T) {
	f := certificateFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.audit.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.audit.Path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	resp, raw := f.unwrap()
	requireRefused(t, resp, raw, kekclient.CodeSecurity)
	data, err := os.ReadFile(f.audit.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("unsafe audit file was modified: %s", data)
	}
}
