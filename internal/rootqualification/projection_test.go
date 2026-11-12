package rootqualification

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// These independently written KVQP1 vectors fix integer order, byte order,
// native list distinctions and unknown numeric observations. They assert no
// root-storage policy admission and exercise no native API.
func TestProjectionLiteralVectors(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		want       Projection
	}{
		{"empty", "4b56515031000001f5000000140000000000000000", Projection{OwnerUID: 501, OwnerGID: 20, ACLs: []ACLProjection{}}},
		{"null-subject", "4b56515031" + "000001f5000000140000000000000001" +
			"000000000000000100000003616e79" + "0000000200000001ffffffff" +
			"00000000000000000000000000000000" + "000000000000000100000002" + "0000000000000000",
			Projection{OwnerUID: 501, OwnerGID: 20, ACLs: []ACLProjection{{AuthorizationNamesState: "readable", Authorizations: []string{"any"}, AuthorizationNumbers: []uint32{1, 0xffffffff}, ContentsState: "readable", DescriptionState: "null", RawPromptState: "readable", RawPromptVersion: 1, RawPromptFlags: 2, ApplicationsState: "null", Applications: []ApplicationProjection{}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeNativeProjection(raw)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decode: %#v %v", got, err)
			}
			encoded, err := EncodeNativeProjection(tc.want)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatalf("encode: %x %v", encoded, err)
			}
			for n := 0; n < len(raw); n++ {
				if _, err := DecodeNativeProjection(raw[:n]); !errors.Is(err, ErrProjection) {
					t.Fatalf("truncation %d accepted", n)
				}
			}
			if _, err := DecodeNativeProjection(append(bytes.Clone(raw), 0)); !errors.Is(err, ErrProjection) {
				t.Fatal("trailing byte accepted")
			}
		})
	}
}

func projectionFixture() Projection {
	return Projection{OwnerUID: 501, OwnerGID: 20, OwnerType: 2, ACLs: []ACLProjection{{AuthorizationNamesState: "unreadable", Authorizations: []string{}, AuthorizationNumbers: []uint32{0xffffffff, 0xffffffff}, ContentsState: "readable", DescriptionState: "present", Description: "", RawPromptState: "readable", RawPromptVersion: 1, RawPromptFlags: 0x80000000, ApplicationsState: "present", Applications: []ApplicationProjection{{RequirementState: "missing", Requirement: []byte{}}, {RequirementState: "unreadable", Requirement: []byte{}}, {RequirementState: "unexpected-type", Requirement: []byte{}}, {RequirementState: "present", Requirement: []byte{1, 2}, RequirementText: "public requirement fixture"}}}}}
}

// Empty and NULL subjects, duplicate unknown authorizations and opaque
// applications remain distinct observations. Invalid states/partial subjects
// refuse encoding rather than being silently normalized into valid evidence.
func TestProjectionPreservesObservationsAndRefusesMalformedShapes(t *testing.T) {
	valid := projectionFixture()
	for _, state := range []string{"null", "present", "unreadable"} {
		p := projectionFixture()
		p.ACLs[0].ApplicationsState = state
		p.ACLs[0].Applications = []ApplicationProjection{}
		if state == "unreadable" {
			p.ACLs[0].ContentsState = "unreadable"
			p.ACLs[0].DescriptionState = "unreadable"
		}
		raw, err := EncodeNativeProjection(p)
		if err != nil {
			t.Fatalf("valid %s: %v", state, err)
		}
		got, err := DecodeNativeProjection(raw)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatalf("lost %s observation", state)
		}
	}
	for name, mutate := range map[string]func(*Projection){
		"unknown-state":                     func(p *Projection) { p.ACLs[0].ContentsState = "other" },
		"unreadable-names-with-values":      func(p *Projection) { p.ACLs[0].Authorizations = []string{"any"} },
		"null-with-apps":                    func(p *Projection) { p.ACLs[0].ApplicationsState = "null" },
		"null-description-with-text":        func(p *Projection) { p.ACLs[0].DescriptionState = "null"; p.ACLs[0].Description = "text" },
		"unreadable-with-readable-subjects": func(p *Projection) { p.ACLs[0].ContentsState = "unreadable" },
		"missing-with-requirement":          func(p *Projection) { p.ACLs[0].Applications[0].Requirement = []byte{1} },
		"present-empty-requirement":         func(p *Projection) { p.ACLs[0].Applications[3].Requirement = nil },
		"present-empty-text":                func(p *Projection) { p.ACLs[0].Applications[3].RequirementText = "" },
		"wide-prompt":                       func(p *Projection) { p.ACLs[0].PromptBits = 65536 },
		"unreadable-prompt-with-flags":      func(p *Projection) { p.ACLs[0].RawPromptState = "unreadable" },
		"invalid-utf8":                      func(p *Projection) { p.ACLs[0].Description = "\xff" },
		"long-description":                  func(p *Projection) { p.ACLs[0].Description = strings.Repeat("a", 32769) },
		"long-requirement":                  func(p *Projection) { p.ACLs[0].Applications[3].Requirement = make([]byte, 65537) },
		"too-many-acls":                     func(p *Projection) { p.ACLs = make([]ACLProjection, 65) },
		"too-many-authorizations":           func(p *Projection) { p.ACLs[0].AuthorizationNumbers = make([]uint32, 65) },
		"too-many-apps":                     func(p *Projection) { p.ACLs[0].Applications = make([]ApplicationProjection, 65) },
	} {
		t.Run(name, func(t *testing.T) {
			p := projectionFixture()
			mutate(&p)
			if b, err := EncodeNativeProjection(p); !errors.Is(err, ErrProjection) || b != nil {
				t.Fatal("malformed projection encoded")
			}
		})
	}
	raw, err := EncodeNativeProjection(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeNativeProjection(raw)
	if err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatal("valid opaque observations lost")
	}
	// Wire parser controls are independent of the encoder's shape checks.
	for _, offset := range []int{0, 17, 21} {
		bad := bytes.Clone(raw)
		bad[offset] = 0xff
		if _, err := DecodeNativeProjection(bad); !errors.Is(err, ErrProjection) {
			t.Fatalf("corrupt field at %d accepted", offset)
		}
	}
	if _, err := DecodeNativeProjection(make([]byte, 1048577)); !errors.Is(err, ErrProjection) {
		t.Fatal("oversized frame accepted")
	}
}
