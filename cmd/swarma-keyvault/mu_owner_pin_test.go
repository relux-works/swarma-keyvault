package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

// Both public preparation families admit only complete, unique, supported owner
// configuration before reading files. A valid configuration reaches file input;
// none of these public-only cases resolves or signs with a vault key.
func TestMUPreparationOwnerAdmission(t *testing.T) {
	f := newMUIssueFixture(t, nil)
	for _, command := range []string{"mu-attestation-prepare", "mu-grant-prepare"} {
		base := []string{"grants", command, "--spec", "missing-spec.json"}
		if command == "mu-attestation-prepare" {
			base = append(base, "--subject-spki-der", "missing-subject.der")
		} else {
			base = append(base, "--subject-attestation", "missing-agent.json", "--publisher-attestation", "missing-publisher.json")
		}
		valid := []string{"--owner-key", "synthetic-mu-owner/grants-owner-v1", "--owner-key-version", "12", "--owner-spki-der", f.ownerPin}
		for _, extra := range [][]string{
			nil, valid[:2], valid[:4],
			{"--owner-key", "synthetic-mu-owner/grants-owner-v2", "--owner-key-version", "12", "--owner-spki-der", f.ownerPin},
			{"--owner-key", "synthetic-mu-owner/grants-owner-v1", "--owner-key-version", "01", "--owner-spki-der", f.ownerPin},
			append(append([]string{}, valid...), "--owner-key", "another/grants-owner-v1"),
			append(append([]string{}, valid...), "--owner-key-version", "13"),
			append(append([]string{}, valid...), "--owner-spki-der", f.ownerPin),
		} {
			if code, out, _ := muCLIRun(append(append([]string{}, base...), extra...)...); code != 2 || out != "" {
				t.Fatal("invalid owner configuration reached preparation", command, code)
			}
		}
		if code, out, _ := muCLIRun(append(base, valid...)...); code != 1 || out != "" {
			t.Fatal("valid owner did not reach missing input", command, code)
		}
	}
	if f.store.factories != 0 || f.store.signs != 0 {
		t.Fatal("public preparation reached custody")
	}
}

// Address-only substitution changes the public association in both preparation
// and issuance rendering, while deterministic attestation body/digest bytes stay
// identical to the existing builder. The fake gate rejects an unenrolled address
// or a different owner DER without a signature; this is software qualification.
func TestMUConfiguredOwnerPinEndToEnd(t *testing.T) {
	for _, kind := range []string{"mac-agent", "publisher", "publisher-ed25519"} {
		t.Run(kind, func(t *testing.T) {
			f := newMUIssueFixture(t, nil)
			if kind == "publisher-ed25519" {
				f.subject = muCLIWrite(t, "ed25519.der", muEd25519SPKI(t))
			}
			spec := muAttestSpec(kind, f.root)
			path := muCLIWrite(t, "spec.json", spec)
			var first map[string]string
			for _, service := range []string{"synthetic-mu-owner", "alternate-mu-owner"} {
				address := signerclient.Address{Kind: signerclient.KindKey, Service: service, Purpose: ownerkey.GrantPurpose, Version: 12}
				flags := []string{"--owner-key", service + "/grants-owner-v1", "--owner-key-version", "12", "--owner-spki-der", f.ownerPin}
				args := append([]string{"grants", "mu-attestation-prepare", "--spec", path, "--subject-spki-der", f.subject}, flags...)
				code, wire, diagnostic := muCLIRun(args...)
				if code != 0 || diagnostic != "" {
					t.Fatal("prepare", code, diagnostic)
				}
				var prepared map[string]string
				if err := json.Unmarshal([]byte(wire), &prepared); err != nil {
					t.Fatal(err)
				}
				pin := ownerkey.PublicPin(address, muSPKI(t, f.owner))
				if prepared["owner_key_pin"] != pin || !strings.HasPrefix(prepared["rendering"], "Owner key pin: "+pin) {
					t.Fatal("preparation omitted exact association")
				}
				raw, _ := base64.RawURLEncoding.DecodeString(prepared["body"])
				subject, err := readInput(f.subject, nil, muSPKIMax)
				if err != nil {
					t.Fatal(err)
				}
				specRaw, _ := json.Marshal(spec)
				canonical, err := muAttestationFromSpec(specRaw, subject)
				if err != nil || !bytes.Equal(raw, canonical.plan.Body()) {
					t.Fatal("canonical signed body changed", err)
				}
				if first != nil && (first["body"] != prepared["body"] || first["digest_sha256"] != prepared["digest_sha256"] || first["owner_key_pin"] == prepared["owner_key_pin"]) {
					t.Fatal("address substitution failed to preserve signed bytes or change pin")
				}
				first = prepared
				issue := append([]string{"grants", "mu-issue", "--kind", kind, "--spec", path, "--subject-spki-der", f.subject}, flags...)
				before := f.store.signs
				if service != "synthetic-mu-owner" {
					code, wire, _ := muCLIRun(issue...)
					if code != 1 || wire != "" || f.store.signs != before {
						t.Fatal("unenrolled address signed")
					}
					rec, problem := keyvault.DecodeRecord(f.store.item.Tag)
					if problem != "" {
						t.Fatal(problem)
					}
					rec.Service = service
					f.store.item.Label = rec.Label()
					f.store.item.Tag, err = keyvault.EncodeRecord(rec)
					if err != nil {
						t.Fatal(err)
					}
				}
				code, wire, review := muCLIRun(issue...)
				if code != 0 || wire == "" || f.store.signs != before+1 || !strings.HasPrefix(review, "Owner key pin: "+pin) {
					t.Fatal("issuance association differs", code, review)
				}
				envelope := f.verifyWire("attestation/1", wire)
				issuedBody, _ := json.Marshal(envelope["body"])
				var want any
				if err := json.Unmarshal(raw, &want); err != nil {
					t.Fatal(err)
				}
				wantBody, _ := json.Marshal(want)
				if !bytes.Equal(issuedBody, wantBody) {
					t.Fatal("issuance signed different body")
				}
			}
			other, _ := muCLIKey(t)
			wrong := []string{"--owner-key", "alternate-mu-owner/grants-owner-v1", "--owner-key-version", "12", "--owner-spki-der", muCLIWrite(t, "wrong.der", muSPKI(t, other))}
			before := f.store.signs
			for _, command := range []string{"mu-attestation-prepare", "mu-issue"} {
				args := []string{"grants", command, "--spec", path, "--subject-spki-der", f.subject}
				if command == "mu-issue" {
					args = append(args, "--kind", kind)
				}
				code, wire, _ := muCLIRun(append(args, wrong...)...)
				if code != 1 || wire != "" || f.store.signs != before {
					t.Fatal("wrong root produced output/signature")
				}
			}
		})
	}
}

// Grant preparation and issuance show the same configured address/SPKI pin.
// Changing only that address changes the public association, and a substituted
// root DER refuses before output or custody. Existing fresh-nonce policy remains.
func TestMUGrantPreparationOwnerPin(t *testing.T) {
	f := newMUIssueFixture(t, nil)
	spec := muCLIWrite(t, "grant-spec.json", muGrantSpecMap(f.root, f.agentID))
	attestations := muAttestFiles(t, f.owner, f.root, f.agent, "@agent:example.invalid")
	var first string
	for _, service := range []string{"synthetic-mu-owner", "alternate-mu-owner"} {
		address := signerclient.Address{Kind: signerclient.KindKey, Service: service, Purpose: ownerkey.GrantPurpose, Version: 12}
		flags := []string{"--owner-key", service + "/grants-owner-v1", "--owner-key-version", "12", "--owner-spki-der", f.ownerPin}
		args := append([]string{"grants", "mu-grant-prepare", "--spec", spec}, attestations...)
		code, wire, diagnostic := muCLIRun(append(args, flags...)...)
		if code != 0 || diagnostic != "" {
			t.Fatal("grant preparation", code, diagnostic)
		}
		var prepared map[string]string
		if err := json.Unmarshal([]byte(wire), &prepared); err != nil {
			t.Fatal(err)
		}
		pin := ownerkey.PublicPin(address, muSPKI(t, f.owner))
		if prepared["owner_key_pin"] != pin || !strings.HasPrefix(prepared["rendering"], "Owner key pin: "+pin) || first == pin {
			t.Fatal("grant public association missing or unchanged")
		}
		first = pin
		rec, problem := keyvault.DecodeRecord(f.store.item.Tag)
		if problem != "" {
			t.Fatal(problem)
		}
		rec.Service = service
		f.store.item.Label = rec.Label()
		var err error
		f.store.item.Tag, err = keyvault.EncodeRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		issue := append([]string{"grants", "mu-issue", "--kind", "grant", "--spec", spec}, attestations...)
		code, wire, review := muCLIRun(append(issue, flags...)...)
		if code != 0 || wire == "" || !strings.HasPrefix(review, "Owner key pin: "+prepared["owner_key_pin"]) {
			t.Fatal("grant issuance association differs", code, review)
		}
		f.verifyWire("grant/1", wire)
	}
	before := f.store.factories
	other, _ := muCLIKey(t)
	flags := muPrepareOwnerArgs(t, other)
	args := append([]string{"grants", "mu-grant-prepare", "--spec", spec}, attestations...)
	code, wire, _ := muCLIRun(append(args, flags...)...)
	if code != 1 || wire != "" || f.store.factories != before {
		t.Fatal("wrong grant preparation root admitted")
	}
}
