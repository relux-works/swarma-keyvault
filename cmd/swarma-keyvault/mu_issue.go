package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

const muIssueUsage = "swarma-keyvault grants mu-issue --kind grant|mac-agent|publisher --spec FILE --owner-spki-der FILE [--subject-spki-der FILE]"

// muOwnerAddress is the owner grant root: the same Secure Enclave key, with
// Touch ID presence, that the existing owner issuance route signs with.
var muOwnerAddress = keyvault.Address{Kind: keyvault.KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1}

// errMUOwnerKey refuses a resolved key that is not the pinned owner root.
var errMUOwnerKey = errors.New("mu-owner-key-mismatch")

// runMUIssue signs one owner-root record (grant/1 or attestation/1) through
// the existing owner issuance route: the typed record is built and its Touch
// ID reason (decision 154) admitted first; the manager is constructed only
// then, with that reason bound to the exact digest; the resolved key must be
// the pinned enclave presence key whose SPKI equals the given owner DER; the
// full rendering is written immediately before the private call; the native
// signature is assembled and verified under the root before any output. A
// failure performs no retry, key creation or store fallback.
func runMUIssue(args []string, stdout, stderr io.Writer) int {
	usage := func() int { fmt.Fprintln(stderr, muIssueUsage); return 2 }
	f := flag.NewFlagSet("mu-issue", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var kind, spec, owner, subject onceString
	f.Var(&kind, "kind", "grant, mac-agent or publisher")
	f.Var(&spec, "spec", "JSON specification file")
	f.Var(&owner, "owner-spki-der", "independently expected owner root public key, SPKI DER")
	f.Var(&subject, "subject-spki-der", "attested key, SPKI DER (attestations only)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, muIssueUsage)
			return 0
		}
		return usage()
	}
	attestation := kind.value == "mac-agent" || kind.value == "publisher"
	if f.NArg() != 0 || !kind.set || !spec.set || !owner.set || spec.value == "" || spec.value == "-" || owner.value == "" || owner.value == "-" ||
		(kind.value != "grant" && !attestation) || subject.set != attestation || (attestation && (subject.value == "" || subject.value == "-")) {
		return usage()
	}
	raw, err := readInput(spec.value, nil, 16384)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded specification")
		return 1
	}
	pin, err := readInput(owner.value, nil, muSPKIMax)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded owner public key")
		return 1
	}
	root, err := mugrant.KeyIDFromSPKI(pin)
	if err != nil {
		fmt.Fprintln(stderr, "owner public key refused: not a P-256 SPKI DER")
		return 1
	}
	var (
		plan                      *mugrant.Plan
		issuer, reason, rendering string
	)
	if attestation {
		spki, err := readInput(subject.value, nil, muSPKIMax)
		if err != nil {
			fmt.Fprintln(stderr, "cannot read bounded subject public key")
			return 1
		}
		a, err := muAttestationFromSpec(raw, spki)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if a.kind != kind.value {
			fmt.Fprintln(stderr, "attestation specification refused: kind differs from --kind")
			return 1
		}
		plan, issuer, reason, rendering = a.plan, a.issuer, a.reason, a.rendering
	} else {
		g, gIssuer, err := muGrantFromSpec(raw)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if reason, err = g.Reason(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		plan, issuer, rendering = g.Plan(), gIssuer, g.Rendering()
	}
	if issuer != root {
		fmt.Fprintln(stderr, "specification refused: issuer is not the given owner root")
		return 1
	}
	digest := plan.Digest()
	prompt := func(d []byte) string {
		if !bytes.Equal(d, digest[:]) {
			return ""
		}
		return reason
	}
	result, err := newIssueManager(prompt).SignIfKey(muOwnerAddress, digest[:], func(key keyvault.ResolvedSigningKey) error {
		if key.Address != muOwnerAddress || key.Store != keyvault.StoreEnclave || !key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, pin) {
			return errMUOwnerKey
		}
		text := rendering + "Touch ID reason: " + reason + "\n"
		if n, err := io.WriteString(stderr, text); err != nil {
			return err
		} else if n != len(text) {
			return io.ErrShortWrite
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "owner signing refused or unavailable")
		return 1
	}
	der, err := result.Signature.Encode(keyvault.FormatSignatureDERLowS)
	if err != nil {
		fmt.Fprintln(stderr, "owner signature unusable")
		return 1
	}
	wire, err := mugrant.AssembleNative(plan, der)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if n, err := stdout.Write(wire); err != nil || n != len(wire) {
		return 1
	}
	return 0
}
