package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
	"github.com/relux-works/swarma-keyvault/internal/ownerkey"
)

const muIssueUsage = "swarma-keyvault grants mu-issue --kind grant|mac-agent|publisher|publisher-ed25519 --spec FILE --owner-spki-der FILE" + ownerAddressUsage + " (--subject-spki-der FILE | --subject-attestation FILE --publisher-attestation FILE)"

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
	ownerKey := addOwnerAddressFlags(f)
	var kind, spec, owner, subject, agentAtt, publisherAtt onceString
	f.Var(&kind, "kind", "grant, mac-agent, publisher or publisher-ed25519")
	f.Var(&spec, "spec", "JSON specification file")
	f.Var(&owner, "owner-spki-der", "independently expected owner root public key, SPKI DER")
	f.Var(&subject, "subject-spki-der", "attested key, SPKI DER (attestations only)")
	f.Var(&agentAtt, "subject-attestation", "owner-root Mac agent attestation of the grantee (grants only)")
	f.Var(&publisherAtt, "publisher-attestation", "owner-root publisher attestation (grants only)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, muIssueUsage)
			return 0
		}
		return usage()
	}
	attestation := kind.value == "mac-agent" || kind.value == "publisher" || kind.value == "publisher-ed25519"
	if f.NArg() != 0 || !kind.set || !spec.set || !owner.set || spec.value == "" || spec.value == "-" || owner.value == "" || owner.value == "-" ||
		(kind.value != "grant" && !attestation) || subject.set != attestation || (attestation && (subject.value == "" || subject.value == "-")) ||
		agentAtt.set == attestation || publisherAtt.set == attestation ||
		(!attestation && (agentAtt.value == "" || agentAtt.value == "-" || publisherAtt.value == "" || publisherAtt.value == "-")) {
		return usage()
	}
	address, err := ownerKey.address()
	if err != nil {
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
		agent, err1 := readInput(agentAtt.value, nil, mugrant.MaxEnvelopeBytes)
		publisher, err2 := readInput(publisherAtt.value, nil, mugrant.MaxEnvelopeBytes)
		if err1 != nil || err2 != nil {
			fmt.Fprintln(stderr, "cannot read bounded attestations")
			return 1
		}
		g, gIssuer, err := muGrantFromSpec(raw, agent, publisher)
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
	if err := ownerkey.CheckPresenceReason(address, reason); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	digest := plan.Digest()
	prompt := func(d []byte) string {
		if !bytes.Equal(d, digest[:]) {
			return ""
		}
		return reason
	}
	result, err := newIssueManager(prompt).SignIfKey(address, digest[:], func(key keyvault.ResolvedSigningKey) error {
		if key.Address != address || key.Store != keyvault.StoreEnclave || !key.UserPresence || key.Extraction != keyvault.ExtractionNone || !bytes.Equal(key.SPKI, pin) {
			return errMUOwnerKey
		}
		text := "Owner key pin: " + ownerkey.PublicPin(address, pin) + rendering + "Touch ID reason: " + reason + "\n"
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
