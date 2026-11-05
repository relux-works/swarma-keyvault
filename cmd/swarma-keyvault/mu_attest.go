package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Owner-root attestations for the sitting (contract X9 and r5). Prepare prints
// the exact canonical attestation/1 body, its signing digest, the subject key
// id and a pre-sign rendering. The installed keyvault signs the digest under
// the owner root; mu-assemble binds that native DER signature. No key is used
// here.

type muAttestationSpecFile struct {
	Kind       string `json:"kind"`
	Issuer     string `json:"issuer"`
	MXID       string `json:"mxid"`
	Generation int64  `json:"generation"`
	NotBefore  string `json:"not_before"`
	Expires    string `json:"expires"`
}

const muSPKIMax = 512

func muSPKIArg(name, extra string, args []string, stderr io.Writer) (spec, spki string, code int) {
	usageText := "swarma-keyvault grants " + name + extra + " --subject-spki-der FILE"
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var s, k onceString
	if extra != "" {
		f.Var(&s, "spec", "JSON specification file")
	}
	f.Var(&k, "subject-spki-der", "subject public key, SPKI DER")
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, usageText)
		if errors.Is(err, flag.ErrHelp) {
			return "", "", 0
		}
		return "", "", 2
	}
	if f.NArg() != 0 || !k.set || k.value == "" || k.value == "-" || (extra != "" && (!s.set || s.value == "" || s.value == "-")) {
		fmt.Fprintln(stderr, usageText)
		return "", "", 2
	}
	return s.value, k.value, -1
}

// runMUKeyID prints the p256 key id of an SPKI DER public key, for specs and
// the receiver configuration.
func runMUKeyID(args []string, stdout, stderr io.Writer) int {
	_, spkiPath, code := muSPKIArg("mu-key-id", "", args, stderr)
	if code >= 0 {
		return code
	}
	spki, err := readInput(spkiPath, nil, muSPKIMax)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded public key")
		return 1
	}
	id, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		fmt.Fprintln(stderr, "public key refused: not a P-256 SPKI DER")
		return 1
	}
	return muWrite(stdout, map[string]string{"type": "mu-key-id-1", "key": id})
}

// muAttestation is a prepared owner-root attestation.
type muAttestation struct {
	kind              string
	plan              *mugrant.Plan
	issuer, subject   string
	rendering, reason string
}

// muAttestationFromSpec builds the attestation/1 plan, its pre-sign rendering
// and its Touch ID reason; the error text is safe to print.
func muAttestationFromSpec(raw, spki []byte) (*muAttestation, error) {
	var s muAttestationSpecFile
	if err := muStrictJSON(raw, &s); err != nil {
		return nil, fmt.Errorf("attestation specification refused: %w", err)
	}
	nb, err1 := muTime(s.NotBefore)
	ex, err2 := muTime(s.Expires)
	if err1 != nil || err2 != nil {
		return nil, errors.New("attestation window refused: times must be exactly YYYY-MM-DDTHH:MM:SSZ")
	}
	a := &muAttestation{issuer: s.Issuer, kind: s.Kind}
	var (
		err   error
		lines []string
	)
	switch s.Kind {
	case "mac-agent":
		a.plan, a.subject, err = mugrant.BuildMacAgentAttestation(s.Issuer, spki, s.MXID, s.Generation, nb, ex)
		if err == nil {
			a.reason, err = mugrant.MacAgentAttestationReason(a.plan, s.MXID, s.Generation, nb, ex)
		}
		lines = []string{
			"attestation/1 Mac agent key (profile mac-se-1), to be signed by the owner root under Touch ID",
			"agent: " + s.MXID,
			fmt.Sprintf("generation: %d", s.Generation),
			"may sign: message.sign (requests under grants naming this key)",
		}
	case "publisher":
		if s.MXID != "" || s.Generation != 0 {
			return nil, errors.New("attestation specification refused: a publisher attestation has no mxid or generation")
		}
		a.plan, a.subject, err = mugrant.BuildPublisherAttestation(s.Issuer, spki, nb, ex)
		if err == nil {
			a.reason, err = mugrant.PublisherAttestationReason(a.plan, nb, ex)
		}
		lines = []string{
			"attestation/1 grant revocation publisher key (profile grant-revocation-1), to be signed by the owner root under Touch ID",
			"may sign: revocation.sign (revocation snapshots for grants of this root only)",
		}
	default:
		return nil, errors.New("attestation specification refused: kind must be mac-agent or publisher")
	}
	if err != nil {
		return nil, err
	}
	d := a.plan.Digest()
	lines = append(lines,
		"issuer: "+s.Issuer,
		"subject key: "+a.subject,
		"window UTC: "+s.NotBefore+" – "+s.Expires,
		"content id: "+a.plan.ContentID(),
		"signing digest: "+hex.EncodeToString(d[:]),
	)
	a.rendering = strings.Join(lines, "\n") + "\n"
	return a, nil
}

func runMUAttestationPrepare(args []string, stdout, stderr io.Writer) int {
	specPath, spkiPath, code := muSPKIArg("mu-attestation-prepare", " --spec FILE", args, stderr)
	if code >= 0 {
		return code
	}
	raw, err := readInput(specPath, nil, 16384)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded attestation specification")
		return 1
	}
	spki, err := readInput(spkiPath, nil, muSPKIMax)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded public key")
		return 1
	}
	a, err := muAttestationFromSpec(raw, spki)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	d := a.plan.Digest()
	return muWrite(stdout, map[string]string{
		"type": "mu-attestation-prepared-1", "kind": "attestation/1", "key": a.issuer, "subject_key": a.subject,
		"body": base64.RawURLEncoding.EncodeToString(a.plan.Body()), "content_id": a.plan.ContentID(),
		"digest_sha256": hex.EncodeToString(d[:]), "reason": a.reason, "rendering": a.rendering,
	})
}
