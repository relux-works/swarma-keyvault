package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Multi-use owner grant commands (contract r3, seams r1 P2/P4). Prepare prints
// the exact canonical body, its signing digest and, for grants, the full
// pre-sign rendering and the Touch ID reason. The installed keyvault signs the
// digest; assemble binds that native DER signature. No key is used here.

type muEntrySpec struct {
	Action string `json:"action"`
	Kind   string `json:"kind"`
	ID     string `json:"id"`
}

type muGrantSpecFile struct {
	Issuer      string        `json:"issuer"`
	Subject     string        `json:"subject"`
	SubjectMXID string        `json:"subject_mxid"`
	Audience    string        `json:"audience"`
	Entries     []muEntrySpec `json:"entries"`
	NotBefore   string        `json:"not_before"`
	Expires     string        `json:"expires"`
	Use         string        `json:"use"`
}

type muRequestSpecFile struct {
	Author            string            `json:"author"`
	AuthorAttestation string            `json:"author_attestation"`
	Audience          string            `json:"audience"`
	Room              string            `json:"room"`
	To                string            `json:"to"`
	Action            string            `json:"action"`
	Kind              string            `json:"kind"`
	ID                string            `json:"id"`
	Arguments         map[string]string `json:"arguments"`
	Text              string            `json:"text"`
	IssuedAt          string            `json:"issued_at"`
	LifetimeSeconds   int               `json:"lifetime_seconds"`
}

// muStrictJSON decodes exactly one JSON object with no unknown fields.
func muStrictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	var rest any
	if err := d.Decode(&rest); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func muTime(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err != nil || t.Format("2006-01-02T15:04:05Z") != s {
		return time.Time{}, errors.New("time must be exactly YYYY-MM-DDTHH:MM:SSZ")
	}
	return t.UTC(), nil
}

func muNonce() ([]byte, error) {
	n := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, err
	}
	return n, nil
}

func muWrite(w io.Writer, v any) int {
	raw, err := json.Marshal(v)
	if err != nil {
		return 1
	}
	raw = append(raw, '\n')
	if n, err := w.Write(raw); err != nil || n != len(raw) {
		return 1
	}
	return 0
}

func muSpecArg(name string, args []string, stderr io.Writer) (string, int) {
	usageText := "swarma-keyvault grants " + name + " --spec FILE"
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var spec onceString
	f.Var(&spec, "spec", "JSON specification file")
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, usageText)
		if errors.Is(err, flag.ErrHelp) {
			return "", 0
		}
		return "", 2
	}
	if f.NArg() != 0 || !spec.set || spec.value == "" || spec.value == "-" {
		fmt.Fprintln(stderr, usageText)
		return "", 2
	}
	return spec.value, -1
}

const muGrantPrepareUsage = "swarma-keyvault grants mu-grant-prepare --spec FILE --subject-attestation FILE --publisher-attestation FILE"

// muGrantInputs parses the grant flags and reads the spec and both owner-root
// attestations (the grantee's Mac agent attestation and the publisher's).
func muGrantInputs(args []string, stderr io.Writer) (raw, agent, publisher []byte, code int) {
	f := flag.NewFlagSet("mu-grant-prepare", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var spec, agentPath, publisherPath onceString
	f.Var(&spec, "spec", "JSON specification file")
	f.Var(&agentPath, "subject-attestation", "owner-root Mac agent attestation of the grantee key (swarm-envelope/2)")
	f.Var(&publisherPath, "publisher-attestation", "owner-root grant revocation publisher attestation (swarm-envelope/2)")
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, muGrantPrepareUsage)
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, nil, 0
		}
		return nil, nil, nil, 2
	}
	for _, v := range []onceString{spec, agentPath, publisherPath} {
		if !v.set || v.value == "" || v.value == "-" {
			fmt.Fprintln(stderr, muGrantPrepareUsage)
			return nil, nil, nil, 2
		}
	}
	if f.NArg() != 0 {
		fmt.Fprintln(stderr, muGrantPrepareUsage)
		return nil, nil, nil, 2
	}
	var err error
	if raw, err = readInput(spec.value, nil, 16384); err != nil {
		fmt.Fprintln(stderr, "cannot read bounded grant specification")
		return nil, nil, nil, 1
	}
	if agent, err = readInput(agentPath.value, nil, mugrant.MaxEnvelopeBytes); err != nil {
		fmt.Fprintln(stderr, "cannot read bounded subject attestation")
		return nil, nil, nil, 1
	}
	if publisher, err = readInput(publisherPath.value, nil, mugrant.MaxEnvelopeBytes); err != nil {
		fmt.Fprintln(stderr, "cannot read bounded publisher attestation")
		return nil, nil, nil, 1
	}
	return raw, agent, publisher, -1
}

// muGrantFromSpec builds a grant/1 plan bound to both owner-root
// attestations, with a fresh CSPRNG nonce; the error text is safe to print.
func muGrantFromSpec(raw, agent, publisher []byte) (*mugrant.Grant, string, error) {
	var s muGrantSpecFile
	if err := muStrictJSON(raw, &s); err != nil {
		return nil, "", fmt.Errorf("grant specification refused: %w", err)
	}
	nb, err1 := muTime(s.NotBefore)
	ex, err2 := muTime(s.Expires)
	if err1 != nil || err2 != nil {
		return nil, "", errors.New("grant interval refused: times must be exactly YYYY-MM-DDTHH:MM:SSZ")
	}
	nonce, err := muNonce()
	if err != nil {
		return nil, "", errors.New("nonce unavailable")
	}
	spec := mugrant.GrantSpec{Issuer: s.Issuer, Subject: s.Subject, SubjectMXID: s.SubjectMXID, SubjectAttestation: agent,
		PublisherAttestation: publisher, Audience: s.Audience, NotBefore: nb, Expires: ex, Use: s.Use, Nonce: nonce}
	for _, e := range s.Entries {
		spec.Entries = append(spec.Entries, mugrant.Entry{Action: e.Action, Target: mugrant.Target{Kind: e.Kind, ID: e.ID}})
	}
	g, err := mugrant.BuildGrant(spec)
	if err != nil {
		return nil, "", err
	}
	return g, s.Issuer, nil
}

func runMUGrantPrepare(args []string, stdout, stderr io.Writer) int {
	raw, agent, publisher, code := muGrantInputs(args, stderr)
	if code >= 0 {
		return code
	}
	g, issuer, err := muGrantFromSpec(raw, agent, publisher)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	reason, err := g.Reason()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	d := g.Plan().Digest()
	return muWrite(stdout, map[string]string{
		"type": "mu-grant-prepared-1", "kind": "grant/1", "key": issuer,
		"body": base64.RawURLEncoding.EncodeToString(g.Plan().Body()), "content_id": g.Plan().ContentID(),
		"digest_sha256": hex.EncodeToString(d[:]), "reason": reason, "rendering": g.Rendering(),
	})
}

func runMURequestPrepare(args []string, stdout, stderr io.Writer) int {
	path, code := muSpecArg("mu-request-prepare", args, stderr)
	if code >= 0 {
		return code
	}
	raw, err := readInput(path, nil, 16384)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded request specification")
		return 1
	}
	var s muRequestSpecFile
	if err := muStrictJSON(raw, &s); err != nil {
		fmt.Fprintln(stderr, "request specification refused:", err)
		return 1
	}
	issued, err := muTime(s.IssuedAt)
	if err != nil {
		fmt.Fprintln(stderr, "request time refused:", err)
		return 1
	}
	nonce, err := muNonce()
	if err != nil {
		fmt.Fprintln(stderr, "nonce unavailable")
		return 1
	}
	r, err := mugrant.BuildRequest(mugrant.RequestSpec{
		Author: s.Author, AuthorAttestation: s.AuthorAttestation, Audience: s.Audience, Room: s.Room, To: s.To,
		Action: s.Action, Target: mugrant.Target{Kind: s.Kind, ID: s.ID}, Arguments: s.Arguments, Text: s.Text,
		Nonce: nonce, IssuedAt: issued, Lifetime: time.Duration(s.LifetimeSeconds) * time.Second,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	d := r.Plan().Digest()
	return muWrite(stdout, map[string]string{
		"type": "mu-request-prepared-1", "kind": "message/1", "key": s.Author,
		"body": base64.RawURLEncoding.EncodeToString(r.Plan().Body()), "content_id": r.Plan().ContentID(),
		"digest_sha256": hex.EncodeToString(d[:]), "text": r.Text(),
	})
}

func runMUAssemble(args []string, stdout, stderr io.Writer) int {
	usageText := "swarma-keyvault grants mu-assemble --kind grant/1|message/1|attestation/1|revocation/1 --body FILE --key KEY_ID --signature DER_FILE"
	f := flag.NewFlagSet("mu-assemble", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var kind, body, key, signature onceString
	f.Var(&kind, "kind", "record kind")
	f.Var(&body, "body", "exact canonical body bytes from prepare (decoded)")
	f.Var(&key, "key", "signer p256 key id")
	f.Var(&signature, "signature", "native DER P-256 signature over the prepared digest")
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, usageText)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 || !kind.set || !body.set || !key.set || !signature.set || body.value == "-" || signature.value == "-" || (kind.value != "grant/1" && kind.value != "message/1" && kind.value != "attestation/1" && kind.value != "revocation/1") {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	b, err := readInput(body.value, nil, mugrant.MaxEnvelopeBytes)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded body")
		return 1
	}
	der, err := readInput(signature.value, nil, 72)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read bounded signature")
		return 1
	}
	p, err := mugrant.Prepare(kind.value, key.value, b)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	wire, err := mugrant.AssembleNative(p, der)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if n, err := stdout.Write(wire); err != nil || n != len(wire) {
		return 1
	}
	return 0
}
