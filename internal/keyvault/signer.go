package keyvault

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// ContractError is the error contract (model §8) as data: every error the
// Manager or a command produces maps onto one of these. Failure marks the
// operational class (CLI exit 1) as opposed to a policy refusal (exit 3).
type ContractError struct {
	Code    string
	Message string
	Hint    string
	Status  int
	Failure bool
}

// ClassifyError maps an error onto the contract: a Refusal keeps its code,
// ErrNotFound is not_found (with the nearest-version hint when the error
// carries one), a raw StatusError is translated, anything else is failure.
// The exit class comes from the registry row of the code
// (signerclient.ErrorContract, the single source); a Refusal whose code
// has no row — a programming error, not a contract state — keeps its own
// Failure flag so the caller still gets a class.
func ClassifyError(err error) ContractError {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return registered(ContractError{Code: refusal.Code, Message: refusal.Message, Hint: refusal.Hint, Status: refusal.Status, Failure: refusal.Failure})
	}
	if errors.Is(err, ErrNotFound) {
		hint := "list shows every record"
		var h interface{ Hint() string }
		if errors.As(err, &h) {
			hint = h.Hint()
		}
		return registered(ContractError{Code: CodeNotFound, Message: err.Error(), Hint: hint})
	}
	var status *StatusError
	if errors.As(err, &status) {
		return ClassifyError(Translate(status.Op, err))
	}
	return registered(ContractError{Code: CodeFailure, Message: err.Error(), Hint: "check the path or environment named in the message and rerun"})
}

// registered sets the exit class of c from its registry row.
func registered(c ContractError) ContractError {
	if row, ok := signerclient.Lookup(c.Code); ok {
		c.Failure = row.Exit == signerclient.ExitFailure
	}
	return c
}

// View is the flat JSON a read command prints and describe returns over
// the signer contract: the record plus derived label, fingerprint,
// exposure, operations and findings. Numeric meta is re-emitted
// digit-exact (json.Number).
func (k Key) View(now time.Time) map[string]any {
	view := map[string]any{}
	raw, _ := json.Marshal(k.Record)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&view)
	ops, findings := k.Findings(now)
	if findings == nil {
		findings = []string{}
	}
	view["label"] = k.Label
	view["fingerprint"] = k.Fingerprint()
	view["exposure"] = Exposure(k.Record)
	view["operations"] = ops
	view["findings"] = findings
	return view
}

// SignerServer serves the signer contract (signerclient, contract 1) for
// one address over JSON lines: the vault side of `mac-keyvault signer
// serve`. The address is resolved once, for the hello: a version of 0
// selects the newest generation at that moment, and the generation the
// hello names is pinned for the life of the stream (review rev1 F1), so a
// rotate after the hello never makes a later request answer with a key
// the consumer did not attest. Every operation runs the same gates as the
// CLI command of the same name — the contract adds no path around them.
type SignerServer struct {
	Manager     *Manager
	Address     Address
	ToolVersion string
	// bound is Address with the version the hello resolved; every
	// operation after the hello addresses exactly this generation.
	bound Address
}

// Serve writes the hello line, then answers each stdin line with exactly
// one response line until EOF, and returns nil. A startup failure (the
// address does not resolve) is written as a hello with ok=false and
// returned so the caller maps it to an exit code; a write failure is
// returned as is. No request, malformed or refused, ends the loop.
func (s *SignerServer) Serve(in io.Reader, out io.Writer) error {
	key, err := s.Manager.Describe(s.Address)
	if err != nil {
		hello := signerclient.Response{Contract: signerclient.Contract, Error: wireError(err)}
		if writeErr := writeLine(out, hello); writeErr != nil {
			return writeErr
		}
		return err
	}
	s.bound = pinGeneration(s.Address, key)
	hello := signerclient.Hello{Tool: "mac-keyvault", ToolVersion: s.ToolVersion, Address: s.bound.Service + "/" + s.bound.Purpose, Kind: s.bound.Kind, Version: s.bound.Version,
		Label: key.Label, Fingerprint: key.Fingerprint(), Ops: signerclient.Ops}
	if err := writeLine(out, signerclient.Response{Contract: signerclient.Contract, OK: true, Result: mustJSON(hello)}); err != nil {
		return err
	}
	reader := bufio.NewReader(in)
	for {
		line, readErr := reader.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) != 0 {
			if err := writeLine(out, s.handle(trimmed)); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// pinGeneration returns addr with the version of the generation the hello
// resolved to, so a version-0 request no longer follows the newest
// generation after the hello. The label is the vault's own naming and
// always parses for a key Describe returned; a label that does not parse
// leaves the requested version, which the startup path has already
// resolved once and which cannot be a rotate target of its own.
func pinGeneration(addr Address, key Key) Address {
	if parsed, ok := ParseLabel(key.Label); ok {
		addr.Version = parsed.Version
	}
	return addr
}

// wireJSON encodes one value compactly without HTML escaping (a hint may
// contain "<"), so a line reads as written.
func wireJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func writeLine(out io.Writer, resp signerclient.Response) error {
	data, err := wireJSON(resp)
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}

func mustJSON(v any) json.RawMessage {
	data, err := wireJSON(v)
	if err != nil {
		panic(err)
	}
	return data
}

func wireError(err error) *signerclient.Error {
	c := ClassifyError(err)
	return &signerclient.Error{Code: c.Code, Message: c.Message, Hint: c.Hint, OSStatus: c.Status}
}

// badRequest is a parameter the server cannot read for the op: it is
// answered before any store call.
func badRequest(format string, args ...any) *signerclient.Error {
	return &signerclient.Error{Code: signerclient.CodeBadRequest, Message: fmt.Sprintf(format, args...), Hint: "requests are one JSON object per line: {id, op, ...params}; see the signerclient package for the fields each op takes"}
}

var nullID = json.RawMessage("null")

// allowedMembers is, per op, the closed set of request members the op
// takes. The gate is on presence, not value: a member outside the set is
// bad_request even when its JSON value is the type's zero value ("" or
// false), because a decoded struct cannot tell an explicit false from an
// absent member (review rev2 F2). id and op are common to every op.
var allowedMembers = map[string]map[string]bool{
	signerclient.OpDescribe: {},
	signerclient.OpPub:      {"format": true},
	signerclient.OpSign:     {"format": true, "digest": true},
	signerclient.OpVerify:   {"format": true, "digest": true, "signature": true, "allow_high_s": true},
}

// handle answers one non-blank line. Gates in order: the line is one JSON
// object with no member repeated (bad_request under id null), id is a
// string or number (missing_id), op is a string in Ops (unknown_op),
// every member is one the op takes (bad_request, presence), the members
// decode into their types (bad_request); then the op's own value checks,
// then the Manager's gates.
func (s *SignerServer) handle(line []byte) signerclient.Response {
	// The line is read token by token into its raw members first
	// (signerclient.DecodeObject: source order, a repeated member name —
	// verbatim or escape-spelt — is refused before any value is read,
	// because a map or struct decode would keep one of the two values
	// and the gate would judge a request the caller did not send; review
	// rev6 F1), so that a request is answered under its own id whatever
	// else is wrong with it, and so that member presence is judged
	// before any value is decoded; a line that is not one JSON object,
	// or that repeats a member, is answered under id null.
	members, err := signerclient.DecodeObject(line)
	if err != nil {
		return signerclient.Response{ID: nullID, Error: badRequest("line is not one JSON object: %v", err)}
	}
	id, _ := members.Get("id")
	if !validID(id) {
		return signerclient.Response{ID: nullID, Error: &signerclient.Error{Code: signerclient.CodeMissingID, Message: "id is required and must be a JSON string or number", Hint: "send {\"id\": <string|number>, \"op\": ...}; the id is echoed in the response"}}
	}
	var op string
	if raw, ok := members.Get("op"); !ok || json.Unmarshal(raw, &op) != nil {
		op = strings.TrimSpace(string(raw))
	}
	allowed, known := allowedMembers[op]
	if !known {
		return signerclient.Response{ID: id, Error: &signerclient.Error{Code: signerclient.CodeUnknownOp, Message: fmt.Sprintf("unknown op %q", op), Hint: "ops are describe, pub, sign, verify"}}
	}
	if err := requireMembers(op, members, allowed); err != nil {
		return signerclient.Response{ID: id, Error: err}
	}
	var req signerclient.Request
	if err := DecodeSingleJSON(line, &req); err != nil {
		return signerclient.Response{ID: id, Error: badRequest("request member has the wrong type: %v", err)}
	}
	var result any
	var wireErr *signerclient.Error
	switch op {
	case signerclient.OpDescribe:
		result, wireErr = s.describe()
	case signerclient.OpPub:
		result, wireErr = s.pub(req)
	case signerclient.OpSign:
		result, wireErr = s.sign(req)
	case signerclient.OpVerify:
		result, wireErr = s.verify(req)
	}
	resp := signerclient.Response{ID: id, OK: wireErr == nil, Error: wireErr}
	if result != nil {
		resp.Result = mustJSON(result)
	}
	return resp
}

// requireMembers refuses any member of the request that op does not take,
// by name, before its value is looked at: a digest sent to describe, an
// allow_high_s sent to sign (true or false), a signature of "" sent to
// pub, or a member the contract does not define at all.
func requireMembers(op string, members signerclient.Object, allowed map[string]bool) *signerclient.Error {
	var extra []string
	for _, name := range members.Names() {
		if name == "id" || name == "op" || allowed[name] {
			continue
		}
		extra = append(extra, name)
	}
	if len(extra) == 0 {
		return nil
	}
	sort.Strings(extra)
	takes := make([]string, 0, len(allowed))
	for name := range allowed {
		takes = append(takes, name)
	}
	sort.Strings(takes)
	if len(takes) == 0 {
		return badRequest("%s takes no members besides id and op (got %s)", op, strings.Join(extra, ", "))
	}
	return badRequest("%s takes only %s besides id and op (got %s)", op, strings.Join(takes, ", "), strings.Join(extra, ", "))
}

// validID accepts a JSON string or number: the shapes a client can compare
// without deep equality.
func validID(id json.RawMessage) bool {
	if len(id) == 0 || bytes.Equal(id, nullID) {
		return false
	}
	var v any
	if err := json.Unmarshal(id, &v); err != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

func (s *SignerServer) describe() (any, *signerclient.Error) {
	key, err := s.Manager.Describe(s.bound)
	if err != nil {
		return nil, wireError(err)
	}
	return key.View(s.Manager.now()), nil
}

func (s *SignerServer) pub(req signerclient.Request) (any, *signerclient.Error) {
	format := req.Format
	switch format {
	case "":
		format = signerclient.FormatSPKIDER
	case signerclient.FormatSPKIDER, signerclient.FormatSPKIPEM:
	default:
		return nil, badRequest("pub format must be %s or %s, got %q", signerclient.FormatSPKIDER, signerclient.FormatSPKIPEM, format)
	}
	key, err := s.Manager.Describe(s.bound)
	if err != nil {
		return nil, wireError(err)
	}
	if len(key.SPKI) == 0 {
		return nil, wireError(&Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("public key of %s is unreadable; fingerprint unknown", key.Label), Hint: "describe shows the findings; rotate the record"})
	}
	pub := signerclient.PublicKey{Label: key.Label, Fingerprint: key.Fingerprint(), Format: format}
	if format == signerclient.FormatSPKIPEM {
		pub.PEM = string(EncodePEM(key.SPKI))
	} else {
		pub.DERBase64 = base64.StdEncoding.EncodeToString(key.SPKI)
	}
	return pub, nil
}

// digestParam reads the digest parameter: hex the server can read
// (bad_request otherwise), then the length gate (invalid_digest).
func digestParam(req signerclient.Request) ([]byte, *signerclient.Error) {
	if req.Digest == "" {
		return nil, badRequest("%s requires digest: the SHA-256 digest as 64 hex characters", req.Op)
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		return nil, badRequest("digest must be hex: %v", err)
	}
	if err := ValidateDigest(digest); err != nil {
		wireErr := wireError(err)
		wireErr.Hint = "digest is the SHA-256 digest of the payload as 64 hex characters; nothing was " + map[string]string{signerclient.OpSign: "signed", signerclient.OpVerify: "verified"}[req.Op]
		return nil, wireErr
	}
	return digest, nil
}

func signatureFormatParam(req signerclient.Request, fallback string) (string, *signerclient.Error) {
	switch req.Format {
	case "":
		return fallback, nil
	case signerclient.FormatDERLowS, signerclient.FormatRaw:
		return req.Format, nil
	}
	return "", badRequest("%s format must be %s or %s, got %q", req.Op, signerclient.FormatDERLowS, signerclient.FormatRaw, req.Format)
}

func (s *SignerServer) sign(req signerclient.Request) (any, *signerclient.Error) {
	if _, err := signatureFormatParam(req, ""); err != nil {
		return nil, err
	}
	digest, wireErr := digestParam(req)
	if wireErr != nil {
		return nil, wireErr
	}
	signed, err := s.Manager.Sign(s.bound, digest)
	if err != nil {
		return nil, wireError(err)
	}
	format, _ := signatureFormatParam(req, signed.Key.Record.Format.Signature)
	if format != signerclient.FormatRaw {
		format = signerclient.FormatDERLowS
	}
	payload, err := signed.Signature.Encode(format)
	if err != nil {
		return nil, wireError(err)
	}
	return signerclient.Signature{Label: signed.Key.Label, Fingerprint: signed.Key.Fingerprint(), Hash: signerclient.Hash, Digest: hex.EncodeToString(digest), Format: format,
		Signature: hex.EncodeToString(payload), SignatureBase64: base64.StdEncoding.EncodeToString(payload), LowS: true, Normalized: signed.Normalized}, nil
}

// verify judges digest, signature and the address's public key. As in the
// CLI, malformed and high-S signatures are refused on the bytes alone,
// before the vault is read.
func (s *SignerServer) verify(req signerclient.Request) (any, *signerclient.Error) {
	format, wireErr := signatureFormatParam(req, signerclient.FormatDERLowS)
	if wireErr != nil {
		return nil, wireErr
	}
	digest, wireErr := digestParam(req)
	if wireErr != nil {
		return nil, wireErr
	}
	if req.Signature == "" {
		return nil, badRequest("verify requires signature: the signature bytes as hex")
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, badRequest("signature must be hex: %v", err)
	}
	sig, err := ParseSignature(sigBytes, format)
	if err != nil {
		return nil, wireError(err)
	}
	verdict := signerclient.Verdict{Hash: signerclient.Hash, Digest: hex.EncodeToString(digest), Format: format, LowS: sig.IsLowS(), HighSAllowed: req.AllowHighS}
	if !sig.IsLowS() && !req.AllowHighS {
		return verdict, wireError(&Refusal{Code: CodeHighSRefused, Message: "signature s is in the high half of the P-256 order (malleable form); the vault only accepts low-S signatures", Hint: "signatures made by mac-keyvault are always low-S; set allow_high_s to accept this one knowingly"})
	}
	key, err := s.Manager.PublicKeyFor(s.bound)
	if err != nil {
		return nil, wireError(err)
	}
	verdict.Label, verdict.Fingerprint = key.Label, key.Fingerprint()
	verified, err := VerifyDigest(key.SPKI, digest, sig)
	if err != nil {
		return nil, wireError(err)
	}
	verdict.Verified = verified
	if !verified {
		return verdict, wireError(&Refusal{Code: CodeSignatureInvalid, Failure: true, Message: "signature does not verify over the digest under this public key", Hint: "the digest, the signature or the key is not the one that was signed; verdict false"})
	}
	return verdict, nil
}

// WriteStartupFailure writes the hello line of a server that cannot
// start (usage or address refused before the vault is opened): contract 1,
// ok=false, the error — one line, the same shape Serve writes when the
// address does not resolve, so a client reads exactly one line either way.
func WriteStartupFailure(out io.Writer, e ContractError) error {
	return writeLine(out, signerclient.Response{Contract: signerclient.Contract, Error: &signerclient.Error{Code: e.Code, Message: e.Message, Hint: e.Hint, OSStatus: e.Status}})
}
