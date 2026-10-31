package signerclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Result validation (review rev6 F2). Every result the server writes is
// judged by ONE owner, checkResult, inside Call — before any typed helper
// (Describe, PublicKey, Sign, Verify, CryptoSigner) can return success —
// against three things at once: the result shape the op documents
// (members present, non-null, typed, no repeats, nothing undefined), the
// PENDING REQUEST (hash, digest, effective format, allow_high_s), and the
// ACCEPTED HELLO (label, fingerprint, and through the fingerprint the
// public key every signature and verdict is checked under with
// crypto/ecdsa). A mismatch is ErrProtocol: the server is reaped and the
// client is unusable, exactly like a malformed envelope, because a
// signature the attested key did not make — or a verdict the attested key
// does not give — is not a refusal a consumer could act on. The members
// of each result:
//
//	hello:  tool, tool_version, address, kind, version, label, fingerprint, ops   (all required)
//	pub:    label, fingerprint, format, der_base64 (spki-der) | pem (spki-pem)   (exactly one encoding)
//	sign:   label, fingerprint, hash, digest, format, signature, signature_base64, low_s, normalized (all required)
//	verify: hash, digest, format, low_s, high_s_allowed, verified (required); label, fingerprint (required
//	        on ok and on signature_invalid, absent on high_s_refused — the only two refusals that carry a verdict)
//	describe: the record view — the closed schema-2 Record (every member typed by the vault's own
//	        decode, every invariant row applied) plus label, fingerprint, exposure, operations,
//	        findings; identity bound to the hello (checkDescribe)
var (
	helloResultMembers    = []string{"tool", "tool_version", "address", "kind", "version", "label", "fingerprint", "ops"}
	pubResultMembers      = []string{"label", "fingerprint", "format"}
	signResultMembers     = []string{"label", "fingerprint", "hash", "digest", "format", "signature", "signature_base64", "low_s", "normalized"}
	verifyResultMembers   = []string{"hash", "digest", "format", "low_s", "high_s_allowed", "verified"}
	verifyIdentityMembers = []string{"label", "fingerprint"}
	describeResultMembers = []string{"label", "fingerprint", "kind", "version", "service", "purpose", "schema", "exposure", "operations", "findings"}
)

// Fingerprint is the key fingerprint the contract carries in the hello,
// pub, sign and verify results: SHA-256 of the SPKI DER, base64url
// without padding. A consumer compares it with the one it configured.
func Fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseSignature reads signature bytes in a contract signature format:
// FormatDERLowS is a strict X9.62 SEQUENCE {r INTEGER, s INTEGER} with
// nothing after it, FormatRaw is exactly 64 bytes r||s. Both integers
// must be in [1, n-1].
func ParseSignature(data []byte, format string) (r, s *big.Int, err error) {
	switch format {
	case FormatRaw:
		if len(data) != 64 {
			return nil, nil, fmt.Errorf("raw signature is %d bytes, not 64", len(data))
		}
		r, s = new(big.Int).SetBytes(data[:32]), new(big.Int).SetBytes(data[32:])
	case FormatDERLowS:
		var decoded struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(data, &decoded)
		if err != nil {
			return nil, nil, fmt.Errorf("signature is not a DER ECDSA-Sig-Value: %v", err)
		}
		if len(rest) != 0 {
			return nil, nil, fmt.Errorf("signature has %d trailing bytes after the DER SEQUENCE", len(rest))
		}
		r, s = decoded.R, decoded.S
	default:
		return nil, nil, fmt.Errorf("signature format %q is not %s or %s", format, FormatDERLowS, FormatRaw)
	}
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, nil, errors.New("signature integers are outside [1, n-1]")
	}
	return r, s, nil
}

var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// IsLowS reports whether s is in the low half of the P-256 order — the
// form every signature the vault emits has, and the only form verify
// accepts unless allow_high_s is set.
func IsLowS(s *big.Int) bool { return s.Cmp(p256HalfOrder) <= 0 }

// ParseSPKI reads a P-256 SPKI DER into its public key.
func ParseSPKI(der []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("SPKI is %T, not ECDSA", parsed)
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("SPKI curve is %s, not P-256", pub.Curve.Params().Name)
	}
	return pub, nil
}

// resultObject reads a result through DecodeObject and requires every
// name in required present and non-null. When closed is set, any member
// outside required and optional is refused.
func resultObject(result json.RawMessage, required, optional []string, closed bool) (Object, error) {
	obj, err := DecodeObject(result)
	if err != nil {
		return nil, err
	}
	if closed {
		allowed := map[string]bool{}
		for _, name := range required {
			allowed[name] = true
		}
		for _, name := range optional {
			allowed[name] = true
		}
		for _, name := range obj.Names() {
			if !allowed[name] {
				return nil, fmt.Errorf("carries member %q the contract does not define", name)
			}
		}
	}
	for _, name := range required {
		value, present := obj.Get(name)
		switch {
		case !present:
			return nil, fmt.Errorf("has no %s member", name)
		case isLiteral(value, "null"):
			return nil, fmt.Errorf("%s is null", name)
		}
	}
	return obj, nil
}

// decodeHelloResult reads the hello result: all eight members present,
// non-null, typed, nothing else. Whether the values are the binding the
// consumer requested is checkHello's judgement, after this one.
func decodeHelloResult(result json.RawMessage) (Hello, error) {
	if _, err := resultObject(result, helloResultMembers, nil, true); err != nil {
		return Hello{}, err
	}
	var h Hello
	if err := json.Unmarshal(result, &h); err != nil {
		return Hello{}, err
	}
	return h, nil
}

// checkResult is the one owner of result validation: it judges the
// result of a response to req — ok, or a refusal that documents a partial
// result — against the request and the hello, and returns the error a
// mismatch is. pub is the public key the hello attests (fetched through
// the same gate) and is required for sign and verify.
func checkResult(req Request, resp Response, hello Hello, pub *ecdsa.PublicKey) error {
	code := ""
	if resp.Error != nil {
		code = resp.Error.Code
	}
	switch req.Op {
	case OpDescribe:
		if code != "" {
			return nil
		}
		_, err := checkDescribe(resp.Result, hello)
		return err
	case OpPub:
		if code != "" {
			return nil
		}
		return checkPub(req, resp.Result, hello)
	case OpSign:
		if code != "" {
			return nil
		}
		if pub == nil {
			return errors.New("sign: no attested public key to verify the signature under")
		}
		return checkSign(req, resp.Result, hello, pub)
	case OpVerify:
		if pub == nil {
			return errors.New("verify: no attested public key to check the verdict under")
		}
		return checkVerify(req, resp, hello, pub)
	}
	return fmt.Errorf("op %q is not a contract-1 operation", req.Op)
}

func bound(what, got, want string) error {
	if got != want {
		return fmt.Errorf("%s %q, want %q", what, got, want)
	}
	return nil
}

// checkIdentity binds label and fingerprint to the hello.
func checkIdentity(label, fingerprint string, hello Hello) error {
	if err := bound("label", label, hello.Label); err != nil {
		return fmt.Errorf("%v (hello attested another key)", err)
	}
	if err := bound("fingerprint", fingerprint, hello.Fingerprint); err != nil {
		return fmt.Errorf("%v (hello attested another key)", err)
	}
	return nil
}

// checkDescribe judges a describe result the way the vault judges its own
// stored record (review rev7 F1): every member is decoded into the closed
// Description/Record struct through DecodeSingleJSON — wrong JSON type,
// null where a value is required, or a member the schema does not define
// is a break — then the per-kind invariant table and the label agreement
// (ValidateStored, the exact rows Init, Rotate and the reads run) are
// applied, and the record's identity (kind, version, service/purpose,
// label, fingerprint) must be the one the hello bound. The derived
// members are held to what the vault derives: exposure in Exposures and
// unknown exactly when unsupported_primitive is reported (then no
// operations), findings from the read vocabulary with record_invalid
// carrying exactly the code the table raises here, validity_expired only
// on a record with not_after. Stated bounds: the registry (which
// primitive a record maps to and its operation list) stays vault-side, so
// an operation entry is checked for shape and non-empty name/via only;
// and whether not_after has passed is the server clock's call.
func checkDescribe(result json.RawMessage, hello Hello) (Description, error) {
	var d Description
	if _, err := resultObject(result, describeResultMembers, nil, false); err != nil {
		return d, fmt.Errorf("describe result %v", err)
	}
	if err := DecodeSingleJSON(result, &d); err != nil {
		return d, fmt.Errorf("describe result does not decode as a schema-%d record view: %v", SchemaVersion, err)
	}
	if d.Schema != SchemaVersion {
		return d, fmt.Errorf("describe result: schema %d is not %d (the contract serves schema-%d records only)", d.Schema, SchemaVersion, SchemaVersion)
	}
	if err := checkIdentity(d.Label, d.Fingerprint, hello); err != nil {
		return d, fmt.Errorf("describe result: %v", err)
	}
	if err := bound("kind", d.Kind, hello.Kind); err != nil {
		return d, fmt.Errorf("describe result: %v (hello bound another kind)", err)
	}
	if d.Version != hello.Version {
		return d, fmt.Errorf("describe result: version %d, hello bound generation %d", d.Version, hello.Version)
	}
	if err := bound("service/purpose", d.Record.Address(), hello.Address); err != nil {
		return d, fmt.Errorf("describe result: %v (hello bound another address)", err)
	}
	if derived := d.Record.Label(); derived != d.Label {
		return d, fmt.Errorf("describe result: label %q is not the label the record derives, %q", d.Label, derived)
	}
	// The vault's own rows, with the vault's own verdict: a violated row
	// is not hidden by the server — it is reported as record_invalid:<code>
	// — and a clean record carries no such finding.
	wantInvalid := ""
	if err := ValidateStored(d.Label, d.Record); err != nil {
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			return d, fmt.Errorf("describe result: record: %v", err)
		}
		wantInvalid = FindingRecordInvalid + ":" + refusal.Code
	}
	if !Contains(Exposures, d.Exposure) {
		return d, fmt.Errorf("describe result: exposure %q is not one of %s", d.Exposure, strings.Join(Exposures, ", "))
	}
	seen := map[string]bool{}
	gotInvalid, noRow, expired := "", false, false
	for _, finding := range d.Findings {
		if seen[finding] {
			return d, fmt.Errorf("describe result: finding %q is listed twice", finding)
		}
		seen[finding] = true
		switch {
		case finding == FindingValidityExpired:
			expired = true
		case finding == CodeUnsupportedPrimitive:
			noRow = true
		case strings.HasPrefix(finding, FindingRecordInvalid+":"):
			gotInvalid = finding
		default:
			return d, fmt.Errorf("describe result: finding %q is not one the read vocabulary defines", finding)
		}
	}
	if gotInvalid != wantInvalid {
		return d, fmt.Errorf("describe result: findings report %q, the record model says %q", gotInvalid, wantInvalid)
	}
	if expired && d.Validity.NotAfter == nil {
		return d, errors.New("describe result: validity_expired on a record without validity.not_after")
	}
	if noRow != (d.Exposure == Unknown) {
		return d, fmt.Errorf("describe result: exposure %q with unsupported_primitive reported %v", d.Exposure, noRow)
	}
	if noRow && len(d.Operations) != 0 {
		return d, errors.New("describe result: operations listed for a record with no primitive")
	}
	for i, op := range d.Operations {
		if op.Name == "" || op.Via == "" {
			return d, fmt.Errorf("describe result: operations[%d] has an empty name or via", i)
		}
	}
	return d, nil
}

// effectiveFormat is the format the server must answer with: the one the
// request named, else the op's default (or "" when the default is the
// record's own, as for sign).
func effectiveFormat(requested, fallback string) string {
	if requested != "" {
		return requested
	}
	return fallback
}

func checkPub(req Request, result json.RawMessage, hello Hello) error {
	format := effectiveFormat(req.Format, FormatSPKIDER)
	encoding := "der_base64"
	if format == FormatSPKIPEM {
		encoding = "pem"
	}
	if _, err := resultObject(result, append(append([]string{}, pubResultMembers...), encoding), nil, true); err != nil {
		return fmt.Errorf("pub result %v", err)
	}
	var pub PublicKey
	if err := json.Unmarshal(result, &pub); err != nil {
		return fmt.Errorf("pub result: %v", err)
	}
	if err := checkIdentity(pub.Label, pub.Fingerprint, hello); err != nil {
		return fmt.Errorf("pub result: %v", err)
	}
	if err := bound("format", pub.Format, format); err != nil {
		return fmt.Errorf("pub result: %v (request asked for %s)", err, format)
	}
	var der []byte
	var err error
	if format == FormatSPKIPEM {
		block, rest := pem.Decode([]byte(pub.PEM))
		switch {
		case block == nil:
			return errors.New("pub result: pem is not a PEM block")
		case block.Type != "PUBLIC KEY":
			return fmt.Errorf("pub result: pem block is %q, not PUBLIC KEY", block.Type)
		case len(strings.TrimSpace(string(rest))) != 0:
			return errors.New("pub result: pem carries data after the block")
		}
		der = block.Bytes
	} else {
		der, err = base64.StdEncoding.DecodeString(pub.DERBase64)
		if err != nil {
			return fmt.Errorf("pub result: der_base64: %v", err)
		}
	}
	if _, err := ParseSPKI(der); err != nil {
		return fmt.Errorf("pub result: %s: %v", encoding, err)
	}
	if got := Fingerprint(der); got != hello.Fingerprint {
		return fmt.Errorf("pub result: %s fingerprints as %s, hello attested %s", encoding, got, hello.Fingerprint)
	}
	return nil
}

func checkSign(req Request, result json.RawMessage, hello Hello, pub *ecdsa.PublicKey) error {
	if _, err := resultObject(result, signResultMembers, nil, true); err != nil {
		return fmt.Errorf("sign result %v", err)
	}
	var sig Signature
	if err := json.Unmarshal(result, &sig); err != nil {
		return fmt.Errorf("sign result: %v", err)
	}
	if err := checkIdentity(sig.Label, sig.Fingerprint, hello); err != nil {
		return fmt.Errorf("sign result: %v", err)
	}
	if err := bound("hash", sig.Hash, Hash); err != nil {
		return fmt.Errorf("sign result: %v", err)
	}
	if err := bound("digest", sig.Digest, req.Digest); err != nil {
		return fmt.Errorf("sign result: %v (not the digest requested)", err)
	}
	switch format := effectiveFormat(req.Format, sig.Format); {
	case sig.Format != format:
		return fmt.Errorf("sign result: format %q, want the requested %q", sig.Format, format)
	case sig.Format != FormatDERLowS && sig.Format != FormatRaw:
		return fmt.Errorf("sign result: format %q is not %s or %s", sig.Format, FormatDERLowS, FormatRaw)
	}
	raw, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("sign result: signature is not hex: %v", err)
	}
	b64, err := base64.StdEncoding.DecodeString(sig.SignatureBase64)
	if err != nil {
		return fmt.Errorf("sign result: signature_base64: %v", err)
	}
	if string(b64) != string(raw) {
		return errors.New("sign result: signature_base64 does not encode the same bytes as signature")
	}
	r, s, err := ParseSignature(raw, sig.Format)
	if err != nil {
		return fmt.Errorf("sign result: %v", err)
	}
	if !IsLowS(s) {
		return errors.New("sign result: s is in the high half of the order (the vault emits low-S only)")
	}
	if !sig.LowS {
		return errors.New("sign result: low_s is false on a signature the contract requires to be low-S")
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		return fmt.Errorf("sign result: the pending request's digest is not hex: %v", err)
	}
	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("sign result: signature does not verify under the attested public key")
	}
	return nil
}

// checkVerify judges a verify response: ok carries a true verdict, and
// only signature_invalid (false verdict) and high_s_refused (partial
// verdict, no key read) carry a result next to their error; any other
// refusal carries none. The verdict is re-derived with crypto/ecdsa under
// the attested key and must agree member by member.
func checkVerify(req Request, resp Response, hello Hello, pub *ecdsa.PublicKey) error {
	code := ""
	if resp.Error != nil {
		code = resp.Error.Code
	}
	switch code {
	case "", CodeSignatureInvalid, CodeHighSRefused:
		if len(resp.Result) == 0 {
			return fmt.Errorf("verify result: %s documents a verdict and none was carried", describeVerifyOutcome(code))
		}
	default:
		if len(resp.Result) != 0 {
			return fmt.Errorf("verify result: a %s refusal carries a result the op does not document", code)
		}
		return nil
	}
	required := verifyResultMembers
	if code != CodeHighSRefused {
		required = append(append([]string{}, verifyIdentityMembers...), verifyResultMembers...)
	}
	if _, err := resultObject(resp.Result, required, nil, true); err != nil {
		return fmt.Errorf("verify result %v", err)
	}
	var v Verdict
	if err := json.Unmarshal(resp.Result, &v); err != nil {
		return fmt.Errorf("verify result: %v", err)
	}
	if code != CodeHighSRefused {
		if err := checkIdentity(v.Label, v.Fingerprint, hello); err != nil {
			return fmt.Errorf("verify result: %v", err)
		}
	}
	if err := bound("hash", v.Hash, Hash); err != nil {
		return fmt.Errorf("verify result: %v", err)
	}
	if err := bound("digest", v.Digest, req.Digest); err != nil {
		return fmt.Errorf("verify result: %v (not the digest requested)", err)
	}
	format := effectiveFormat(req.Format, FormatDERLowS)
	if err := bound("format", v.Format, format); err != nil {
		return fmt.Errorf("verify result: %v (not the format requested)", err)
	}
	if v.HighSAllowed != req.AllowHighS {
		return fmt.Errorf("verify result: high_s_allowed %v, request sent %v", v.HighSAllowed, req.AllowHighS)
	}
	signature, err := hex.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("verify result: the pending request's signature is not hex: %v", err)
	}
	r, s, err := ParseSignature(signature, format)
	if err != nil {
		return fmt.Errorf("verify result: a verdict on a signature that does not parse: %v", err)
	}
	if v.LowS != IsLowS(s) {
		return fmt.Errorf("verify result: low_s %v, the signature's s is low: %v", v.LowS, IsLowS(s))
	}
	digest, err := hex.DecodeString(req.Digest)
	if err != nil {
		return fmt.Errorf("verify result: the pending request's digest is not hex: %v", err)
	}
	switch code {
	case CodeHighSRefused:
		if IsLowS(s) || req.AllowHighS {
			return errors.New("verify result: high_s_refused on a signature that is low-S or with allow_high_s set")
		}
		if v.Verified {
			return errors.New("verify result: high_s_refused carries verified true")
		}
		return nil
	case CodeSignatureInvalid:
		if v.Verified {
			return errors.New("verify result: signature_invalid carries verified true")
		}
	default:
		if !v.Verified {
			return errors.New("verify result: ok carries verified false")
		}
	}
	if !IsLowS(s) && !req.AllowHighS {
		return errors.New("verify result: a verdict on a high-S signature without allow_high_s (must be high_s_refused)")
	}
	if verified := ecdsa.Verify(pub, digest, r, s); verified != v.Verified {
		return fmt.Errorf("verify result: verified %v, crypto/ecdsa under the attested key says %v", v.Verified, verified)
	}
	return nil
}

func describeVerifyOutcome(code string) string {
	if code == "" {
		return "ok"
	}
	return code
}

func isArray(raw json.RawMessage) bool {
	t := trim(raw)
	return len(t) > 0 && t[0] == '['
}
