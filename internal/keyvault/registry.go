package keyvault

import "time"

// Operation is one crypto operation a primitive supports right now. It is
// derived from the registry and the record's policy, never stored.
type Operation struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Output string `json:"output"`
	Via    string `json:"via"`
	// HumanAuthorized marks an export that needs --human-authorized.
	HumanAuthorized bool `json:"human_authorized,omitempty"`
	// requires is the usage the policy filter demands; "" means always.
	requires string
	// expires marks operations that validity.not_after switches off.
	expires bool
	// extraction marks operations that need extraction != none.
	extraction bool
}

// PrimitiveKey addresses one registry row.
type PrimitiveKey struct {
	Kind      string
	Algorithm string
	Store     StoreKind
}

// Primitive is what one (kind, algorithm, store) combination can do.
type Primitive struct {
	Exposure   string
	Operations []Operation
}

// ViaReserved marks an operation no CLI command performs yet; a consumer
// never assumes it works.
const ViaReserved = "reserved"

// registry is the single table describe, list and the gates are driven from.
// Adding a primitive is one row plus its backend implementation; no command
// grows a special case. The Secure Enclave row signs, verifies and exports
// its public half; nothing else is reserved for it. The keychain row's
// ECIES decryption is performed by mac-keyvault-kek, not by mac-keyvault.
var registry = map[PrimitiveKey]Primitive{
	{Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreEnclave}: {
		Exposure: ExposureNever,
		Operations: []Operation{
			{Name: OperationSign, Input: "sha256-digest", Output: "ecdsa-der-low-s|ecdsa-raw", Via: "sign", requires: "sign", expires: true},
			{Name: OperationVerify, Input: "sha256-digest+signature", Output: "verdict", Via: "verify"},
			{Name: "export-public", Input: "", Output: "spki-der|spki-pem|jwk", Via: "pub"},
		},
	},
	{Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreKeychain}: {
		Exposure: ExposureNever,
		Operations: []Operation{
			{Name: OperationSign, Input: "sha256-digest", Output: "ecdsa-der-low-s|ecdsa-raw", Via: "sign", requires: "sign", expires: true},
			{Name: OperationVerify, Input: "sha256-digest+signature", Output: "verdict", Via: "verify"},
			{Name: "ecdh-p256", Input: "peer-spki", Output: "shared-secret", Via: ViaReserved, requires: "wrap"},
			{Name: "ecies-p256-encrypt", Input: "payload", Output: "envelope:ecies-x963-sha256-aesgcm", Via: ViaReserved},
			{Name: OperationDecrypt, Input: "envelope:ecies-x963-sha256-aesgcm", Output: "payload", Via: "mac-keyvault-kek unwrap", requires: "decrypt", expires: true},
			{Name: "export-public", Input: "", Output: "spki-der|spki-pem|jwk", Via: "pub"},
			{Name: "export-private", Input: "", Output: "pkcs8-der|pkcs8-pem|pkcs12", Via: ViaReserved, extraction: true},
		},
	},
}

// LookupPrimitive returns the registry row for the record, if any.
func LookupPrimitive(rec Record) (Primitive, bool) {
	primitive, ok := registry[PrimitiveKey{Kind: rec.Kind, Algorithm: rec.Algorithm, Store: rec.Store}]
	return primitive, ok
}

// Exposure derives the record's exposure from its registry row; a record
// without a row reports unknown rather than a guess.
func Exposure(rec Record) string {
	if primitive, ok := LookupPrimitive(rec); ok {
		return primitive.Exposure
	}
	return Unknown
}

// Operations derives what the record can do now: the primitive's supported
// set intersected with usages and validity. A record without a registry row
// reports no operations and the unsupported_primitive finding, never a
// guess. now bounds validity.
func Operations(rec Record, now time.Time) (ops []Operation, findings []string) {
	ops = []Operation{}
	primitive, ok := LookupPrimitive(rec)
	if !ok {
		return ops, []string{CodeUnsupportedPrimitive}
	}
	expired := rec.Validity.NotAfter != nil && !rec.Validity.NotAfter.IsZero() && !now.Before(rec.Validity.NotAfter.Time)
	if expired {
		findings = append(findings, FindingValidityExpired)
	}
	for _, op := range primitive.Operations {
		if op.requires != "" && !contains(rec.Usages, op.requires) {
			continue
		}
		if op.expires && expired {
			continue
		}
		if op.extraction {
			if rec.Extraction == ExtractionNone || rec.Extraction == Unknown {
				continue
			}
			op.HumanAuthorized = rec.Extraction == ExtractionHuman
		}
		ops = append(ops, op)
	}
	return ops, findings
}
