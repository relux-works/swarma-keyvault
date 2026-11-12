// Package rootqualification implements the closed public-marker qualification
// protocol. Parsing a message grants no Keychain or cleanup authority.
package rootqualification

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

const (
	Schema       = "keyvault-root-acl-qualification/1"
	Namespace    = "works.relux.mac-keyvault.root-acl-qualification.v1"
	Account      = "public-marker@1"
	ItemClass    = "generic-password"
	PublicMarker = "keyvault-root-acl-qualification/1"
	MaxReference = 16384
	MaxRequest   = 32768
)

var ErrProtocol = errors.New("public marker qualification protocol refused")

// Request owns a copy of the public test item's persistent reference. No
// constructor accepts a caller-selected namespace, account, class or path.
type Request struct {
	data *requestData
}

type requestData struct {
	mu            sync.Mutex
	reference     []byte
	receiptSHA256 string
}

type requestJSON struct {
	Schema              string `json:"schema"`
	Namespace           string `json:"namespace"`
	Account             string `json:"account"`
	ItemClass           string `json:"item_class"`
	PersistentReference string `json:"persistent_reference"`
	ReceiptSHA256       string `json:"receipt_sha256"`
}

func NewRequest(reference []byte, receiptSHA256 string) (Request, error) {
	if len(reference) < 1 || len(reference) > MaxReference || !validSHA256(receiptSHA256) {
		return Request{}, ErrProtocol
	}
	return Request{data: &requestData{reference: bytes.Clone(reference), receiptSHA256: receiptSHA256}}, nil
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

// Reference returns an owned public reference, never the request's backing slice.
func (r Request) Reference() []byte {
	if r.data == nil {
		return nil
	}
	r.data.mu.Lock()
	defer r.data.mu.Unlock()
	return bytes.Clone(r.data.reference)
}
func (r Request) ReceiptSHA256() string {
	if r.data == nil {
		return ""
	}
	r.data.mu.Lock()
	defer r.data.mu.Unlock()
	return r.data.receiptSHA256
}

// Clear releases the owned public reference and invalidates all Request value
// copies sharing it. It is idempotent; previously returned Reference clones
// remain their caller's responsibility. JSON strings/runtime copies cannot be
// reliably erased by Go, so this is not a secret-memory guarantee. This wire
// carries only the fixed public-marker item's reference, never private keys.
func (r *Request) Clear() {
	if r == nil || r.data == nil {
		return
	}
	r.data.mu.Lock()
	defer r.data.mu.Unlock()
	clear(r.data.reference)
	r.data.reference = nil
	r.data.receiptSHA256 = ""
}

func (r Request) canonical() ([]byte, error) {
	if r.data == nil {
		return nil, ErrProtocol
	}
	r.data.mu.Lock()
	defer r.data.mu.Unlock()
	if len(r.data.reference) < 1 || len(r.data.reference) > MaxReference || !validSHA256(r.data.receiptSHA256) {
		return nil, ErrProtocol
	}
	b, err := json.Marshal(requestJSON{Schema, Namespace, Account, ItemClass, base64.StdEncoding.EncodeToString(r.data.reference), r.data.receiptSHA256})
	if err != nil || len(b) > MaxRequest {
		return nil, ErrProtocol
	}
	return b, nil
}

// WriteRequest writes the one frame. The transport closes stdin after writing
// and owns the original deadline, actual child identity and process lifetime.
func WriteRequest(w io.Writer, r Request) error {
	b, err := r.canonical()
	if err != nil {
		return err
	}
	defer clear(b)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, b)
}

// ReadRequest requires exactly one canonical frame followed by actual EOF.
// Callers must impose the qualification deadline on the underlying transport.
func ReadRequest(rd io.Reader) (Request, error) {
	var header [4]byte
	if _, err := io.ReadFull(rd, header[:]); err != nil {
		return Request{}, ErrProtocol
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 1 || n > MaxRequest {
		return Request{}, ErrProtocol
	}
	b := make([]byte, int(n))
	defer clear(b)
	if _, err := io.ReadFull(rd, b); err != nil {
		return Request{}, ErrProtocol
	}
	if err := requireEOF(rd); err != nil {
		return Request{}, err
	}
	var wire requestJSON
	if err := json.Unmarshal(b, &wire); err != nil {
		return Request{}, ErrProtocol
	}
	if wire.Schema != Schema || wire.Namespace != Namespace || wire.Account != Account || wire.ItemClass != ItemClass {
		return Request{}, ErrProtocol
	}
	ref, err := base64.StdEncoding.Strict().DecodeString(wire.PersistentReference)
	defer clear(ref)
	if err != nil {
		return Request{}, ErrProtocol
	}
	r, err := NewRequest(ref, wire.ReceiptSHA256)
	if err != nil {
		return Request{}, err
	}
	canonical, err := r.canonical()
	defer clear(canonical)
	// Exact equality also rejects unknown/duplicate/reordered fields, alternate
	// escaping, whitespace and noncanonical base64; no normalization admits them.
	if err != nil || !bytes.Equal(canonical, b) {
		r.Clear()
		return Request{}, ErrProtocol
	}
	return r, nil
}

type Result uint8

const (
	AccessRefused Result = iota + 1
	UnexpectedAccess
	Unqualified
)

func (r Result) name() string {
	switch r {
	case AccessRefused:
		return "access-refused"
	case UnexpectedAccess:
		return "unexpected-access"
	case Unqualified:
		return "unqualified"
	}
	return ""
}

// WriteResponse reports only a fixed public control result. Selecting
// AccessRefused requires an actual intended native marker-read denial; a
// startup identity refusal, missing item or unknown OS result is Unqualified.
func WriteResponse(w io.Writer, result Result) error {
	name := result.name()
	if name == "" {
		return ErrProtocol
	}
	return writeFull(w, []byte(`{"schema":"`+Schema+`","result":"`+name+`"}`+"\n"))
}

// ReadResponse requires the complete fixed response and EOF, including its LF.
// An unqualified result is a valid protocol response, never a passing control.
func ReadResponse(rd io.Reader) (Result, error) {
	b, err := io.ReadAll(io.LimitReader(rd, 257))
	if err != nil || len(b) > 256 {
		return 0, ErrProtocol
	}
	for _, r := range []Result{AccessRefused, UnexpectedAccess, Unqualified} {
		var want bytes.Buffer
		_ = WriteResponse(&want, r)
		if bytes.Equal(b, want.Bytes()) {
			return r, nil
		}
	}
	return 0, ErrProtocol
}

func requireEOF(rd io.Reader) error {
	var b [1]byte
	if n, err := rd.Read(b[:]); n != 0 || err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return ErrProtocol
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
