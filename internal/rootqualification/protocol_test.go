package rootqualification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func validRequest(t *testing.T) (Request, []byte) {
	t.Helper()
	r, err := NewRequest([]byte{1, 2, 3}, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteRequest(&b, r); err != nil {
		t.Fatal(err)
	}
	return r, b.Bytes()
}

func framed(b []byte) []byte {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	return append(h[:], b...)
}

// These controls prove the exact fixed wire representation and owned reference
// copies at minimum/maximum bounds; they make no native ACL-access claim.
func TestRequestCanonicalBoundsAndOwnership(t *testing.T) {
	for _, n := range []int{1, 3, MaxReference} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			input := bytes.Repeat([]byte{0xab}, n)
			r, err := NewRequest(input, strings.Repeat("0", 64))
			if err != nil {
				t.Fatal(err)
			}
			input[0] = 0
			if r.Reference()[0] != 0xab {
				t.Fatal("constructor retained caller storage")
			}
			owned := r.Reference()
			owned[0] = 0
			if r.Reference()[0] != 0xab {
				t.Fatal("getter exposed request storage")
			}
			var buf bytes.Buffer
			if err := WriteRequest(&buf, r); err != nil {
				t.Fatal(err)
			}
			decoded, err := ReadRequest(&buf)
			if err != nil || !bytes.Equal(decoded.Reference(), r.Reference()) || decoded.ReceiptSHA256() != r.ReceiptSHA256() {
				t.Fatalf("roundtrip: %v", err)
			}
		})
	}
	_, b := validRequest(t)
	want := `{"schema":"keyvault-root-acl-qualification/1","namespace":"works.relux.mac-keyvault.root-acl-qualification.v1","account":"public-marker@1","item_class":"generic-password","persistent_reference":"AQID","receipt_sha256":"` + strings.Repeat("a", 64) + `"}`
	if !bytes.Equal(b, framed([]byte(want))) {
		t.Fatal("wire changed")
	}
}

// Malformed shape, alternate encodings, duplicate fields and wrong fixed
// bindings all refuse alongside the valid control, without returning a ref.
func TestRequestRejectsNoncanonicalAndWrongBinding(t *testing.T) {
	_, good := validRequest(t)
	body := string(good[4:])
	changes := map[string]string{
		"unknown":             strings.Replace(body, `"schema":`, `"extra":0,"schema":`, 1),
		"duplicate":           strings.Replace(body, `"schema":`, `"schema":"wrong","schema":`, 1),
		"wrong-schema":        strings.Replace(body, Schema, Schema+"x", 1),
		"wrong-namespace":     strings.Replace(body, Namespace, Namespace+".other", 1),
		"wrong-account":       strings.Replace(body, Account, "other@1", 1),
		"wrong-class":         strings.Replace(body, ItemClass, "key", 1),
		"missing":             strings.Replace(body, `"account":"`+Account+`",`, "", 1),
		"whitespace":          " " + body,
		"newline":             body + "\n",
		"escaped":             strings.Replace(body, "public-marker", `public\u002dmarker`, 1),
		"base64-empty":        strings.Replace(body, "AQID", "", 1),
		"base64-invalid":      strings.Replace(body, "AQID", "!!!!", 1),
		"base64-noncanonical": strings.Replace(body, "AQID", `AQID\r\n`, 1),
		"base64-pad-bits":     strings.Replace(body, "AQID", "AR==", 1),
		"digest-uppercase":    strings.Replace(body, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"digest-short":        strings.Replace(body, strings.Repeat("a", 64), strings.Repeat("a", 63), 1),
		"null":                "null",
		"array":               "[]",
		"second-json":         body + body,
	}
	for name, mutation := range changes {
		t.Run(name, func(t *testing.T) {
			r, err := ReadRequest(bytes.NewReader(framed([]byte(mutation))))
			if !errors.Is(err, ErrProtocol) || len(r.Reference()) != 0 {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := ReadRequest(bytes.NewReader(good)); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// Framing refuses truncation, overlarge lengths before any payload read, and
// even one trailing byte; a slow reader still accepts an exact valid frame.
func TestRequestFraming(t *testing.T) {
	_, good := validRequest(t)
	for n := 0; n < len(good); n++ {
		if _, err := ReadRequest(bytes.NewReader(good[:n])); !errors.Is(err, ErrProtocol) {
			t.Fatalf("truncated at %d: %v", n, err)
		}
	}
	for _, extra := range [][]byte{{0}, good} {
		if _, err := ReadRequest(bytes.NewReader(append(bytes.Clone(good), extra...))); !errors.Is(err, ErrProtocol) {
			t.Fatalf("trailing: %v", err)
		}
	}
	for _, n := range []uint32{0, MaxRequest + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		r := &headerOnlyReader{header: bytes.NewReader(h[:])}
		if _, err := ReadRequest(r); !errors.Is(err, ErrProtocol) || r.payloadRead {
			t.Fatalf("length %d err=%v payload=%v", n, err, r.payloadRead)
		}
	}
	if _, err := ReadRequest(oneByteReader{bytes.NewReader(good)}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(io.MultiReader(bytes.NewReader(good), errorReader{})); !errors.Is(err, ErrProtocol) {
		t.Fatal("non-EOF read failure accepted")
	}
}

type headerOnlyReader struct {
	header      *bytes.Reader
	payloadRead bool
}

func (r *headerOnlyReader) Read(b []byte) (int, error) {
	if r.header.Len() == 0 {
		r.payloadRead = true
		return 0, io.ErrUnexpectedEOF
	}
	return r.header.Read(b)
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// Construction and write validation refuse missing/overlarge references and
// malformed owner-reviewed digests before producing any request bytes.
func TestRequestInvalidConstructionAndZeroValue(t *testing.T) {
	for _, ref := range [][]byte{nil, {}, make([]byte, MaxReference+1)} {
		if _, err := NewRequest(ref, strings.Repeat("a", 64)); !errors.Is(err, ErrProtocol) {
			t.Fatal("bad reference accepted")
		}
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("G", 64), strings.Repeat("A", 64), strings.Repeat("a", 63) + "\x00"} {
		if _, err := NewRequest([]byte{1}, digest); !errors.Is(err, ErrProtocol) {
			t.Fatal("bad digest accepted")
		}
	}
	var b bytes.Buffer
	if err := WriteRequest(&b, Request{}); !errors.Is(err, ErrProtocol) || b.Len() != 0 {
		t.Fatal("zero request emitted bytes")
	}
}

// Every finite result has one exact LF-terminated response. Unqualified remains
// distinct from access-refused; the parser does not decide native success.
func TestResponseFiniteControls(t *testing.T) {
	for _, result := range []Result{AccessRefused, UnexpectedAccess, Unqualified} {
		var b bytes.Buffer
		if err := WriteResponse(&b, result); err != nil {
			t.Fatal(err)
		}
		wire := bytes.Clone(b.Bytes())
		got, err := ReadResponse(oneByteReader{&b})
		if err != nil || got != result {
			t.Fatalf("result %d: %d %v", result, got, err)
		}
		mutations := [][]byte{wire[:len(wire)-1], append(bytes.Clone(wire), 0), append(bytes.Clone(wire), '\n'), bytes.Replace(wire, []byte(`"schema":`), []byte(`"extra":0,"schema":`), 1), bytes.Replace(wire, []byte(result.name()), []byte("other"), 1), bytes.Repeat([]byte{'x'}, 257)}
		for _, bad := range mutations {
			if got, err := ReadResponse(bytes.NewReader(bad)); !errors.Is(err, ErrProtocol) || got != 0 {
				t.Fatalf("bad response accepted: %v", err)
			}
		}
		if got, err := ReadResponse(io.MultiReader(bytes.NewReader(wire), errorReader{})); !errors.Is(err, ErrProtocol) || got != 0 {
			t.Fatal("read error accepted")
		}
	}
	var b bytes.Buffer
	if err := WriteResponse(&b, 0); !errors.Is(err, ErrProtocol) || b.Len() != 0 {
		t.Fatal("unknown result emitted bytes")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return w.Buffer.Write(b)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// Legal partial writes complete without duplication; blocked/failed writers
// return their intended error instead of spinning or claiming a full frame.
func TestProtocolPartialAndFailedWrites(t *testing.T) {
	r, good := validRequest(t)
	var w shortWriter
	if err := WriteRequest(&w, r); err != nil || !bytes.Equal(w.Bytes(), good) {
		t.Fatalf("partial write: %v", err)
	}
	if err := WriteRequest(zeroWriter{}, r); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := WriteRequest(failedWriter{}, r); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := WriteResponse(zeroWriter{}, AccessRefused); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if err := WriteResponse(failedWriter{}, AccessRefused); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
