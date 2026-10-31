package grants

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// These are synthetic scalar encodings, not generated or verified signatures.
// Independent literal DER values exercise both scalar minima and R=N-1,
// S=floor(N/2); accepted parsing conveys no issuer/enrollment/authority.
func TestParseLowSSignatureDER(t *testing.T) {
	tests := []struct{ name, raw, r, s string }{
		{"minimum", "3006020101020101", "1", "1"},
		{"maximum low S", "3045022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255002207fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"},
		{"required sign pad", "300702020080020101", "80", "1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := hex.DecodeString(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(raw)
			r, s, err := parseLowSSignatureDER(raw)
			if err != nil || r == nil || s == nil {
				t.Fatal("valid representation refused", err)
			}
			if r.Text(16) != test.r || s.Text(16) != test.s {
				t.Fatalf("scalars %x %x", r, s)
			}
			if !bytes.Equal(before, raw) {
				t.Fatal("received DER mutated")
			}
		})
	}
}

// Invalid/minimally encoded aliases and scalar-bound neighbors refuse with
// nil R/S and unchanged input; each refusal is paired with a valid control.
// This proves representation checks only, never ECDSA verification.
func TestParseLowSSignatureDERRefuses(t *testing.T) {
	tests := []struct{ name, raw string }{
		{"empty", ""}, {"raw64", strings.Repeat("01", 64)},
		{"zero R", "3006020100020101"}, {"zero S", "3006020101020100"},
		{"negative R", "3006020180020101"}, {"negative S", "3006020101020180"},
		{"empty R", "30050200020101"}, {"empty S", "30050201010200"},
		{"nonminimal R", "300702020001020101"}, {"nonminimal S", "300702010102020001"},
		{"long sequence length", "308106020101020101"},
		{"long R length", "300702810101020101"},
		{"indefinite sequence", "30800201010201010000"},
		{"trailing byte", "300602010102010100"},
		{"third integer", "3009020101020101020101"},
		{"wrong sequence tag", "3106020101020101"},
		{"wrong R tag", "3006030101020101"},
		{"wrong S tag", "3006020101030101"},
		{"truncated", "30060201010201"},
		{"R equals N", "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101"},
		{"R exceeds N", "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552020101"},
		{"S above half", "302502010102207fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"},
		{"S equals N", "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := hex.DecodeString(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(raw)
			r, s, err := parseLowSSignatureDER(raw)
			if !errors.Is(err, errSignatureInvalid) || r != nil || s != nil {
				t.Fatalf("partial/non-signature refusal: %v %v %v", r, s, err)
			}
			if !bytes.Equal(before, raw) {
				t.Fatal("failed DER parse changed input")
			}
			r, s, err = parseLowSSignatureDER([]byte{0x30, 6, 2, 1, 1, 2, 1, 1})
			if err != nil || r == nil || s == nil || r.String() != "1" || s.String() != "1" {
				t.Fatal("valid neighbor after rejection", r, s, err)
			}
		})
	}
}

// The decoded72-byte cap applies before DER interpretation. A malformed
// exactly72-byte input is within the cap and gets signature-invalid;73 gets
// input-limit-exceeded, both with nil outputs and no input mutation.
func TestParseLowSSignatureDERSizeLimit(t *testing.T) {
	for _, size := range []int{72, 73} {
		raw := bytes.Repeat([]byte{0}, size)
		before := bytes.Clone(raw)
		want := errSignatureInvalid
		if size > 72 {
			want = errInputLimit
		}
		r, s, err := parseLowSSignatureDER(raw)
		if !errors.Is(err, want) || r != nil || s != nil || !bytes.Equal(raw, before) {
			t.Fatalf("size%d: %v %v %v", size, r, s, err)
		}
	}
}
