package grants

import (
	"errors"
	"strings"
	"testing"
)

// These pairs prove the exact opaque-ID grammar and 128-byte boundary only;
// case-sensitive bytes survive unchanged. Matrix IDs use a separate contract.
func TestParseOpaqueID(t *testing.T) {
	tests := []struct {
		name, value string
		want        error
	}{
		{"one letter", "a", nil}, {"one digit", "0", nil},
		{"accepted punctuation", "A.b_C:d/e-f9", nil},
		{"maximum", "A" + strings.Repeat("-", 127), nil},
		{"too long", "A" + strings.Repeat("-", 128), errInputLimit},
		{"empty", "", errBadSchema}, {"leading underscore", "_a", errBadSchema},
		{"leading slash", "/a", errBadSchema}, {"leading dot", ".a", errBadSchema},
		{"space", "a b", errBadSchema}, {"trailing space", "abc ", errBadSchema},
		{"percent alias", "a%2fb", errBadSchema}, {"plus", "a+b", errBadSchema},
		{"backslash", `a\b`, errBadSchema}, {"non ASCII", "aé", errBadSchema},
		{"control", "a\nb", errBadSchema}, {"DEL", "a\x7f", errBadSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseOpaqueID(test.value)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
			if test.want == nil && got != test.value {
				t.Fatalf("ID changed: %q -> %q", test.value, got)
			}
			if test.want != nil && got != "" {
				t.Fatalf("failed parse returned ID %q", got)
			}
			if valid, e := parseOpaqueID("Case/a:B_9-."); e != nil || valid != "Case/a:B_9-." {
				t.Fatal("valid neighbor rejected/changed", valid, e)
			}
		})
	}
}

// Fixed independent hex goldens prove exact lowercase64hex decoding and zero
// output on a refusal, including a late bad character after a valid prefix.
func TestParseWireDigest(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	var want [32]byte
	for i := range want {
		want[i] = 0xab
	}
	got, err := parseWireDigest(valid)
	if err != nil || got != want {
		t.Fatal("fixed digest", got, err)
	}
	for _, raw := range []string{"", valid[:63], valid + "0", strings.ToUpper(valid), valid[:63] + "g", valid[:63] + "G", " " + valid, valid + "\n", "sha256:" + valid, strings.Repeat("0", 62) + "é"} {
		out, e := parseWireDigest(raw)
		if !errors.Is(e, errBadSchema) || out != ([32]byte{}) {
			t.Fatalf("%q: non-schema refusal or partial output: %x %v", raw, out, e)
		}
		if v, e := parseWireDigest(valid); e != nil || v != want {
			t.Fatal("valid digest after rejection", v, e)
		}
	}
	if v, e := parseWireDigest(strings.Repeat("0", 64)); e != nil || v != ([32]byte{}) {
		t.Fatal("all-zero digest spelling is valid", v, e)
	}
}

// Decimal values are strings, parsed exactly without float conversion;
// overflow and alternate spellings refuse and return zero.
func TestParsePositiveDecimal(t *testing.T) {
	valid := []struct {
		raw  string
		want uint64
	}{{"1", 1}, {"9007199254740993", 9007199254740993}, {"18446744073709551615", ^uint64(0)}}
	for _, test := range valid {
		got, err := parsePositiveDecimal(test.raw)
		if err != nil || got != test.want {
			t.Fatalf("%q=%d %v", test.raw, got, err)
		}
	}
	for _, raw := range []string{"", "0", "00", "01", "+1", "-1", "1.0", "1e0", " 1", "1 ", "1\n", "18446744073709551616", "99999999999999999999", strings.Repeat("1", 1000), "١", "1a"} {
		got, err := parsePositiveDecimal(raw)
		if !errors.Is(err, errBadSchema) || got != 0 {
			t.Fatalf("%q: %d %v", raw, got, err)
		}
		if got, e := parsePositiveDecimal("18446744073709551615"); e != nil || got != ^uint64(0) {
			t.Fatal("valid max after refusal", got, e)
		}
	}
}

// Fixed public-shaped bytes are unenrolled, never key generation or authority.
// Strict unpadded base64url rejects aliases/padding and wrong decoded length;
// failed parses return no partially decoded public bytes.
func TestParseDevicePublicBytes(t *testing.T) {
	valid := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	var want [32]byte
	for i := range want {
		want[i] = byte(i)
	}
	got, err := parseDevicePublicBytes(valid)
	if err != nil || got != want {
		t.Fatal("fixed public-shaped bytes", got, err)
	}
	for _, raw := range []string{"", valid[:42], valid + "A", valid + "=", valid[:42] + "9", valid[:42] + "/", valid[:42] + "+", valid[:10] + "\n" + valid[11:], " " + valid[1:], valid[:42] + "é", strings.Repeat("/", 42) + "8", strings.Repeat("_", 41) + "=8"} {
		out, e := parseDevicePublicBytes(raw)
		if !errors.Is(e, errBadSchema) || out != ([32]byte{}) {
			t.Fatalf("%q: %x %v", raw, out, e)
		}
		if v, e := parseDevicePublicBytes(valid); e != nil || v != want {
			t.Fatal("valid public-shaped neighbor", v, e)
		}
	}
	var allFF [32]byte
	for i := range allFF {
		allFF[i] = 255
	}
	if got, e := parseDevicePublicBytes(strings.Repeat("_", 42) + "8"); e != nil || got != allFF {
		t.Fatal("URL alphabet positive", got, e)
	}
}
