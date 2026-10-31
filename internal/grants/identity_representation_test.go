package grants

import (
	"errors"
	"strings"
	"testing"
)

// Existing-account consumption preserves the admitted printable ASCII subset
// of historical MXIDs; it neither registers nor authenticates these accounts.
func TestMatrixAccountRepresentationExact(t *testing.T) {
	valid := []string{"@alice:matrix.org", "@A+B_=/.:MATRIX.Org:8448", "@:example.org", "@Legacy !@\\\":example.org", "@a:1.2.3.4", "@a:001.002.003.004:00000", "@a:[2001:db8::ABCD]", "@a:[::ffff:192.0.2.1]:99999", "@a:-label..", "@a:" + strings.Repeat("x", 252)}
	for _, s := range valid {
		got, e := parseMatrixAccountRepresentation(s)
		if e != nil || got != s {
			t.Fatalf("exact historical %q: %q %v", s, got, e)
		}
	}
	for _, s := range []string{"", "alice:matrix.org", "!alice:matrix.org", "@alice", "@alice:", "@alice:example.org:", "@alice:example.org:123456", "@alice:example.org:+80", "@alice:example.org:8x", "@alice:example_org", "@alice:example.org/path", "@alice:256.2.3.4", "@alice:[1.2.3.4]", "@alice:2001:db8::1", "@alice:[::1%zone]", "@alice:[1::2::3]", "@alice:[1:2:3:4:5:6:7:8:9]", "@alice:[12345::]", "@alice:[::ffff:192.0.2.256]", "@alice:[::1]extra", "@alice:[::1]:", "@alice:[::1]:1:2", "@alice:[::1", "@al\x00ice:example.org", "@al\nice:example.org", "@\u00e9:example.org", "@a:" + strings.Repeat("x", 253)} {
		good := "@Alice:Example.Org"
		if got, e := parseMatrixAccountRepresentation(good); e != nil || got != good {
			t.Fatal("positive before", e)
		}
		got, e := parseMatrixAccountRepresentation(s)
		if got != "" || !errors.Is(e, errBadSchema) {
			t.Fatalf("schema %q: %q %v", s, got, e)
		}
		if got, e := parseMatrixAccountRepresentation(good); e != nil || got != good {
			t.Fatal("positive after", e)
		}
	}
	if got, e := parseMatrixAccountRepresentation(strings.Repeat("x", 513)); got != "" || !errors.Is(e, errInputLimit) {
		t.Fatal("local513 bound", e)
	}
}

// Address literals obey their representation grammar without DNS access or
// text normalization; all declared IPv6 expansion/compression forms are probed.
func TestMatrixServerAddressRepresentations(t *testing.T) {
	for _, server := range []string{"1.2.3.4", "000.001.002.255", "[::]", "[::1]", "[1::]", "[1:2:3:4:5:6:7:8]", "[1:2:3:4:5:6:192.0.2.1]", "[::ffff:192.000.002.001]", "[a:b:c:d:e:f:0:1]:12345", "matrix.org:65536", "matrix.org:99999"} {
		raw := "@a:" + server
		got, e := parseMatrixAccountRepresentation(raw)
		if e != nil || got != raw {
			t.Fatal("valid address", server, e)
		}
	}
	for _, server := range []string{"[]", "[:]", "[1:]", "[:1]", "[1:2:3:4:5:6:7]", "[1:2:3:4:5:6:7:8::]", "[1:2:3:4:5:6::192.0.2.1]", "[1:2:3:4:5:192.0.2.1:8]", "[::ffff:1.2.3]", "[::ffff:1.2.3.4.5]", "[::ffff:0000.2.3.4]", "[::g]", "[fe80::1%en0]", "1.2.3.999", "1.2.3.0000"} {
		if got, e := parseMatrixAccountRepresentation("@a:" + server); got != "" || !errors.Is(e, errBadSchema) {
			t.Fatal("bad address", server, e)
		}
		if got, e := parseMatrixAccountRepresentation("@a:[::1]"); e != nil || got != "@a:[::1]" {
			t.Fatal("valid neighbor", e)
		}
	}
}

// Device IDs use the consumer's printable exact representation, not opaque
// local identifier grammar, and cannot establish enrollment or a public key.
func TestDeviceIDRepresentation(t *testing.T) {
	for _, s := range []string{"device", "DEVICE +/:\\= ", " ", strings.Repeat("x", 128)} {
		if got, e := parseDeviceIDRepresentation(s); e != nil || got != s {
			t.Fatal("exact device", e)
		}
	}
	for _, s := range []string{"", "x\n", "x\x00", "x\x7f", "\u00e9"} {
		if got, e := parseDeviceIDRepresentation(s); got != "" || !errors.Is(e, errBadSchema) {
			t.Fatal("device refusal", e)
		}
		if got, e := parseDeviceIDRepresentation("Neighbor_+/="); e != nil || got != "Neighbor_+/=" {
			t.Fatal("device neighbor", e)
		}
	}
	if got, e := parseDeviceIDRepresentation(strings.Repeat("x", 129)); got != "" || !errors.Is(e, errInputLimit) {
		t.Fatal("device129", e)
	}
}
