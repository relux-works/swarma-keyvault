package seedsetup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// Equal and separate identities are explicit and independent. Missing,
// malformed, legacy, duplicate and secret-input flags cannot form a plan.
func TestExplicitIdentityArguments(t *testing.T) {
	for _, pair := range [][2]string{{"north", "south"}, {"north", "north"}, {"south", "north"}} {
		c, err := Parse([]string{"--nostr-identity", pair[0], "--namecoin-identity", pair[1]})
		if err != nil || c.NostrIdentity != pair[0] || c.NamecoinIdentity != pair[1] || c.Version != 0 {
			t.Fatal("valid explicit identities refused", err)
		}
	}
	base := []string{"--nostr-identity", "north", "--namecoin-identity", "south"}
	for _, args := range [][]string{
		nil, {"--nostr-identity", "north"}, {"--namecoin-identity", "south"},
		{"--nostr-identity", "bad/name", "--namecoin-identity", "south"},
		append(append([]string{}, base...), "--nostr-identity", "other"),
		append(append([]string{}, base...), "--service", "legacy"),
		append(append([]string{}, base...), "--seed", "public-control"),
		append(append([]string{}, base...), "--version", "0"),
		append(append([]string{}, base...), "--nostr-version", "2147483648"),
		append(append([]string{}, base...), "--namecoin-version", "-1"),
		append(append([]string{}, base...), "--version", "1", "--version", "2"),
		append(append([]string{}, base...), "--artifact-dir", "relative"),
		append(append([]string{}, base...), "--artifact-dir", "/tmp/../tmp"),
		append(append([]string{}, base...), "--qualification-nostr-identity", "test"),
		append(append([]string{}, base...), "--qualification-nostr-identity", "north", "--qualification-namecoin-identity", "test"),
	} {
		if c, err := Parse(args); err == nil || c != (Config{}) {
			t.Fatal("invalid arguments produced configuration")
		}
	}

	c, err := Parse(append(base, "--version", "7", "--nostr-version", "9", "--namecoin-version", "11", "--qualification-nostr-identity", "test-a", "--qualification-namecoin-identity", "test-b", "--artifact-dir", "/tmp/public-release"))
	if err != nil || c.Version != 7 || c.NostrVersion != 9 || c.NamecoinVersion != 11 || c.QualificationNostr != "test-a" || c.QualificationNamecoin != "test-b" {
		t.Fatal("explicit generations/qualification changed", err)
	}
}

// Disposable names derive from each selected identity, remain valid at the
// name-length limit, and require entropy only when explicit names are absent.
func TestDisposableIdentitySelection(t *testing.T) {
	c := Config{NostrIdentity: "north", NamecoinIdentity: "south"}
	i, err := SelectIdentities(c, bytes.NewReader(make([]byte, 8)))
	if err != nil || !strings.HasPrefix(i.QualificationNostr, "north-qualification-") || !strings.HasPrefix(i.QualificationNamecoin, "south-qualification-") {
		t.Fatal("derived identities lost selected inputs", err)
	}
	swapped, err := SelectIdentities(Config{NostrIdentity: "south", NamecoinIdentity: "north"}, bytes.NewReader(make([]byte, 8)))
	if err != nil || swapped.QualificationNostr != i.QualificationNamecoin || swapped.QualificationNamecoin != i.QualificationNostr {
		t.Fatal("swapped input did not swap derived names")
	}
	for _, random := range []io.Reader{nil, bytes.NewReader(nil), bytes.NewReader(make([]byte, 7))} {
		if _, err := SelectIdentities(c, random); err == nil || err.Error() != "qualification_entropy_unavailable" {
			t.Fatal("missing entropy accepted")
		}
	}
	c.NostrIdentity = strings.Repeat("n", signerclient.MaxNameLength)
	c.NamecoinIdentity = c.NostrIdentity
	i, err = SelectIdentities(c, bytes.NewReader(make([]byte, 8)))
	if err != nil || !validIdentity(i.QualificationNostr) || len(i.QualificationNostr) > signerclient.MaxNameLength || i.QualificationNostr != i.QualificationNamecoin {
		t.Fatal("maximum-length/equal identities refused")
	}
	c.QualificationNostr, c.QualificationNamecoin = "test-a", "test-b"
	if i, err := SelectIdentities(c, nil); err != nil || i.QualificationNostr != "test-a" || i.QualificationNamecoin != "test-b" {
		t.Fatal("explicit public names required entropy")
	}
	c.QualificationNamecoin = ""
	if _, err := SelectIdentities(c, nil); err == nil || err.Error() != "both_qualification_identities_required" {
		t.Fatal("one explicit disposable name inferred the other")
	}
}

// Injected homes produce disjoint per-user installation/lock paths without
// creating either home. Invalid source/version/path inputs yield no paths.
func TestPerUserPathsNoWrites(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "account-a"), filepath.Join(root, "account-b")
	head := strings.Repeat("1", 40)
	pa, err := UserPaths(a, "/tmp/public-release/keyvault-seed", "", "v0.2.0", head)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := UserPaths(b, "/tmp/public-release/keyvault-seed", "/tmp/other-release", "v0.2.0", head)
	if err != nil || !strings.HasPrefix(pa.InstallDirectory, a+string(os.PathSeparator)) || !strings.HasPrefix(pb.InstallDirectory, b+string(os.PathSeparator)) || pa.Lock == pb.Lock || pa.ArtifactDirectory != "/tmp/public-release" || pb.ArtifactDirectory != "/tmp/other-release" {
		t.Fatal("user paths crossed homes", err)
	}
	for _, home := range []string{a, b} {
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatal("public plan created user directories")
		}
	}
	for _, bad := range [][5]string{
		{"relative", "/tmp/tool", "", "v0.2.0", head},
		{a, "relative", "", "v0.2.0", head},
		{a, "/tmp/tool", "../other", "v0.2.0", head},
		{a, "/tmp/tool", "", "../escape", head},
		{a, "/tmp/tool", "", "v0.2.0", "not-a-source-pin"},
	} {
		if _, err := UserPaths(bad[0], bad[1], bad[2], bad[3], bad[4]); err == nil {
			t.Fatal("invalid path/pin accepted")
		}
	}
}

// Valid UTF-8 homes and release paths preserve their exact bytes. Control,
// format, invalid UTF-8 and traversal paths remain forbidden without writes.
func TestUnicodeUserPaths(t *testing.T) {
	for _, home := range []string{"/fixture-homes/é", "/fixture-homes/测试", "/fixture-homes/թ"} {
		p, err := UserPaths(home, home+"/Загрузки/keyvault-seed", "", "v0.2.0", strings.Repeat("1", 40))
		if err != nil || p.Home != home || !strings.HasPrefix(p.InstallDirectory, home+"/") {
			t.Fatal("valid UTF-8 path refused", err)
		}
	}
	for _, home := range []string{"/fixture-homes/a\nother", "/fixture-homes/a\x00other", "/fixture-homes/a\u202eother", "/fixture-homes/\xff", "/fixture-homes/a/../b"} {
		if p, err := UserPaths(home, "/tmp/keyvault-seed", "", "v0.2.0", strings.Repeat("1", 40)); err == nil || p.Home != "" {
			_ = p
			t.Fatal("unsafe path admitted")
		}
	}
}
