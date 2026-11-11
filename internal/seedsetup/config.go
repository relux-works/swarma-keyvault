// Package seedsetup runs the attended seed setup. Its preflight uses public
// configuration; the vault handles custody and actual recovery words.
package seedsetup

import (
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

type Config struct {
	NostrIdentity, NamecoinIdentity           string
	Version, NostrVersion, NamecoinVersion    int
	QualificationNostr, QualificationNamecoin string
	ArtifactDirectory                         string
}

func validIdentity(s string) bool {
	return signerclient.ValidateName("identity", signerclient.CodeInvalidService, s) == nil
}

// Parse requires both identities and rejects repeated or unsupported inputs.
// Zero generations mean advisory selection, never an inferred identity.
func Parse(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("keyvault-seed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	seen := map[string]bool{}
	str := func(name string, p *string) {
		fs.Func(name, "public setup parameter", func(v string) error {
			if seen[name] {
				return errors.New("duplicate_parameter")
			}
			seen[name] = true
			*p = v
			return nil
		})
	}
	number := func(name string, p *int) {
		fs.Func(name, "public generation", func(v string) error {
			if seen[name] {
				return errors.New("duplicate_parameter")
			}
			seen[name] = true
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 2147483647 || strconv.Itoa(n) != v {
				return errors.New("invalid_generation")
			}
			*p = n
			return nil
		})
	}
	str("nostr-identity", &c.NostrIdentity)
	str("namecoin-identity", &c.NamecoinIdentity)
	str("qualification-nostr-identity", &c.QualificationNostr)
	str("qualification-namecoin-identity", &c.QualificationNamecoin)
	str("artifact-dir", &c.ArtifactDirectory)
	number("version", &c.Version)
	number("nostr-version", &c.NostrVersion)
	number("namecoin-version", &c.NamecoinVersion)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return Config{}, errors.New("invalid_arguments")
	}
	if !validIdentity(c.NostrIdentity) || !validIdentity(c.NamecoinIdentity) {
		return Config{}, errors.New("both_identities_required")
	}
	if seen["qualification-nostr-identity"] || seen["qualification-namecoin-identity"] {
		if !validIdentity(c.QualificationNostr) || !validIdentity(c.QualificationNamecoin) {
			return Config{}, errors.New("both_qualification_identities_required")
		}
		if c.QualificationNostr == c.NostrIdentity || c.QualificationNamecoin == c.NamecoinIdentity {
			return Config{}, errors.New("qualification_identity_collision")
		}
	}
	if seen["artifact-dir"] && (c.ArtifactDirectory == "" || !filepath.IsAbs(c.ArtifactDirectory) || filepath.Clean(c.ArtifactDirectory) != c.ArtifactDirectory) {
		return Config{}, errors.New("invalid_artifact_directory")
	}
	return c, nil
}

type Identities struct{ Nostr, Namecoin, QualificationNostr, QualificationNamecoin string }

// SelectIdentities derives bounded disposable names from the selected actual
// identities and one caller-supplied random suffix. Explicit names need no
// entropy. Inventory checks must still reject collisions before mutation.
func SelectIdentities(c Config, random io.Reader) (Identities, error) {
	var zero Identities
	if !validIdentity(c.NostrIdentity) || !validIdentity(c.NamecoinIdentity) {
		return zero, errors.New("both_identities_required")
	}
	i := Identities{Nostr: c.NostrIdentity, Namecoin: c.NamecoinIdentity, QualificationNostr: c.QualificationNostr, QualificationNamecoin: c.QualificationNamecoin}
	if i.QualificationNostr != "" || i.QualificationNamecoin != "" {
		if !validIdentity(i.QualificationNostr) || !validIdentity(i.QualificationNamecoin) {
			return zero, errors.New("both_qualification_identities_required")
		}
	} else {
		var nonce [8]byte
		if random == nil {
			return zero, errors.New("qualification_entropy_unavailable")
		}
		if _, err := io.ReadFull(random, nonce[:]); err != nil {
			return zero, errors.New("qualification_entropy_unavailable")
		}
		suffix := "-qualification-" + hex.EncodeToString(nonce[:])
		derive := func(s string) string {
			limit := signerclient.MaxNameLength - len(suffix)
			if len(s) > limit {
				s = s[:limit]
			}
			return s + suffix
		}
		i.QualificationNostr, i.QualificationNamecoin = derive(i.Nostr), derive(i.Namecoin)
	}
	if i.QualificationNostr == i.Nostr || i.QualificationNamecoin == i.Namecoin {
		return zero, errors.New("qualification_identity_collision")
	}
	return i, nil
}

type Paths struct {
	Home, ArtifactDirectory, Root, BinaryParent, InstallDirectory string
	LockParents                                                   []string
	Lock                                                          string
}

// UserPaths uses the caller's resolved OS home and executable location; it
// neither trusts a compiled account nor creates any of the returned paths.
func UserPaths(home, executable, artifactDirectory, version, sourceHead string) (Paths, error) {
	var zero Paths
	cleanAbs := func(s string) bool {
		if !utf8.ValidString(s) || !filepath.IsAbs(s) || filepath.Clean(s) != s || s == "/" || len(s) > 2048 {
			return false
		}
		for _, r := range s {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return false
			}
		}
		return true
	}
	if !cleanAbs(home) || !cleanAbs(executable) || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		return zero, errors.New("invalid_runtime_paths")
	}
	h, err := hex.DecodeString(sourceHead)
	if err != nil || len(h) != 20 || hex.EncodeToString(h) != sourceHead {
		return zero, errors.New("invalid_source_pin")
	}
	if artifactDirectory == "" {
		artifactDirectory = filepath.Dir(executable)
	}
	if !cleanAbs(artifactDirectory) {
		return zero, errors.New("invalid_artifact_directory")
	}
	root := filepath.Join(home, "Library", "Application Support", "swarma-keyvault")
	locks := filepath.Join(home, "Library", "Application Support", "mac-infra")
	bin := filepath.Join(root, "bin")
	return Paths{Home: home, ArtifactDirectory: artifactDirectory, Root: root, BinaryParent: bin, InstallDirectory: filepath.Join(bin, version+"-"+sourceHead), LockParents: []string{locks, filepath.Join(locks, "keyvault")}, Lock: filepath.Join(locks, "keyvault", "init.lock")}, nil
}
