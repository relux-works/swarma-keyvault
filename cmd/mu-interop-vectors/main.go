// Command mu-interop-vectors writes the multi-use grant interop vector set:
// one JSON file per case plus the published test keys. Signatures are fresh
// on every run, so regenerating changes the files; the committed set is the
// contract and the Go check verifies it.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/relux-works/swarma-keyvault/internal/muinterop"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	f := flag.NewFlagSet("mu-interop-vectors", flag.ContinueOnError)
	f.SetOutput(stderr)
	out := f.String("out", "", "directory to write (must not exist)")
	owner := f.String("owner", "", "synthetic fixture owner (owner:NAME)")
	uidText := f.String("linux-uid", "", "synthetic Linux UID")
	parseErr := f.Parse(args)
	uid, uidErr := strconv.ParseInt(*uidText, 10, 64)
	if parseErr != nil || *out == "" || f.NArg() != 0 || muinterop.ValidateFixtureOwner(*owner) != nil ||
		uidErr != nil || uid < 0 || uid > 4294967294 || strconv.FormatInt(uid, 10) != *uidText {
		fmt.Fprintln(stderr, "usage: mu-interop-vectors -out DIR -owner owner:NAME -linux-uid UID")
		return 2
	}
	if err := write(*out, *owner, uid); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func write(dir, owner string, uid int64) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	cases, err := muinterop.MacFamily(owner)
	if err != nil {
		return err
	}
	linux, err := muinterop.LinuxFamily(owner, uid)
	if err != nil {
		return err
	}
	cases = append(cases, linux...)
	publisher2, err := muinterop.PublisherEd25519Family(owner)
	if err != nil {
		return err
	}
	cases = append(cases, publisher2...)
	if err := os.Mkdir(filepath.Join(dir, "cases"), 0o755); err != nil {
		return err
	}
	for _, c := range cases {
		if err := writeJSON(filepath.Join(dir, "cases", c.ID+".json"), c); err != nil {
			return err
		}
	}
	type keyFile struct {
		Name, Algorithm, KeyID, SeedHex, SPKIHex string
	}
	var keys []keyFile
	for _, name := range muinterop.KeyNames {
		k, err := muinterop.P256(name)
		if err != nil {
			return err
		}
		keys = append(keys, keyFile{name, "P-256", k.ID, hex.EncodeToString(k.Seed), hex.EncodeToString(k.SPKI)})
	}
	for _, name := range muinterop.EdKeyNames {
		k, err := muinterop.Ed25519(name)
		if err != nil {
			return err
		}
		keys = append(keys, keyFile{name, "Ed25519", k.ID, hex.EncodeToString(k.Seed), hex.EncodeToString(k.Public)})
	}
	return writeJSON(filepath.Join(dir, "keys.json"), keys)
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
