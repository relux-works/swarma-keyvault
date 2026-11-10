// labtestsigner is a separate, non-release fixture tool. Never use owner keys.
// It has no KeyVault backend, Enclave fallback, provider, or network client.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func regular(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute clean file required")
	}
	f, err := os.Lstat(path)
	if err != nil || !f.Mode().IsRegular() || f.Size() > limit {
		return nil, errors.New("bounded regular file required")
	}
	if private {
		p, err := os.Lstat(filepath.Dir(path))
		if err != nil || !p.IsDir() || p.Mode().Perm() != 0700 || f.Mode().Perm() != 0600 {
			return nil, errors.New("private key custody permissions required")
		}
	}
	h, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input unavailable")
	}
	defer h.Close()
	raw, err := io.ReadAll(io.LimitReader(h, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("input limit exceeded")
	}
	return raw, nil
}

func lowS(key *ecdsa.PrivateKey, digest [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		s.Sub(key.Params().N, s)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func generate(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("absolute clean new custody directory required")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return errors.New("custody directory must be new")
	}
	for _, role := range []string{"owner", "requester", "adversary"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.New("test key generation failed")
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		for name, raw := range map[string][]byte{role + ".pk8": private, role + ".der": public} {
			f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return errors.New("test key custody write failed")
			}
			_, err = f.Write(raw)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				return errors.New("test key custody write failed")
			}
		}
	}
	return nil
}

func run(args []string, out, stderr io.Writer) int {
	refuse := func(err error) int { fmt.Fprintln(stderr, "lab test signer refused:", err); return 1 }
	if len(args) == 0 {
		fmt.Fprintln(stderr, "labtestsigner keygen|prepare-request|certificate|request [flags]")
		return 2
	}
	f := flag.NewFlagSet("labtestsigner", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var dir, payload, keyFile, ownerFile, requesterFile, digest string
	f.StringVar(&dir, "dir", "", "new private throwaway-key custody directory")
	f.StringVar(&payload, "payload", "", "exact prepared payload file")
	f.StringVar(&keyFile, "key", "", "locally held throwaway PKCS8 P-256 key")
	f.StringVar(&ownerFile, "owner-spki", "", "public owner DER")
	f.StringVar(&requesterFile, "requester-spki", "", "public requester DER")
	f.StringVar(&digest, "digest", "", "exact prepared SHA256 digest, lowercase hex")
	expectedOwner := ""
	ownerSet := false
	f.Func("owner-mxid", "required independently expected certificate owner", func(value string) error {
		if ownerSet || value == "" {
			return errors.New("one nonempty expected owner required")
		}
		ownerSet = true
		expectedOwner = value
		return nil
	})
	seen := map[string]bool{}
	// Reject duplicate flags instead of silently replacing an explicit input.
	for _, arg := range args[1:] {
		if len(arg) > 2 && arg[:2] == "--" {
			name := arg
			for i, c := range name {
				if c == '=' {
					name = name[:i]
					break
				}
			}
			if seen[name] {
				return 2
			}
			seen[name] = true
		}
	}
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
		return 2
	}
	if args[0] == "certificate" && (!ownerSet || grants.ValidateOwnerPrincipal(expectedOwner) != nil) {
		return 2
	}
	if ownerSet && args[0] != "certificate" {
		return 2
	}
	if args[0] == "keygen" {
		if dir == "" || payload != "" || keyFile != "" || ownerFile != "" || requesterFile != "" || digest != "" {
			return 2
		}
		if err := generate(dir); err != nil {
			return refuse(err)
		}
		return 0
	}
	if dir != "" || (args[0] != "certificate" && args[0] != "request" && args[0] != "prepare-request") {
		return 2
	}
	if payload == "" || requesterFile == "" {
		return 2
	}
	raw, err := regular(payload, 65536, false)
	if err != nil {
		return refuse(err)
	}
	requester, err := regular(requesterFile, 1024, false)
	if err != nil {
		return refuse(err)
	}
	var expected [32]byte
	var envelope func([]byte) ([]byte, error)
	var public []byte
	if args[0] == "certificate" {
		if ownerFile == "" {
			return 2
		}
		owner, err := regular(ownerFile, 1024, false)
		if err != nil {
			return refuse(err)
		}
		plan, err := grants.NewLocalRepositoryIssuance(raw, expectedOwner, owner, requester, grants.LocalOrganization, grants.LocalRepository)
		if err != nil {
			return refuse(err)
		}
		expected = plan.Digest()
		envelope = plan.SignedEnvelope
		public = owner
	} else {
		if ownerFile != "" {
			return 2
		}
		plan, err := grants.PrepareLocalRequest(raw, requester)
		if err != nil {
			return refuse(err)
		}
		expected = plan.Digest()
		envelope = plan.SignedEnvelope
		public = requester
	}
	if args[0] == "prepare-request" {
		if keyFile != "" || digest != "" {
			return 2
		}
		_, err := fmt.Fprintf(out, "%x", expected)
		if err != nil {
			return 1
		}
		return 0
	}
	if keyFile == "" || digest == "" {
		return 2
	}
	if digest != hex.EncodeToString(expected[:]) {
		return refuse(errors.New("prepared digest mismatch"))
	}
	keyRaw, err := regular(keyFile, 4096, true)
	if err != nil {
		return refuse(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyRaw)
	if err != nil {
		return refuse(errors.New("test key encoding invalid"))
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return refuse(errors.New("test P-256 key required"))
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(der, public) {
		return refuse(errors.New("test key does not match public pin"))
	}
	signature, err := lowS(key, expected)
	if err != nil {
		return refuse(errors.New("test signature failed"))
	}
	encoded, err := envelope(signature)
	if err != nil {
		return refuse(err)
	}
	limit := 12288
	if args[0] == "certificate" {
		limit = 98304
	}
	if len(encoded) >= limit {
		return refuse(errors.New("serialized envelope limit exceeded"))
	}
	n, err := out.Write(encoded)
	if err != nil || n != len(encoded) {
		return 1
	}
	return 0
}
