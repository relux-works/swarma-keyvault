package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

var newNostrBackend = func() keyvault.NostrBackend { return keyvault.NewNostrSecurityStore() }

const nostrUsage = "mac-keyvault [--json] nostr generate --service S --purpose P [--version N] | nostr list | nostr describe|pub|sign SERVICE/PURPOSE [--version N] [pub: --format x-only-hex|npub] [sign: --digest HEX] | nostr verify --pub HEX --digest HEX --sig HEX | nostr delete SERVICE/PURPOSE --version N --expected-npub NPUB"

func runNostr(args []string, out output) int {
	if len(args) == 0 {
		return out.fail(usagef("nostr requires an operation"))
	}
	op := args[0]
	// Closed command/flag vocabulary, before constructing or contacting a store.
	switch op {
	case "generate", "list", "describe", "pub", "sign", "verify", "delete":
	default:
		return out.fail(usagef("unsupported Nostr operation; private import and export are refused"))
	}
	fs := flag.NewFlagSet("nostr "+op, flag.ContinueOnError)
	var service, purpose, digestText, format, publicText, signatureText, expectedNPub string
	version := 1
	if op == "generate" {
		fs.StringVar(&service, "service", "", "service")
		fs.StringVar(&purpose, "purpose", "", "purpose")
	}
	if op != "list" && op != "verify" {
		defaultVersion := 1
		if op == "delete" {
			defaultVersion = 0
		}
		fs.IntVar(&version, "version", defaultVersion, "generation; delete requires an explicit version")
	}
	if op == "sign" || op == "verify" {
		fs.StringVar(&digestText, "digest", "", "32-byte NIP-01 event id, hexadecimal")
	}
	if op == "delete" {
		fs.StringVar(&expectedNPub, "expected-npub", "", "exact public Nostr pin")
	}
	if op == "pub" {
		fs.StringVar(&format, "format", "x-only-hex", "x-only-hex or npub")
	}
	if op == "verify" {
		fs.StringVar(&publicText, "pub", "", "x-only public key hexadecimal")
		fs.StringVar(&signatureText, "sig", "", "BIP-340 signature hexadecimal")
	}
	positional, err := parseFlags(fs, args[1:])
	if err != nil {
		return out.fail(usagef("invalid Nostr arguments; see help"))
	}
	if op == "describe" || op == "pub" || op == "sign" || op == "delete" {
		if len(positional) != 1 {
			return out.fail(usagef("one SERVICE/PURPOSE address is required"))
		}
		parts := strings.Split(positional[0], "/")
		if len(parts) != 2 {
			return out.fail(usagef("invalid Nostr address"))
		}
		service, purpose = parts[0], parts[1]
	} else if len(positional) != 0 {
		return out.fail(usagef("unexpected Nostr positional arguments"))
	}
	if op != "list" && op != "verify" {
		if keyvault.ValidateName("service", keyvault.CodeInvalidService, service) != nil || keyvault.ValidateName("purpose", keyvault.CodeInvalidPurpose, purpose) != nil || version < 1 || version > 2147483647 {
			return out.fail(usagef("invalid Nostr address or generation"))
		}
	}
	if op == "pub" && format != "x-only-hex" && format != "npub" {
		return out.fail(usagef("public format must be x-only-hex or npub; private export is refused"))
	}
	if op == "delete" && expectedNPub == "" {
		return out.fail(usagef("exact public Nostr pin required"))
	}
	var digest []byte
	if op == "sign" || op == "verify" {
		digest, err = hex.DecodeString(digestText)
		if err != nil || len(digest) != 32 {
			return out.fail(usagef("digest must be exactly 32 bytes encoded as 64 hexadecimal characters"))
		}
	}
	if op == "verify" {
		public, err := hex.DecodeString(publicText)
		if err != nil {
			return out.fail(usagef("invalid public key encoding"))
		}
		sig, err := hex.DecodeString(signatureText)
		if err != nil {
			return out.fail(usagef("invalid signature encoding"))
		}
		if err := keyvault.VerifyNostr(public, digest, sig); err != nil {
			return out.fail(err)
		}
		return out.success(map[string]bool{"verified": true}, func(w io.Writer) { fmt.Fprintln(w, "verified: true") })
	}
	lock, err := vaultLock()
	if err != nil {
		return out.fail(err)
	}
	m := keyvault.NewNostrManager(newNostrBackend(), lock)
	if op == "delete" {
		if expectedNPub == "" {
			return out.fail(usagef("exact public Nostr pin required"))
		}
		if err := m.Delete(service, purpose, version, expectedNPub); err != nil {
			return out.fail(err)
		}
		return out.success(map[string]bool{"deleted": true}, func(w io.Writer) { fmt.Fprintln(w, "deleted: true") })
	}
	if op == "list" {
		records, err := m.List()
		if err != nil {
			return out.fail(err)
		}
		return out.success(records, func(w io.Writer) {
			for _, r := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\tpresence=false\n", r.Account(), r.PublicKey, r.NPub, r.Storage)
			}
		})
	}
	if op == "sign" {
		sig, err := m.Sign(service, purpose, version, digest)
		if err != nil {
			return out.fail(err)
		}
		text := hex.EncodeToString(sig)
		return out.success(map[string]string{"algorithm": "secp256k1-bip340", "signature": text}, func(w io.Writer) { fmt.Fprintln(w, text) })
	}
	var rec keyvault.NostrRecord
	if op == "generate" {
		rec, err = m.Generate(service, purpose, version)
	} else {
		rec, err = m.Describe(service, purpose, version)
	}
	if err != nil {
		return out.fail(err)
	}
	if op == "pub" {
		value := rec.PublicKey
		if format == "npub" {
			value = rec.NPub
		}
		return out.success(map[string]string{"format": format, "public_key": value}, func(w io.Writer) { fmt.Fprintln(w, value) })
	}
	return out.success(rec, func(w io.Writer) {
		fmt.Fprintf(w, "%s\nalgorithm: %s\nstorage: %s\npresence: false\nprivate_export: false\npublic_key: %s\nnpub: %s\n", rec.Account(), rec.Algorithm, rec.Storage, rec.PublicKey, rec.NPub)
	})
}
