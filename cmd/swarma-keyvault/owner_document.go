package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/ownerdocument"
)

const ownerDocumentUsage = "swarma-keyvault owner-document review|sign|verify --document FILE --owner-spki-der FILE [--signature FILE (verify only)]"

func runOwnerDocument(args []string, stdout, stderr io.Writer) int {
	usage := func() int { fmt.Fprintln(stderr, ownerDocumentUsage); return 2 }
	if len(args) == 0 {
		return usage()
	}
	op := args[0]
	if op != "review" && op != "sign" && op != "verify" {
		return usage()
	}
	f := flag.NewFlagSet("owner-document "+op, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var document, public, signature onceString
	f.Var(&document, "document", "exact nonempty bounded UTF-8 regular file (no symlinks)")
	f.Var(&public, "owner-spki-der", "independent exact owner P-256 SPKI DER pin")
	if op == "verify" {
		f.Var(&signature, "signature", "detached strict low-S DER file")
	}
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, ownerDocumentUsage)
			return 0
		}
		return usage()
	}
	if f.NArg() != 0 || !document.set || !public.set || document.value == "" || document.value == "-" || public.value == "" || public.value == "-" || op == "verify" && (!signature.set || signature.value == "" || signature.value == "-") {
		return usage()
	}
	raw, err := ownerdocument.ReadFile(document.value, ownerdocument.MaxDocumentBytes)
	if err != nil {
		fmt.Fprintln(stderr, "owner-document: cannot read bounded regular document")
		return 1
	}
	pin, err := ownerdocument.ReadFile(public.value, ownerdocument.MaxSPKIBytes)
	if err != nil {
		fmt.Fprintln(stderr, "owner-document: cannot read bounded public DER")
		return 1
	}
	p, err := ownerdocument.Prepare(raw, pin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	switch op {
	case "review":
		if err := p.Render(stdout); err != nil {
			fmt.Fprintln(stderr, "owner-document: full rendering failed; no confirmation or signature")
			return 1
		}
		current, err := ownerdocument.ReadFile(document.value, ownerdocument.MaxDocumentBytes)
		if err != nil || p.CheckSource(current) != nil {
			fmt.Fprintln(stderr, ownerdocument.ErrChanged)
			return 1
		}
		return 0
	case "verify":
		der, err := ownerdocument.ReadFile(signature.value, 80)
		if err == nil {
			err = p.Verify(der)
		}
		if err != nil {
			fmt.Fprintln(stderr, "owner-document: exact-byte public verification refused")
			return 1
		}
		current, err := ownerdocument.ReadFile(document.value, ownerdocument.MaxDocumentBytes)
		if err != nil || p.CheckSource(current) != nil {
			fmt.Fprintln(stderr, ownerdocument.ErrChanged)
			return 1
		}
		text := "verified exact document (detached P-256 SHA256 low-S DER); no grant authority asserted\n"
		if n, err := io.WriteString(stdout, text); err != nil || n != len(text) {
			return 1
		}
		return 0
	default:
		// The matching macOS helper owns complete review and presence, in order.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		der, err := p.SignFile(ctx, document.value)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if n, err := stdout.Write(der); err != nil || n != len(der) {
			fmt.Fprintln(stderr, ownerdocument.ErrOutcomeUnknown)
			return 1
		}
		return 0
	}
}
