package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

const prepareUsage = "swarma-keyvault grants prepare --plan FILE|- --owner-mxid MXID --issuer-spki-der FILE"
const localPrepareUsage = "swarma-keyvault grants local-prepare --plan FILE|- --owner-mxid MXID --issuer-spki-der FILE --requester-spki-der FILE"

type onceString struct {
	value string
	set   bool
}

func (v *onceString) String() string { return v.value }
func (v *onceString) Set(value string) error {
	if v.set {
		return errors.New("option repeated")
	}
	v.value, v.set = value, true
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) >= 2 && args[0] == "grants" {
		switch args[1] {
		case "a2a-prepare":
			return runA2ACertificate(args[2:], stdin, stdout, stderr, false)
		case "a2a-issue":
			return runA2ACertificate(args[2:], stdin, stdout, stderr, true)
		case "a2a-request-prepare":
			return runA2ARequest(args[2:], stdin, stdout, stderr, false)
		case "a2a-request-pack":
			return runA2ARequest(args[2:], stdin, stdout, stderr, true)
		}
	}
	if len(args) >= 2 && args[0] == "grants" && args[1] == "local-issue" {
		return runIssueProfile(args[2:], stdin, stdout, stderr, true)
	}
	if len(args) >= 2 && args[0] == "grants" && args[1] == "local-prepare" {
		return runPrepare(args[2:], stdin, stdout, stderr, true)
	}
	if len(args) >= 2 && args[0] == "grants" && args[1] == "issue" {
		return runIssue(args[2:], stdin, stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "grants" && args[1] == "request" {
		return runRequest(args[2:], stdin, stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "grants" && args[1] == "execute" {
		return runExecute(args[2:], stdin, stdout, stderr)
	}
	usage := func() int { _, _ = fmt.Fprintln(stderr, prepareUsage); return 2 }
	if len(args) < 2 || args[0] != "grants" || args[1] != "prepare" {
		return usage()
	}
	return runPrepare(args[2:], stdin, stdout, stderr, false)
}

func runPrepare(args []string, stdin io.Reader, stdout, stderr io.Writer, local bool) int {
	usageText := prepareUsage
	if local {
		usageText = localPrepareUsage
	}
	usage := func() int { _, _ = fmt.Fprintln(stderr, usageText); return 2 }
	var plan, owner, spki, requester onceString
	flags := flag.NewFlagSet("grants prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&plan, "plan", "explicit canonical draft file, or - for stdin")
	flags.Var(&owner, "owner-mxid", "exact owner Matrix account")
	flags.Var(&spki, "issuer-spki-der", "explicit public P-256 SPKI DER file")
	if local {
		flags.Var(&requester, "requester-spki-der", "explicit requester public P-256 DER file")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(stderr, usageText)
			return 0
		}
		return usage()
	}
	if (local && (!requester.set || requester.value == "" || requester.value == "-")) || flags.NArg() != 0 || !plan.set || !owner.set || !spki.set || plan.value == "" || owner.value == "" || spki.value == "" || spki.value == "-" {
		return usage()
	}
	draft, err := readInput(plan.value, stdin, 65536)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded draft")
		return 1
	}
	// A public key is a separate explicit file, never a second stdin read.
	public, err := readInput(spki.value, nil, 1024)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "cannot read bounded public SPKI DER")
		return 1
	}
	var prepared *grants.UnsignedCertificate
	if local {
		requesterPublic, readErr := readInput(requester.value, nil, 1024)
		if readErr != nil {
			_, _ = fmt.Fprintln(stderr, "cannot read bounded requester SPKI DER")
			return 1
		}
		prepared, err = grants.PrepareLocalRepositoryCertificate(draft, owner.value, public, requesterPublic)
	} else {
		prepared, err = grants.PrepareRepositoryCertificate(draft, owner.value, public)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	// A failed review sink must not release even an unsigned payload. Neither
	// stream is a transactional store or an authenticated signing boundary.
	if n, err := io.WriteString(stderr, prepared.Review); err != nil || n != len(prepared.Review) {
		return 1
	}
	if n, err := stdout.Write(prepared.Payload); err != nil || n != len(prepared.Payload) {
		return 1
	}
	return 0
}

func readInput(path string, stdin io.Reader, maximum int64) ([]byte, error) {
	reader := stdin
	if path != "-" {
		// Refuse ordinary non-regular paths before open: opening a FIFO could
		// otherwise wait for a writer. Recheck the opened descriptor below.
		// This is bounded input handling, not a same-user race boundary.
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("regular input file required")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err = file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("regular input file required")
		}
		reader = file
	}
	if reader == nil {
		return nil, errors.New("input unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("input unavailable or over limit")
	}
	return raw, nil
}
