package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

// maxSSHUnlock bounds --unlock-for: an unlock is a working session, not a
// standing grant.
const maxSSHUnlock = 24 * time.Hour

type sshRepeated []string

func (s *sshRepeated) String() string         { return strings.Join(*s, ",") }
func (s *sshRepeated) Set(value string) error { *s = append(*s, value); return nil }

func runSSHAgent(args []string, out output) int {
	fs := flag.NewFlagSet("ssh-agent", flag.ContinueOnError)
	socket := fs.String("socket", "", "absolute Unix socket in an owned 0700 directory")
	var keys, hookArgs sshRepeated
	fs.Var(&keys, "key", "explicit service/purpose@VERSION (repeatable)")
	hookPath := fs.String("confirm-exec", "", "absolute confirmation executable; exit 0 grants each use")
	fs.Var(&hookArgs, "confirm-arg", "literal confirmation argument (repeatable)")
	hookTimeout := fs.Duration("confirm-timeout", 15*time.Second, "confirmation deadline (at most 1m)")
	confirmWhen := fs.String("confirm-when", "sign", "when the hook is asked: sign (each signature), unlock (once at start), both")
	unlockFor := fs.Duration("unlock-for", 0, "serve only this long (at most 24h), then refuse, remove the socket and exit 0")
	namespace := fs.String("sign-namespace", "", "sign only ssh-keygen -Y sign requests with this namespace (for example git); refuse authentication and any other data")
	auditPath := fs.String("audit-log", "", "absolute append-only JSONL file; one record per signature request, written before a signature is returned")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	if len(positional) != 0 || *socket == "" || len(keys) == 0 || len(keys) > 32 {
		return out.fail(usagef("ssh-agent requires --socket PATH and 1..32 --key service/purpose@VERSION, with no positional arguments"))
	}
	addresses := make([]keyvault.Address, 0, len(keys))
	for _, input := range keys {
		name, ver, ok := strings.Cut(input, "@")
		version, parseErr := strconv.Atoi(ver)
		if !ok || parseErr != nil || version < 1 {
			return out.fail(usagef("--key requires service/purpose@VERSION with an explicit positive version"))
		}
		addr, err := keyvault.ParseAddress(name, keyvault.KindKey, version)
		if err != nil {
			return out.fail(err)
		}
		addresses = append(addresses, addr)
	}
	unlockSet, whenSet, namespaceSet, auditSet := false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		unlockSet = unlockSet || f.Name == "unlock-for"
		whenSet = whenSet || f.Name == "confirm-when"
		namespaceSet = namespaceSet || f.Name == "sign-namespace"
		auditSet = auditSet || f.Name == "audit-log"
	})
	if namespaceSet && !keyvault.ValidSSHSigNamespace(*namespace) {
		return out.fail(usagef("--sign-namespace must be 1-64 characters of letters, digits and @._- starting with a letter or digit"))
	}
	if auditSet && !filepath.IsAbs(*auditPath) {
		return out.fail(usagef("--audit-log requires an absolute path"))
	}
	if unlockSet && (*unlockFor <= 0 || *unlockFor > maxSSHUnlock) {
		return out.fail(usagef("--unlock-for must be in (0, 24h]"))
	}
	confirmSign, confirmUnlock := false, false
	switch *confirmWhen {
	case "sign":
		confirmSign = true
	case "unlock":
		confirmUnlock = true
	case "both":
		confirmSign, confirmUnlock = true, true
	default:
		return out.fail(usagef("--confirm-when must be sign, unlock or both"))
	}
	if confirmUnlock && !unlockSet {
		return out.fail(usagef("--confirm-when %s requires --unlock-for", *confirmWhen))
	}
	var hook func(context.Context, keyvault.SSHConfirmation) error
	if *hookPath != "" {
		hook, err = keyvault.SSHConfirmHook(*hookPath, hookArgs, *hookTimeout)
		if err != nil {
			return out.fail(usagef("%s", err))
		}
	} else if len(hookArgs) != 0 || *hookTimeout != 15*time.Second || whenSet {
		// An explicit --confirm-when without a hook would silently sign
		// unconfirmed; only the absent flag keeps hook-free signing.
		return out.fail(usagef("confirmation options require --confirm-exec"))
	}
	signHook := hook
	if !confirmSign {
		signHook = nil
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(errors.New("SSH keyvault unavailable"))
	}
	agent, err := keyvault.NewSSHAgent(manager, addresses, signHook)
	if err != nil {
		classified := keyvault.ClassifyError(err)
		return out.fail(&keyvault.Refusal{Code: classified.Code, Failure: classified.Failure, Status: classified.Status, Message: "SSH identities unavailable or signing policy refused", Hint: "use describe to inspect the selected records"})
	}
	if namespaceSet {
		agent.RequireSSHSigNamespace(*namespace)
	}
	// The audit log opens before the socket exists: an unusable log leaves
	// no agent for any client to reach.
	if auditSet {
		log, err := keyvault.OpenSSHAuditLog(*auditPath)
		if err != nil {
			return out.fail(err)
		}
		defer log.Close()
		agent.AuditTo(log)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var until time.Time
	if unlockSet {
		until = time.Now().Add(*unlockFor)
		agent.ExpireAt(until)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, until)
		defer cancel()
	}
	// The unlock is granted before the socket exists: a refusal leaves no
	// socket for any client to reach.
	if confirmUnlock {
		if err := agent.ConfirmUnlock(ctx, hook, until); err != nil {
			return out.fail(&keyvault.Refusal{Code: keyvault.CodeConfirmationRequired, Message: "unlock was not confirmed", Hint: "the agent did not open its socket"})
		}
	}
	listener, cleanup, err := keyvault.ListenSSH(*socket)
	if err != nil {
		return out.fail(err)
	}
	defer cleanup()
	// Readiness is public metadata. Protocol traffic only uses the socket.
	if out.json {
		ready := map[string]any{"socket": *socket, "identities": len(addresses)}
		if unlockSet {
			ready["until"] = until.UTC().Format(time.RFC3339)
		}
		if namespaceSet {
			ready["sign_namespace"] = *namespace
		}
		if auditSet {
			ready["audit_log"] = *auditPath
		}
		out.success(ready, nil)
	} else {
		line := "SSH agent listening on " + *socket
		if unlockSet {
			line += " until " + until.UTC().Format(time.RFC3339)
		}
		if namespaceSet {
			line += "; signs only SSHSIG namespace " + *namespace
		}
		if auditSet {
			line += "; audit log " + *auditPath
		}
		fmt.Fprintln(out.stderr, line)
	}
	if err := agent.Serve(ctx, listener); err != nil {
		return out.fail(err)
	}
	return exitOK
}
