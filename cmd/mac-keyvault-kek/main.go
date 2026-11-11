// mac-keyvault-kek keeps a service's key-encryption key (KEK) wrapped to a
// non-extractable login-Keychain key and hands it back only to the code the
// wrapped envelope is bound to (KEK contract 1, pkg/kekclient).
//
// It is a separate binary from mac-keyvault: its key's ACL trusts only this
// binary, and building or installing it touches no existing Keychain item.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/kek"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

// Version is stamped into the records this tool creates.
const Version = "0.1.0"

// serveTimeout bounds the wait for the one connection and its request.
const serveTimeout = 10 * time.Second

const usage = `usage:
  mac-keyvault-kek create --address SERVICE/PURPOSE [--title T] [--not-after RFC3339]
  mac-keyvault-kek pub --address SERVICE/PURPOSE [--version N]
  mac-keyvault-kek unwrap --address SERVICE/PURPOSE --socket PATH
  mac-keyvault-kek rebind --address SERVICE/PURPOSE --socket PATH
  mac-keyvault-kek audit-verify
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// deps are what run needs from the host; tests replace them.
type deps struct {
	vault     func() (*keyvault.Manager, error)
	inspector kek.Inspector
	audit     func() (*kek.Audit, error)
	disableUI func() error
}

var host = deps{
	vault: func() (*keyvault.Manager, error) {
		lock, err := keyvault.DefaultFileLock()
		if err != nil {
			return nil, err
		}
		return keyvault.NewManager(keyvault.NewSecurityStore(), lock, origin()), nil
	},
	inspector: kek.CodeInspector{},
	audit: func() (*kek.Audit, error) {
		path, err := kek.DefaultAuditPath()
		return &kek.Audit{Path: path}, err
	},
	disableUI: keyvault.DisableKeychainUI,
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "create":
		err = runCreate(rest, stdout)
	case "pub":
		err = runPub(rest, stdout)
	case kekclient.OpUnwrap, kekclient.OpRebind:
		err = runServe(cmd, rest, stdout)
	case "audit-verify":
		err = runAuditVerify(rest, stdout)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	var u usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &u):
		fmt.Fprintf(stderr, "mac-keyvault-kek: %v\n%s", err, usage)
		return 2
	}
	fmt.Fprintf(stderr, "mac-keyvault-kek: %v\n", err)
	return 1
}

type usageError struct{ error }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

func parse(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if fs.NArg() != 0 {
		return usagef("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func address(text string) (keyvault.Address, error) {
	if !kekclient.ValidAddress(text) {
		return keyvault.Address{}, usagef("--address must be SERVICE/PURPOSE in lowercase keyvault names, not %q", text)
	}
	service, purpose, _ := strings.Cut(text, "/")
	return keyvault.Address{Kind: keyvault.KindKey, Service: service, Purpose: purpose}, nil
}

// keyView is what create and pub print: the public half and how to pin it.
type keyView struct {
	Address     string `json:"address"`
	Generation  int    `json:"generation"`
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	SPKI        string `json:"spki"`
	NotAfter    string `json:"not_after,omitempty"`
}

func view(k keyvault.Key) keyView {
	v := keyView{Address: k.Record.Service + "/" + k.Record.Purpose, Generation: k.Record.Version, Label: k.Label, Fingerprint: k.Fingerprint(), SPKI: base64.StdEncoding.EncodeToString(k.SPKI)}
	if na := k.Record.Validity.NotAfter; na != nil {
		v.NotAfter = na.UTC().Format(time.RFC3339)
	}
	return v
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runCreate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	addr := fs.String("address", "", "SERVICE/PURPOSE")
	title := fs.String("title", "", "short human name")
	notAfter := fs.String("not-after", "", "RFC3339 end of validity; unwrap refuses after it")
	if err := parse(fs, args); err != nil {
		return err
	}
	a, err := address(*addr)
	if err != nil {
		return err
	}
	spec := keyvault.InitSpec{
		Service: a.Service, Purpose: a.Purpose, Kind: keyvault.KindKey, Title: *title,
		Description: "KEK wrapping key; unwrapped only by mac-keyvault-kek for the bound caller",
		Algorithm:   keyvault.AlgorithmECP256, Store: keyvault.StoreKeychain, Extraction: keyvault.ExtractionNone,
		Usages: []string{"decrypt"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
	}
	if *notAfter != "" {
		t, err := time.Parse(time.RFC3339, *notAfter)
		if err != nil {
			return usagef("--not-after must be RFC3339: %v", err)
		}
		spec.NotAfter = &t
	}
	if err := host.disableUI(); err != nil {
		return err
	}
	m, err := host.vault()
	if err != nil {
		return err
	}
	key, err := m.Init(spec)
	if err != nil {
		return err
	}
	return printJSON(stdout, view(key))
}

func runPub(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pub", flag.ContinueOnError)
	addr := fs.String("address", "", "SERVICE/PURPOSE")
	version := fs.Int("version", 0, "generation; 0 is the newest")
	if err := parse(fs, args); err != nil {
		return err
	}
	a, err := address(*addr)
	if err != nil {
		return err
	}
	a.Version = *version
	if err := host.disableUI(); err != nil {
		return err
	}
	m, err := host.vault()
	if err != nil {
		return err
	}
	key, err := m.Describe(a)
	if err != nil {
		return err
	}
	if len(key.SPKI) == 0 {
		return fmt.Errorf("the public half of %s is unreadable", key.Label)
	}
	return printJSON(stdout, view(key))
}

func runServe(op string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	addr := fs.String("address", "", "SERVICE/PURPOSE")
	sock := fs.String("socket", "", "absolute path of a new socket in a private directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	if _, err := address(*addr); err != nil {
		return err
	}
	if err := checkSocketPath(*sock); err != nil {
		return usagef("%v", err)
	}
	if err := host.disableUI(); err != nil {
		return err
	}
	m, err := host.vault()
	if err != nil {
		return err
	}
	audit, err := host.audit()
	if err != nil {
		return err
	}
	l, err := listen(*sock)
	if err != nil {
		return err
	}
	defer os.Remove(*sock)
	defer l.Close()
	fmt.Fprintf(stdout, "listening %s\n", *sock)
	server := &kek.Server{Vault: m, Inspector: host.inspector, Audit: audit, Op: op, Address: *addr, Timeout: serveTimeout}
	if err := server.Serve(l); err != nil {
		return err
	}
	return nil
}

// checkSocketPath requires a clean absolute path that does not exist yet,
// short enough for a Unix socket, in a directory owned by this user with no
// group or other permissions.
func checkSocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("--socket %q is not a clean absolute path", path)
	}
	if len(path) >= 104 {
		return fmt.Errorf("--socket %q is too long for a Unix socket", path)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--socket %s already exists", path)
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a private directory of this user", dir)
	}
	return nil
}

func listen(path string) (*net.UnixListener, error) {
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

func runAuditVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	if err := parse(fs, args); err != nil {
		return err
	}
	audit, err := host.audit()
	if err != nil {
		return err
	}
	n, head, err := audit.Verify()
	if err != nil {
		return fmt.Errorf("audit log %s: %v", audit.Path, err)
	}
	fmt.Fprintf(stdout, "audit log %s: %d entries, chain intact, head %s\n", audit.Path, n, head)
	return nil
}

func origin() keyvault.Origin {
	o := keyvault.Origin{Tool: "mac-keyvault-kek/" + Version, User: keyvault.Unknown, Host: keyvault.Unknown}
	if current, err := user.Current(); err == nil && current.Username != "" {
		o.User = current.Username
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		o.Host = h
	}
	return o
}
