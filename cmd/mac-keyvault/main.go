// mac-keyvault manages non-extractable P-256 key pairs in the login keychain.
// Every item carries a schema-2 record (service, purpose, version, policy,
// meta) in its application tag and is addressed as <service>/<purpose>.
//
// Exit codes: 0 success, 1 operational failure (Security.framework error,
// unknown address, I/O, a signature that does not verify), 2 usage error,
// 3 policy refusal (invalid record, duplicate, missing --confirm, label
// outside the tool namespace, Secure Enclave or user-presence unavailable,
// unknown metadata on rotate, usage or validity gate on sign, a mis-sized
// digest or malformed signature, a high-S signature without --allow-high-s).
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitRefused = 3
)

// Production wiring; tests swap these for recording stores and a temp lock.
var (
	newBackend = func() keyvault.Backend {
		return keyvault.RoutedBackend{Keychain: keyvault.NewSecurityStore(), Enclave: describedEnclave(keyvault.DefaultEnclaveStore())}
	}
	vaultLock = keyvault.DefaultFileLock
	now       = time.Now
)

func main() {
	entered := time.Now()
	if rootQualificationChildAdmitted(recoveryQualificationOnly, os.Args[1:]) {
		os.Exit(rootQualificationChildProcess(entered))
	}
	if recoveryQualificationOnly == "" && rootQualificationParentInvocation(os.Args[1:]) {
		os.Exit(rootQualificationParentProcess(entered, os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// usageError is a command-line mistake: exit 2, no store call. Its hint is
// the exact usage line of the command.
type usageError struct {
	msg     string
	command string
}

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// usageLines are the per-command usage lines the error contract hands back
// as the hint of a usage error.
var usageLines = map[string]string{
	"nostr":          nostrUsage,
	"recovery":       recoveryUsage,
	"init":           "mac-keyvault [--json] init --service S --purpose P [--kind key] [--algorithm ec-p256] [--title T] [--description D] [--usages a,b] [--format-public F] [--format-signature F] [--format-envelope F] [--extraction none|human|agent] [--not-after RFC3339] [--meta k=v]... [--meta-json FILE] [--generate SPEC] [--keychain|--enclave] [--user-presence]",
	"list":           "mac-keyvault [--json] list [--service S] [--kind K]",
	"describe":       "mac-keyvault [--json] describe <service>/<purpose> [--kind K] [--version N]",
	"pub":            "mac-keyvault [--json] pub <service>/<purpose> [--kind K] [--version N] [--out FILE] [--format spki-der|spki-pem|jwk|ssh]",
	"sign":           "mac-keyvault [--json] sign <service>/<purpose> (--digest <hex|@file> | --data-file FILE | --stdin) [--raw | --format ecdsa-der-low-s|ecdsa-raw] [--out FILE] [--kind K] [--version N]",
	"verify":         "mac-keyvault [--json] verify (<service>/<purpose> [--kind K] [--version N] | --spki FILE) (--digest <hex|@file> | --data-file FILE | --stdin) --sig <hex|@file> [--raw] [--allow-high-s]",
	"rotate":         "mac-keyvault [--json] rotate <service>/<purpose> [--kind K]",
	"delete":         "mac-keyvault [--json] delete <service>/<purpose> --confirm [--kind K] [--version N]",
	"meta":           "mac-keyvault [--json] meta get|set|unset <service>/<purpose> [key] [value] [--kind K] [--version N] [--json-value]",
	"meta get":       "mac-keyvault [--json] meta get <service>/<purpose> [key] [--kind K] [--version N]",
	"meta set":       "mac-keyvault [--json] meta set <service>/<purpose> <key> <value> [--json-value] [--kind K] [--version N]",
	"meta unset":     "mac-keyvault [--json] meta unset <service>/<purpose> <key> [--kind K] [--version N]",
	"signer":         "mac-keyvault signer serve --address <service>/<purpose> [--kind K] [--version N]",
	"signer serve":   "mac-keyvault signer serve --address <service>/<purpose> [--kind K] [--version N]",
	"ssh-agent":      "mac-keyvault ssh-agent --socket PATH --key service/purpose@VERSION [--key ...] [--confirm-exec /absolute/executable] [--confirm-arg ARG] [--confirm-timeout 15s] [--confirm-when sign|unlock|both] [--unlock-for DURATION]",
	"confirm-dialog": "mac-keyvault confirm-dialog [--wait 12s]   (ssh-agent confirmation hook: one request on stdin, exit 0 only on the grant button)",
	"version":        "mac-keyvault [--json] version",
}

// response is the JSON envelope every command emits in --json mode.
type response struct {
	OK      bool           `json:"ok"`
	Command string         `json:"command"`
	Result  any            `json:"result,omitempty"`
	Error   *responseError `json:"error,omitempty"`
}

// responseError is the error contract (model §8): stable code, message in
// the caller's terms, a hint that says what to do next, os_status when
// Security.framework produced the failure.
type responseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
	Status  int    `json:"os_status,omitempty"`
}

type output struct {
	command string
	json    bool
	stdout  io.Writer
	stderr  io.Writer
}

func (o output) success(result any, text func(io.Writer)) int {
	if o.json {
		encodeJSON(o.stdout, response{OK: true, Command: o.command, Result: result})
		return exitOK
	}
	text(o.stdout)
	return exitOK
}

// fail routes every failure, usage errors included, through the JSON
// emitter when --json was given (review F3); text mode writes
// "error: <code>: <message>" and "hint: <hint>" to stderr.
func (o output) fail(err error) int {
	code, respErr := o.classify(err)
	if o.json {
		encodeJSON(o.stdout, response{OK: false, Command: o.command, Error: respErr})
		return code
	}
	fmt.Fprintf(o.stderr, "error: %s: %s\n", respErr.Code, respErr.Message)
	if respErr.Status != 0 {
		fmt.Fprintf(o.stderr, "os_status: %d (%s)\n", respErr.Status, keyvault.OSStatusName(respErr.Status))
	}
	fmt.Fprintf(o.stderr, "hint: %s\n", respErr.Hint)
	return code
}

// failWith is fail with a result attached: a verify verdict of false is an
// error by the contract (exit 1 or 3, code, message, hint) and also carries
// the verdict fields so a consumer sees what was judged.
func (o output) failWith(result any, err error) int {
	code, respErr := o.classify(err)
	if o.json {
		encodeJSON(o.stdout, response{OK: false, Command: o.command, Result: result, Error: respErr})
		return code
	}
	fmt.Fprintln(o.stdout, "verified: false")
	fmt.Fprintf(o.stderr, "error: %s: %s\n", respErr.Code, respErr.Message)
	fmt.Fprintf(o.stderr, "hint: %s\n", respErr.Hint)
	return code
}

func (o output) classify(err error) (int, *responseError) {
	var usage *usageError
	if errors.As(err, &usage) {
		hint := usageLines[o.command]
		if hint == "" {
			hint = usageLines[strings.SplitN(o.command, " ", 2)[0]]
		}
		if hint == "" {
			hint = "mac-keyvault help lists the commands: recovery, nostr, init, list, describe, pub, sign, verify, rotate, delete, meta, signer, version"
		}
		return exitUsage, &responseError{Code: keyvault.CodeUsage, Message: usage.msg, Hint: hint}
	}
	return exitCodeOf(err), contractError(err)
}

// exitCodeOf maps a non-usage error to its exit class: 1 for the
// operational failures, 3 for policy refusals.
func exitCodeOf(err error) int {
	if keyvault.ClassifyError(err).Failure {
		return exitFailure
	}
	return exitRefused
}

func contractError(err error) *responseError {
	c := keyvault.ClassifyError(err)
	return &responseError{Code: c.Code, Message: c.Message, Hint: c.Hint, Status: c.Status}
}

func encodeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// wantsJSON decides the output mode before any command parsing can fail.
// It is not string matching (review F3/F6/F9): every token is offered on
// its own to a flag.FlagSet that defines only the json bool, so the set of
// spellings that select the envelope is, by construction, exactly the set
// flag.Bool accepts (--json, -json, --json=true, --json=1, --json=T,
// -json=TRUE, ...) and a later --json=false wins over an earlier --json,
// as it does in the command parser. Tokens the pre-parser does not know
// (every other flag, positionals, --) are ignored here and judged by the
// command parser later.
func wantsJSON(args []string) bool {
	jsonMode := false
	for _, arg := range args {
		if arg == "--" {
			break // flag terminator: what follows is positional for the command parser too
		}
		if value, ok := jsonToken(arg); ok {
			jsonMode = value
		}
	}
	return jsonMode
}

// jsonToken parses one token with the json-only pre-parser; ok is false
// for anything that is not a json flag spelling flag.Bool would accept.
func jsonToken(arg string) (value bool, ok bool) {
	fs := flag.NewFlagSet("json-mode", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.Bool("json", false, "")
	if err := fs.Parse([]string{arg}); err != nil || fs.NFlag() != 1 {
		return false, false
	}
	return *mode, true
}

// Only the separately signed public-qualification asset sets this linker
// pin. It cannot create, delete, restore or display any seed.
var recoveryQualificationOnly string

func qualificationInvocation(args []string) bool {
	if rootQualificationChildInvocation(args) {
		return true
	}
	return len(args) == 8 && args[0] == "--json" && args[1] == "nostr" && args[2] == "sign" &&
		strings.HasSuffix(args[3], "/nostr") && args[4] == "--version" && args[5] == "1" &&
		args[6] == "--digest" && args[7] == strings.Repeat("0", 64)
}

func run(args []string, stdout, stderr io.Writer) int {
	if recoveryQualificationOnly != "" && (recoveryQualificationOnly != "1" || !qualificationInvocation(args)) {
		return (output{command: "nostr", json: wantsJSON(args), stdout: stdout, stderr: stderr}).fail(usagef("public qualification executable admits only its fixed digest check"))
	}

	if rootQualificationChildInvocation(args) {
		return runRootQualificationChild(stdout)
	}
	// Owning native work requires actual main's original process deadline.
	// In-process dispatch cannot silently become an untimed native operation.
	if rootQualificationParentInvocation(args) {
		return writeRootQualificationParent(stdout, args[4], "unqualified", "", exitRefused)
	}

	jsonMode := wantsJSON(args)
	for len(args) > 0 {
		if _, ok := jsonToken(args[0]); !ok {
			break
		}
		args = args[1:]
	}
	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	out := output{command: command, json: jsonMode, stdout: stdout, stderr: stderr}
	if command == "" {
		return out.fail(usagef("a command is required"))
	}
	rest := args[1:]
	switch command {
	case "recovery":
		return runRecovery(rest, out)
	case "nostr":
		return runNostr(rest, out)
	case "init":
		return runInit(rest, out)
	case "list":
		return runList(rest, out)
	case "describe":
		return runDescribe(rest, out)
	case "pub":
		return runPub(rest, out)
	case "sign":
		return runSign(rest, out)
	case "verify":
		return runVerify(rest, out)
	case "rotate":
		return runRotate(rest, out)
	case "delete":
		return runDelete(rest, out)
	case "meta":
		return runMeta(rest, out)
	case "ssh-agent":
		return runSSHAgent(rest, out)
	case "confirm-dialog":
		return runConfirmDialog(rest, out)
	case "signer":
		return runSigner(rest, out)
	case "version":
		return runVersion(rest, out)
	case "help", "--help", "-h":
		// help takes nothing; extra input is the same usage class as
		// everywhere else (review F6), so it is refused before printing.
		if err := requireNoArguments(command, rest); err != nil {
			return out.fail(err)
		}
		printUsage(stdout)
		return exitOK
	default:
		return out.fail(usagef("unknown command %q", command))
	}
}

// runVersion goes through the same flag parser as every other command so
// that a stray positional or unknown flag is a usage error (envelope, exit 2)
// instead of being ignored (review F6, repeat of F3).
func runVersion(args []string, out output) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	if err := requireNoArguments("version", positional); err != nil {
		return out.fail(err)
	}
	return out.success(map[string]string{"version": Version, "commit": Commit, "build_date": BuildDate}, func(w io.Writer) {
		fmt.Fprintf(w, "mac-keyvault %s %s %s\n", Version, Commit, BuildDate)
	})
}

// requireNoArguments refuses any leftover input for a command that takes none.
func requireNoArguments(command string, rest []string) error {
	if len(rest) != 0 {
		return usagef("%s takes no arguments (got %q)", command, rest[0])
	}
	return nil
}

func newManager() (*keyvault.Manager, error) {
	lock, err := vaultLock()
	if err != nil {
		return nil, fmt.Errorf("lock path: %w", err)
	}
	manager := keyvault.NewManager(newBackend(), lock, localOrigin())
	// One clock for created stamps, the validity gate of sign and the
	// operations describe prints.
	manager.SetClock(now)
	return manager, nil
}

func localOrigin() keyvault.Origin {
	// user and host are always present (the record invariant requires
	// them); a failed lookup is recorded as unknown, never as an empty
	// string that reads like an absent field.
	origin := keyvault.Origin{Tool: "mac-keyvault/" + Version, User: keyvault.Unknown, Host: keyvault.Unknown}
	if current, err := user.Current(); err == nil && current.Username != "" {
		origin.User = current.Username
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		origin.Host = host
	}
	return origin
}

// parseFlags parses flags interspersed with positionals
// (mac-keyvault delete ADDR --confirm) and turns parser output into a usage
// error instead of writing to stderr.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var sink strings.Builder
	fs.SetOutput(&sink)
	fs.Bool("json", false, "emit a JSON envelope on stdout")
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, usagef("%s", strings.TrimSpace(sink.String()))
			}
			return nil, usagef("%s", strings.TrimSpace(strings.SplitN(sink.String(), "\n", 2)[0]))
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if terminated := len(args) - len(rest) - 1; terminated >= 0 && args[terminated] == "--" {
			// "--" ends flag parsing for good; nothing after it is re-parsed.
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// addressFlags adds --kind and --version to a command that names one item.
func addressFlags(fs *flag.FlagSet) (kind *string, version *int) {
	kind = fs.String("kind", keyvault.KindKey, "record kind: key, public-key, certificate or secret")
	version = fs.Int("version", 0, "one generation; 0 selects the newest")
	return kind, version
}

func singleAddress(fs *flag.FlagSet, positional []string, kind string, version int) (keyvault.Address, error) {
	if len(positional) != 1 {
		return keyvault.Address{}, usagef("%s requires exactly one <service>/<purpose> address", fs.Name())
	}
	return keyvault.ParseAddress(positional[0], kind, version)
}

// keyView is the flat JSON a read command prints: the record plus derived
// label, fingerprint, operations and findings (keyvault.Key.View, shared
// with the signer contract's describe).
func keyView(key keyvault.Key) map[string]any {
	return key.View(now())
}

func orUnknown(value string) string {
	if value == "" {
		return keyvault.Unknown
	}
	return value
}

func createdText(key keyvault.Key) string {
	if key.Record.Created.IsZero() {
		return keyvault.Unknown
	}
	return key.Record.Created.UTC().Format(time.RFC3339)
}

type metaFlags struct {
	pairs []string
}

func (m *metaFlags) String() string     { return strings.Join(m.pairs, ",") }
func (m *metaFlags) Set(v string) error { m.pairs = append(m.pairs, v); return nil }

func runInit(args []string, out output) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	service := fs.String("service", "", "consumer of the key (kvctl, build-ci, agent)")
	purpose := fs.String("purpose", "", "role of the key (pki-root, attest)")
	kind := fs.String("kind", keyvault.KindKey, "record kind; only key is created in this revision")
	title := fs.String("title", "", "short human name, at most 80 characters")
	description := fs.String("description", "", "free text shown by describe and list --json")
	algorithm := fs.String("algorithm", keyvault.AlgorithmECP256, "ec-p256 (ec-p384, rsa-3072 reserved; ed25519 refused)")
	usages := fs.String("usages", "sign,verify", "comma-separated subset of "+strings.Join(keyvault.Usages, ","))
	formatPublic := fs.String("format-public", keyvault.FormatPublicSPKIDER, "default public representation: spki-der, spki-pem or jwk")
	formatSignature := fs.String("format-signature", keyvault.FormatSignatureDERLowS, "default signature representation: ecdsa-der-low-s or ecdsa-raw")
	formatEnvelope := fs.String("format-envelope", "", "default envelope representation for kind secret: json or der")
	extraction := fs.String("extraction", keyvault.ExtractionNone, "none, human or agent; typed literally, never a default")
	generate := fs.String("generate", "", "kind secret only: token:N | password:N[:charset] | bytes:N")
	notAfter := fs.String("not-after", "", "RFC3339 validity end; sign refuses after it")
	var meta metaFlags
	fs.Var(&meta, "meta", "k=v string entry; repeatable")
	metaJSON := fs.String("meta-json", "", "JSON object file with string, number and bool values")
	enclave := fs.Bool("enclave", false, "create the pair in the Secure Enclave (CryptoKit blob, needs mac-keyvault-enclave; never falls back to the keychain)")
	keychain := fs.Bool("keychain", false, "store the pair in the login keychain (default)")
	userPresence := fs.Bool("user-presence", false, "with --enclave: Touch ID or the login password for every signature; on the keychain store it refuses with -34018 on an unprovisioned binary")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	switch {
	case len(positional) != 0:
		return out.fail(usagef("init takes no positional arguments; use --service and --purpose (got %q)", positional[0]))
	case *enclave && *keychain:
		return out.fail(usagef("init accepts either --enclave or --keychain, not both"))
	case *service == "" || *purpose == "":
		return out.fail(usagef("init requires --service and --purpose"))
	}
	spec := keyvault.InitSpec{
		Service: *service, Purpose: *purpose, Kind: *kind, Title: *title, Description: *description,
		Algorithm: *algorithm, Store: keyvault.StoreKeychain, UserPresence: *userPresence, Extraction: *extraction,
		Usages: splitList(*usages), Format: keyvault.Format{Public: *formatPublic, Signature: *formatSignature, Envelope: *formatEnvelope},
		Generate: *generate,
	}
	if *enclave {
		spec.Store = keyvault.StoreEnclave
	}
	if *notAfter != "" {
		parsed, err := time.Parse(time.RFC3339, *notAfter)
		if err != nil {
			return out.fail(usagef("--not-after must be RFC3339: %v", err))
		}
		spec.NotAfter = &parsed
	}
	spec.Meta, err = collectMeta(meta.pairs, *metaJSON)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	key, err := manager.Init(spec)
	if err != nil {
		return out.fail(err)
	}
	return out.success(keyView(key), func(w io.Writer) {
		fmt.Fprintf(w, "created %s label=%s store=%s created=%s fingerprint=%s\n", key.Record.Address(), key.Label, key.Record.Store, createdText(key), key.Fingerprint())
	})
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// collectMeta merges --meta k=v pairs and a --meta-json file. Shapes the
// parser cannot read are usage errors; reserved names and bad value types
// are refused by the record validation.
func collectMeta(pairs []string, jsonPath string) (map[string]any, error) {
	meta := map[string]any{}
	if jsonPath != "" {
		data, err := os.ReadFile(jsonPath)
		if err != nil {
			return nil, usagef("--meta-json: %v", err)
		}
		if err := keyvault.DecodeSingleJSON(data, &meta); err != nil {
			return nil, usagef("--meta-json %s is not a single JSON object: %v", jsonPath, err)
		}
		if meta == nil {
			meta = map[string]any{}
		}
	}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || name == "" {
			return nil, usagef("--meta expects k=v, got %q", pair)
		}
		if _, exists := meta[name]; exists {
			return nil, usagef("meta %q is given twice", name)
		}
		meta[name] = value
	}
	return meta, nil
}

func runList(args []string, out output) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	service := fs.String("service", "", "only records of this service")
	kind := fs.String("kind", "", "only records of this kind")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	if len(positional) != 0 {
		return out.fail(usagef("list takes no positional arguments"))
	}
	if *service != "" {
		if err := keyvault.ValidateName("service", keyvault.CodeInvalidService, *service); err != nil {
			return out.fail(err)
		}
	}
	if *kind != "" {
		// Same closed vocabulary as the address parser, judged before the
		// manager exists (review F10).
		if err := keyvault.ValidateKind(*kind); err != nil {
			return out.fail(err)
		}
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	keys, err := manager.List(*service, *kind)
	if err != nil {
		return out.fail(err)
	}
	views := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		views = append(views, keyView(key))
	}
	return out.success(views, func(w io.Writer) {
		if len(keys) == 0 {
			fmt.Fprintln(w, "no keys under "+keyvault.LabelPrefix)
			return
		}
		for _, key := range keys {
			rec := key.Record
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", key.Label, orUnknown(rec.Kind), orUnknown(rec.Algorithm), orUnknown(string(rec.Store)), orUnknown(rec.Extraction),
				orUnknown(strings.Join(rec.SortedUsages(), ",")), createdText(key), orUnknown(key.Fingerprint()), rec.Title)
		}
	})
}

func runDescribe(args []string, out output) int {
	fs := flag.NewFlagSet("describe", flag.ContinueOnError)
	kind, version := addressFlags(fs)
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	addr, err := singleAddress(fs, positional, *kind, *version)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	key, err := manager.Describe(addr)
	if err != nil {
		return out.fail(err)
	}
	view := keyView(key)
	return out.success(view, func(w io.Writer) { encodeJSON(w, view) })
}

func runPub(args []string, out output) int {
	fs := flag.NewFlagSet("pub", flag.ContinueOnError)
	kind, version := addressFlags(fs)
	outPath := fs.String("out", "", "write the public key to PATH (.pem for PEM, .jwk/.json for JWK, anything else for SPKI DER)")
	format := fs.String("format", "", "spki-der, spki-pem or jwk; default is inferred from --out, else the record's format.public")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	addr, err := singleAddress(fs, positional, *kind, *version)
	if err != nil {
		return out.fail(err)
	}
	if *format != "" && *format != keyvault.FormatPublicSPKIDER && *format != keyvault.FormatPublicSPKIPEM && *format != keyvault.FormatPublicJWK && *format != "ssh" {
		return out.fail(usagef("--format must be spki-der, spki-pem, jwk or ssh, got %q", *format))
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	key, err := manager.Describe(addr)
	if err != nil {
		return out.fail(err)
	}
	if len(key.SPKI) == 0 {
		return out.fail(fmt.Errorf("public key of %s is unreadable; fingerprint unknown", key.Label))
	}
	encoding := resolveFormat(*format, *outPath, key.Record.Format.Public)
	payload, err := encodePublic(key.SPKI, encoding)
	if err != nil {
		return out.fail(err)
	}
	result := keyView(key)
	result["format"] = encoding
	if *outPath != "" {
		if err := writeOutFile(*outPath, payload); err != nil {
			return out.fail(err)
		}
		result["out"] = *outPath
		return out.success(result, func(w io.Writer) {
			fmt.Fprintf(w, "wrote %s %s to %s fingerprint=%s\n", key.Label, encoding, *outPath, key.Fingerprint())
		})
	}
	if !out.json {
		_, err := out.stdout.Write(payload)
		if err != nil {
			return out.fail(err)
		}
		return exitOK
	}
	switch encoding {
	case "ssh":
		result["ssh"] = string(payload)
	case keyvault.FormatPublicSPKIDER:
		result["der_base64"] = base64.StdEncoding.EncodeToString(payload)
	case keyvault.FormatPublicJWK:
		var jwk map[string]string
		_ = json.Unmarshal(payload, &jwk)
		result["jwk"] = jwk
	default:
		result["pem"] = string(payload)
	}
	return out.success(result, nil)
}

// resolveFormat picks the output representation: explicit --format, then
// the --out extension, then the record's own format.public.
func resolveFormat(format, outPath, recordDefault string) string {
	if format != "" {
		return format
	}
	switch strings.ToLower(filepath.Ext(outPath)) {
	case ".pem":
		return keyvault.FormatPublicSPKIPEM
	case ".jwk", ".json":
		return keyvault.FormatPublicJWK
	case ".der":
		return keyvault.FormatPublicSPKIDER
	}
	switch recordDefault {
	case keyvault.FormatPublicSPKIPEM, keyvault.FormatPublicJWK:
		return recordDefault
	default:
		return keyvault.FormatPublicSPKIDER
	}
}

func encodePublic(spki []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "ssh":
		return keyvault.SSHPublicKey(spki)
	case keyvault.FormatPublicSPKIPEM:
		return keyvault.EncodePEM(spki), nil
	case keyvault.FormatPublicJWK:
		return keyvault.EncodeJWK(spki)
	default:
		return spki, nil
	}
}

// digestFlags are the three ways a command takes its SHA-256 digest:
// --digest (the caller hashed; the tool signs exactly those 32 bytes),
// --data-file or --stdin (the tool hashes with SHA-256 and says so in the
// output). Exactly one must be given.
type digestFlags struct {
	digest, dataFile *string
	stdin            *bool
}

func addDigestFlags(fs *flag.FlagSet) digestFlags {
	return digestFlags{
		digest:   fs.String("digest", "", "SHA-256 digest to sign/verify: 64 hex chars, or @FILE holding the 32 raw bytes"),
		dataFile: fs.String("data-file", "", "hash FILE with SHA-256 and use that digest"),
		stdin:    fs.Bool("stdin", false, "hash stdin with SHA-256 and use that digest"),
	}
}

// stdinReader is swapped by tests.
var stdinReader io.Reader = os.Stdin

// resolve returns the digest bytes and the source name (digest, file,
// stdin). Length is judged by keyvault.ValidateDigest so a mis-sized
// caller digest is refused with invalid_digest before any store exists.
func (d digestFlags) resolve() ([]byte, string, error) {
	digest, _, source, err := d.resolveData()
	return digest, source, err
}

// writeOutFile creates path for --out as a new 0600 file: it never follows
// or replaces an existing entry (a symlink planted while a presence prompt
// waits would otherwise redirect the write), and a failed write leaves
// nothing behind.
func writeOutFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return usagef("--out %s already exists; choose a new path", path)
		}
		return fmt.Errorf("--out: %w", err)
	}
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("--out: %w", err)
	}
	return nil
}

// resolveData also returns the hashed data (nil for --digest), which sign
// uses to word the presence prompt.
func (d digestFlags) resolveData() ([]byte, []byte, string, error) {
	given := 0
	for _, set := range []bool{*d.digest != "", *d.dataFile != "", *d.stdin} {
		if set {
			given++
		}
	}
	if given != 1 {
		return nil, nil, "", usagef("exactly one of --digest, --data-file or --stdin is required")
	}
	switch {
	case *d.digest != "":
		digest, err := bytesArg("--digest", *d.digest)
		if err != nil {
			return nil, nil, "", err
		}
		if err := keyvault.ValidateDigest(digest); err != nil {
			return nil, nil, "", err
		}
		return digest, nil, "digest", nil
	case *d.dataFile != "":
		data, err := os.ReadFile(*d.dataFile)
		if err != nil {
			return nil, nil, "", usagef("--data-file: %v", err)
		}
		sum := sha256.Sum256(data)
		return sum[:], data, "file", nil
	default:
		data, err := io.ReadAll(stdinReader)
		if err != nil {
			return nil, nil, "", fmt.Errorf("stdin: %w", err)
		}
		sum := sha256.Sum256(data)
		return sum[:], data, "stdin", nil
	}
}

// bytesArg decodes a hex string, or the raw bytes of @FILE (files are never
// hex-decoded, so a raw digest that happens to look like hex is not
// misread). A value the parser cannot read is a usage error.
func bytesArg(flagName, value string) ([]byte, error) {
	if strings.HasPrefix(value, "@") {
		data, err := os.ReadFile(value[1:])
		if err != nil {
			return nil, usagef("%s: %v", flagName, err)
		}
		return data, nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, usagef("%s must be hex or @FILE: %v", flagName, err)
	}
	return decoded, nil
}

// signatureFormat resolves --raw / --format against the record default.
func signatureFormat(raw bool, format, recordDefault string) (string, error) {
	switch {
	case raw && format != "" && format != keyvault.FormatSignatureRaw:
		return "", usagef("--raw contradicts --format %s", format)
	case raw:
		return keyvault.FormatSignatureRaw, nil
	case format == keyvault.FormatSignatureDERLowS || format == keyvault.FormatSignatureRaw:
		return format, nil
	case format != "":
		return "", usagef("--format must be %s or %s, got %q", keyvault.FormatSignatureDERLowS, keyvault.FormatSignatureRaw, format)
	case recordDefault == keyvault.FormatSignatureRaw:
		return recordDefault, nil
	default:
		return keyvault.FormatSignatureDERLowS, nil
	}
}

func runSign(args []string, out output) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	kind, version := addressFlags(fs)
	digestIn := addDigestFlags(fs)
	raw := fs.Bool("raw", false, "emit raw r||s (64 bytes) instead of DER")
	format := fs.String("format", "", "ecdsa-der-low-s or ecdsa-raw; default is the record's format.signature")
	outPath := fs.String("out", "", "write the signature bytes to PATH")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	// Gates before the store exists: flag shape, digest length, address.
	if _, err := signatureFormat(*raw, *format, ""); err != nil {
		return out.fail(err)
	}
	digest, data, source, err := digestIn.resolveData()
	if err != nil {
		return out.fail(err)
	}
	addr, err := singleAddress(fs, positional, *kind, *version)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	if data != nil {
		signDescription = describeData(data)
		defer func() { signDescription = nil }()
	}
	signed, err := manager.Sign(addr, digest)
	if err != nil {
		return out.fail(err)
	}
	encoding, _ := signatureFormat(*raw, *format, signed.Key.Record.Format.Signature)
	payload, err := signed.Signature.Encode(encoding)
	if err != nil {
		return out.fail(err)
	}
	result := keyView(signed.Key)
	result["hash"] = "sha256"
	result["digest"] = hex.EncodeToString(digest)
	result["digest_source"] = source
	result["format"] = encoding
	result["signature"] = hex.EncodeToString(payload)
	result["signature_base64"] = base64.StdEncoding.EncodeToString(payload)
	result["low_s"] = true
	result["normalized"] = signed.Normalized
	if *outPath != "" {
		if err := writeOutFile(*outPath, payload); err != nil {
			return out.fail(err)
		}
		result["out"] = *outPath
		return out.success(result, func(w io.Writer) {
			fmt.Fprintf(w, "signed sha256 %s with %s: wrote %s (%d bytes) to %s\n", hex.EncodeToString(digest), signed.Key.Label, encoding, len(payload), *outPath)
		})
	}
	return out.success(result, func(w io.Writer) { fmt.Fprintln(w, hex.EncodeToString(payload)) })
}

func runVerify(args []string, out output) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	kind, version := addressFlags(fs)
	digestIn := addDigestFlags(fs)
	spkiPath := fs.String("spki", "", "verify under this SPKI DER or PEM file instead of a vault address")
	sigIn := fs.String("sig", "", "signature: hex, or @FILE with the raw bytes")
	raw := fs.Bool("raw", false, "the signature is raw r||s (64 bytes), not DER")
	allowHighS := fs.Bool("allow-high-s", false, "accept a signature whose s is in the high half (malleable form)")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	switch {
	case *spkiPath != "" && len(positional) != 0:
		return out.fail(usagef("verify takes either a <service>/<purpose> address or --spki FILE, not both"))
	case *spkiPath == "" && len(positional) != 1:
		return out.fail(usagef("verify requires a <service>/<purpose> address or --spki FILE"))
	case *sigIn == "":
		return out.fail(usagef("verify requires --sig <hex|@file>"))
	}
	digest, source, err := digestIn.resolve()
	if err != nil {
		return out.fail(err)
	}
	encoding := keyvault.FormatSignatureDERLowS
	if *raw {
		encoding = keyvault.FormatSignatureRaw
	}
	sigBytes, err := bytesArg("--sig", *sigIn)
	if err != nil {
		return out.fail(err)
	}
	sig, err := keyvault.ParseSignature(sigBytes, encoding)
	if err != nil {
		return out.fail(err)
	}
	// The high-S policy is judged on the signature bytes alone, so it is
	// refused here, before the SPKI file is read and before the vault is
	// listed: a malleable signature never causes a Security call (rev1 F2).
	inputs := map[string]any{"hash": "sha256", "digest": hex.EncodeToString(digest), "digest_source": source, "format": encoding, "low_s": sig.IsLowS(), "high_s_allowed": *allowHighS}
	if !sig.IsLowS() && !*allowHighS {
		inputs["verified"] = false
		return out.failWith(inputs, &keyvault.Refusal{Code: keyvault.CodeHighSRefused, Message: "signature s is in the high half of the P-256 order (malleable form); the vault only accepts low-S signatures", Hint: "signatures made by mac-keyvault sign are always low-S; pass --allow-high-s to accept this one knowingly"})
	}
	// The public key: from the file, or from the vault after the record
	// gate (readable record, registry row, readable public half).
	var spki []byte
	result := map[string]any{}
	if *spkiPath != "" {
		data, err := os.ReadFile(*spkiPath)
		if err != nil {
			return out.fail(usagef("--spki: %v", err))
		}
		der, _, err := keyvault.ParseSPKI(data)
		if err != nil {
			return out.fail(err)
		}
		spki = der
		result["by"] = "spki"
		result["spki"] = *spkiPath
		result["fingerprint"] = keyvault.Key{SPKI: der}.Fingerprint()
	} else {
		addr, err := singleAddress(fs, positional, *kind, *version)
		if err != nil {
			return out.fail(err)
		}
		manager, err := newManager()
		if err != nil {
			return out.fail(err)
		}
		key, err := manager.PublicKeyFor(addr)
		if err != nil {
			return out.fail(err)
		}
		spki = key.SPKI
		result = keyView(key)
		result["by"] = "label"
	}
	for k, v := range inputs {
		result[k] = v
	}
	verified, err := keyvault.VerifyDigest(spki, digest, sig)
	if err != nil {
		return out.fail(err)
	}
	result["verified"] = verified
	if !verified {
		return out.failWith(result, &keyvault.Refusal{Code: keyvault.CodeSignatureInvalid, Failure: true, Message: "signature does not verify over the digest under this public key", Hint: "the digest, the signature or the key is not the one that was signed; verdict false"})
	}
	return out.success(result, func(w io.Writer) { fmt.Fprintln(w, "verified: true") })
}

func runRotate(args []string, out output) int {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	kind := fs.String("kind", keyvault.KindKey, "record kind: key, public-key, certificate or secret")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	addr, err := singleAddress(fs, positional, *kind, 0)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	rotated, err := manager.Rotate(addr)
	if err != nil {
		return out.fail(err)
	}
	result := map[string]any{"old": keyView(rotated.Old), "new": keyView(rotated.New)}
	return out.success(result, func(w io.Writer) {
		fmt.Fprintf(w, "rotated %s -> %s fingerprint=%s (old key kept until deleted)\n", rotated.Old.Label, rotated.New.Label, rotated.New.Fingerprint())
	})
}

func runDelete(args []string, out output) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	kind, version := addressFlags(fs)
	confirm := fs.Bool("confirm", false, "acknowledge that the private key is destroyed irreversibly")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	addr, err := singleAddress(fs, positional, *kind, *version)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	label, err := manager.Delete(addr, *confirm)
	if err != nil {
		return out.fail(err)
	}
	result := map[string]any{"label": label, "deleted": true}
	return out.success(result, func(w io.Writer) { fmt.Fprintf(w, "deleted %s\n", label) })
}

func runMeta(args []string, out output) int {
	if len(args) == 0 {
		return out.fail(usagef("meta requires get, set or unset"))
	}
	sub, rest := args[0], args[1:]
	out.command = "meta " + sub
	fs := flag.NewFlagSet("meta "+sub, flag.ContinueOnError)
	kind, version := addressFlags(fs)
	jsonValue := fs.Bool("json-value", false, "set: parse VALUE as JSON (number or bool) instead of a string")
	positional, err := parseFlags(fs, rest)
	if err != nil {
		return out.fail(err)
	}
	want := map[string]int{"get": 1, "set": 3, "unset": 2}[sub]
	if want == 0 {
		return out.fail(usagef("unknown meta command %q; use get, set or unset", sub))
	}
	if sub == "get" && len(positional) == 2 {
		want = 2
	}
	if len(positional) != want {
		return out.fail(usagef("meta %s takes %s", sub, map[string]string{"get": "<service>/<purpose> [key]", "set": "<service>/<purpose> <key> <value>", "unset": "<service>/<purpose> <key>"}[sub]))
	}
	addr, err := keyvault.ParseAddress(positional[0], *kind, *version)
	if err != nil {
		return out.fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return out.fail(err)
	}
	switch sub {
	case "get":
		key, err := manager.Describe(addr)
		if err != nil {
			return out.fail(err)
		}
		if len(positional) == 2 {
			value, ok := key.Record.Meta[positional[1]]
			if !ok {
				return out.fail(&keyvault.MetaNotFoundError{Name: positional[1], Label: key.Label})
			}
			return out.success(map[string]any{"label": key.Label, "name": positional[1], "value": value}, func(w io.Writer) { fmt.Fprintf(w, "%v\n", value) })
		}
		return out.success(map[string]any{"label": key.Label, "meta": key.Record.Meta}, func(w io.Writer) { encodeJSON(w, key.Record.Meta) })
	case "set":
		var value any = positional[2]
		if *jsonValue {
			// A number stays a json.Number: the digits the caller typed are
			// what the record carries and what describe prints (review F11).
			if err := keyvault.DecodeSingleJSON([]byte(positional[2]), &value); err != nil {
				return out.fail(usagef("--json-value: %v", err))
			}
		}
		key, err := manager.MetaSet(addr, positional[1], value)
		if err != nil {
			return out.fail(err)
		}
		return out.success(map[string]any{"label": key.Label, "meta": key.Record.Meta}, func(w io.Writer) { fmt.Fprintf(w, "set %s on %s\n", positional[1], key.Label) })
	default:
		key, err := manager.MetaUnset(addr, positional[1])
		if err != nil {
			return out.fail(err)
		}
		return out.success(map[string]any{"label": key.Label, "meta": key.Record.Meta}, func(w io.Writer) { fmt.Fprintf(w, "unset %s on %s\n", positional[1], key.Label) })
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `mac-keyvault manages non-extractable P-256 key pairs in the login keychain.
Items are records addressed as <service>/<purpose> (+ --kind, default key; + --version N, default newest);
the label %s<kind>.<service>.<purpose>.v<N> is derived by the vault and never typed.

Usage:
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s
  %s

sign takes a SHA-256 digest (--digest) or hashes --data-file/--stdin itself and says so;
it emits strict DER with low-S (or --raw r||s). verify judges the digest, the signature
and a key (vault address or --spki FILE): exit 0 verified, 1 not, 3 high-S refused.
Raw labels are refused as foreign_label. --enclave creates the pair in the Secure
Enclave through the mac-keyvault-enclave helper and keeps its device-bound blob under
~/Library/Application Support/mac-infra/keyvault/enclave; with --user-presence every
signature asks for Touch ID or the login password (macOS .userPresence; the key
survives fingerprint changes). The prompt names what is signed: sign shows
the sha256 prefix, or the action and package digest prefix of a vpn-core
authorization statement. --user-presence on the keychain store
fails with missing_entitlement (OSStatus -34018) on a binary without a provisioning
profile. There is never a fallback between stores. --extraction agent must be typed literally.
signer serve binds one address and speaks JSON lines (contract 1) on stdin/stdout for a
consumer such as kvctl: hello line, then {id, op: describe|pub|sign|verify, ...} ->
{id, ok, result|error}; errors never end the stream, EOF exits 0.

Exit codes: 0 ok, 1 failure, 2 usage, 3 refused by a policy gate. Every error is
{code, message, hint, os_status}; text mode prints "error: <code>: <message>" and "hint: <hint>".
`, keyvault.LabelPrefix, usageLines["recovery"], usageLines["nostr"], usageLines["init"], usageLines["list"], usageLines["describe"], usageLines["pub"], usageLines["sign"], usageLines["verify"], usageLines["rotate"], usageLines["delete"], usageLines["meta"], usageLines["signer"], usageLines["ssh-agent"], usageLines["confirm-dialog"], usageLines["version"])
}

// runSigner dispatches the signer subcommands; serve is the only one in
// contract 1. Its stdout is the JSON-lines stream by definition, so every
// failure before the server runs — usage, a refused address, no vault —
// is written as the one-line startup hello (contract 1, ok=false, error)
// with the usual exit code; text mode and the multi-line CLI envelope are
// never used here.
func runSigner(args []string, out output) int {
	fail := func(err error) int {
		code, respErr := out.classify(err)
		_ = keyvault.WriteStartupFailure(out.stdout, keyvault.ContractError{Code: respErr.Code, Message: respErr.Message, Hint: respErr.Hint, Status: respErr.Status})
		return code
	}
	if len(args) == 0 {
		return fail(usagef("signer requires serve"))
	}
	sub, rest := args[0], args[1:]
	out.command = "signer " + sub
	if sub != "serve" {
		return fail(usagef("unknown signer command %q; use serve", sub))
	}
	fs := flag.NewFlagSet("signer serve", flag.ContinueOnError)
	address := fs.String("address", "", "the <service>/<purpose> the server signs with")
	kind, version := addressFlags(fs)
	positional, err := parseFlags(fs, rest)
	if err != nil {
		return fail(err)
	}
	switch {
	case len(positional) != 0:
		return fail(usagef("signer serve takes no positional arguments; use --address (got %q)", positional[0]))
	case *address == "":
		return fail(usagef("signer serve requires --address <service>/<purpose>"))
	}
	addr, err := keyvault.ParseAddress(*address, *kind, *version)
	if err != nil {
		return fail(err)
	}
	manager, err := newManager()
	if err != nil {
		return fail(err)
	}
	server := &keyvault.SignerServer{Manager: manager, Address: addr, ToolVersion: Version}
	if err := server.Serve(stdinReader, out.stdout); err != nil {
		// A startup failure already wrote its hello line; a write failure
		// has no stream left to report on. Only the exit code remains.
		code, _ := out.classify(err)
		return code
	}
	return exitOK
}
