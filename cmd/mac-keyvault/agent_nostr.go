package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

const agentNostrUsage = "mac-keyvault [--json] agent-nostr generate --service agent-NAME --version N | list | describe agent-NAME/nostr --version N | pub agent-NAME/nostr --version N --format x-only-hex|npub | sign agent-NAME/nostr --version N --identity FULL_MXID --enrollment-receipt PATH --digest HEX"

type agentNostrOperations interface {
	List() ([]keyvault.AgentNostrPublic, error)
	Describe(service string, version int) (keyvault.AgentNostrPublic, error)
	Generate(service string, version int) (keyvault.AgentNostrPublic, error)
	Sign(identity string, receipt keyvault.AgentNostrEnrollment, service string, version int, digest []byte) (keyvault.AgentNostrSignature, error)
}

var newAgentNostrOperations = func() (agentNostrOperations, error) {
	lock, err := vaultLock()
	if err != nil {
		return nil, err
	}
	return keyvault.NewAgentNostrManager(keyvault.NewAgentNostrSecurityStore(), keyvault.NewAgentNostrPrivate(), lock), nil
}

type agentNostrOptions struct {
	operation   string
	service     string
	version     int
	format      string
	identity    string
	receiptPath string
	digest      []byte
}

type agentNostrResponse struct {
	OK      bool                 `json:"ok"`
	Command string               `json:"command"`
	Result  any                  `json:"result,omitempty"`
	Error   *agentNostrJSONError `json:"error,omitempty"`
}

type agentNostrJSONError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

type agentNostrUnknownResult struct {
	Operation         string `json:"operation"`
	Service           string `json:"service"`
	Purpose           string `json:"purpose"`
	Version           int    `json:"version"`
	Outcome           string `json:"outcome"`
	PublicKey         string `json:"public_key"`
	KeySHA256         string `json:"key_sha256"`
	RecordFingerprint string `json:"record_fingerprint"`
}

type agentNostrPubResult struct {
	Format            string `json:"format"`
	PublicKey         string `json:"public_key"`
	RecordFingerprint string `json:"record_fingerprint"`
	KeySHA256         string `json:"key_sha256"`
}

var agentNostrJSONEncode = func(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func runAgentNostr(args []string, out output) int {
	opts, ok := parseAgentNostrArgs(args)
	if !ok {
		return deliverAgentNostrFailure(out, agentNostrInvalid(""), false)
	}

	var receipt keyvault.AgentNostrEnrollment
	if opts.operation == "sign" {
		var err error
		receipt, err = readAgentNostrEnrollment(opts.receiptPath)
		if err != nil {
			return deliverAgentNostrFailure(out, agentNostrFailure("invalid_enrollment", "sign", opts.service, opts.version), false)
		}
		if receipt.OwnerMXID != opts.identity || receipt.Service != opts.service || receipt.Purpose != "nostr" || receipt.Version != opts.version {
			return deliverAgentNostrFailure(out, agentNostrFailure("enrollment_mismatch", "sign", opts.service, opts.version), false)
		}
	}

	operations, err := newAgentNostrOperations()
	if err != nil || operations == nil {
		return deliverAgentNostrFailure(out, agentNostrFailure("unavailable", opts.operation, opts.service, opts.version), false)
	}

	var result any
	switch opts.operation {
	case "generate":
		public, err := operations.Generate(opts.service, opts.version)
		if err != nil {
			return deliverAgentNostrFailure(out, normalizeAgentNostrFailure(err, opts), false)
		}
		result = public
	case "list":
		rows, err := operations.List()
		if err != nil {
			return deliverAgentNostrFailure(out, normalizeAgentNostrFailure(err, opts), false)
		}
		if rows == nil {
			rows = []keyvault.AgentNostrPublic{}
		}
		result = rows
	case "describe", "pub":
		public, err := operations.Describe(opts.service, opts.version)
		if err != nil {
			return deliverAgentNostrFailure(out, normalizeAgentNostrFailure(err, opts), false)
		}
		if opts.operation == "describe" {
			result = public
		} else {
			value := public.Record.PublicKey
			if opts.format == "npub" {
				value = public.Record.NPub
			}
			result = agentNostrPubResult{Format: opts.format, PublicKey: value, RecordFingerprint: public.RecordFingerprint, KeySHA256: public.KeySHA256}
		}
	case "sign":
		signature, err := operations.Sign(opts.identity, receipt, opts.service, opts.version, opts.digest)
		if err != nil {
			return deliverAgentNostrFailure(out, normalizeAgentNostrFailure(err, opts), false)
		}
		result = signature
	default:
		return deliverAgentNostrFailure(out, agentNostrInvalid(opts.operation), false)
	}

	plain := agentNostrPlainSuccess(opts.operation, result)
	var success []byte
	if out.json {
		success, err = agentNostrJSONEncode(agentNostrResponse{OK: true, Command: "agent-nostr", Result: result})
	} else {
		success = []byte(plain)
	}
	if err != nil || len(success) == 0 {
		failure := agentNostrFailure("unavailable", opts.operation, opts.service, opts.version)
		if opts.operation == "generate" || opts.operation == "sign" {
			failure = agentNostrResultFailure(opts, result)
		}
		return deliverAgentNostrFailure(out, failure, false)
	}
	if !agentNostrOutputFits(success) {
		failure := agentNostrFailure("unavailable", opts.operation, opts.service, opts.version)
		if opts.operation == "generate" || opts.operation == "sign" {
			failure = agentNostrResultFailure(opts, result)
		}
		return deliverAgentNostrFailure(out, failure, false)
	}
	if checkedAgentNostrWrite(out.stdout, success) {
		return exitOK
	}
	if opts.operation == "generate" || opts.operation == "sign" {
		agentNostrWriteFallback(out.stderr, agentNostrFailure("unknown", opts.operation, opts.service, opts.version))
	} else {
		agentNostrWriteFallback(out.stderr, agentNostrFailure("unavailable", opts.operation, opts.service, opts.version))
	}
	return exitFailure
}

func agentNostrOutputFits(encoded []byte) bool {
	return len(encoded) <= keyvault.AgentNostrMaxPublicOutput
}

func parseAgentNostrArgs(args []string) (agentNostrOptions, bool) {
	if len(args) == 0 {
		return agentNostrOptions{}, false
	}
	opts := agentNostrOptions{operation: args[0]}
	switch opts.operation {
	case "generate", "list", "describe", "pub", "sign":
	default:
		return agentNostrOptions{}, false
	}
	allowed := map[string]bool{}
	switch opts.operation {
	case "generate":
		allowed["service"], allowed["version"] = true, true
	case "describe":
		allowed["version"] = true
	case "pub":
		allowed["version"], allowed["format"] = true, true
	case "sign":
		allowed["version"], allowed["identity"], allowed["enrollment-receipt"], allowed["digest"] = true, true, true, true
	}
	values := make(map[string]string, len(allowed))
	seen := make(map[string]bool, len(allowed))
	var positional []string
	for i := 1; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if _, isGlobalOutputFlag := jsonToken(token); isGlobalOutputFlag {
			continue
		}
		if !strings.HasPrefix(token, "--") {
			positional = append(positional, token)
			continue
		}
		nameValue := strings.TrimPrefix(token, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")
		if !allowed[name] || seen[name] {
			return agentNostrOptions{}, false
		}
		seen[name] = true
		if !hasValue {
			if i+1 >= len(args) || args[i+1] == "--" {
				return agentNostrOptions{}, false
			}
			i++
			value = args[i]
		}
		values[name] = value
	}

	required := func(name string) bool { return seen[name] && values[name] != "" }
	if opts.operation == "generate" || opts.operation == "describe" || opts.operation == "pub" || opts.operation == "sign" {
		if !required("version") {
			return agentNostrOptions{}, false
		}
		version, err := strconv.Atoi(values["version"])
		if err != nil || strconv.Itoa(version) != values["version"] || keyvault.ValidateAgentNostrVersion(version) != nil {
			return agentNostrOptions{}, false
		}
		opts.version = version
	}
	switch opts.operation {
	case "generate":
		if len(positional) != 0 || !required("service") || keyvault.ValidateAgentNostrService(values["service"]) != nil {
			return agentNostrOptions{}, false
		}
		opts.service = values["service"]
	case "list":
		if len(positional) != 0 {
			return agentNostrOptions{}, false
		}
	case "describe", "pub", "sign":
		if len(positional) != 1 {
			return agentNostrOptions{}, false
		}
		service, purpose, ok := strings.Cut(positional[0], "/")
		if !ok || strings.Contains(purpose, "/") || purpose != "nostr" || keyvault.ValidateAgentNostrService(service) != nil {
			return agentNostrOptions{}, false
		}
		opts.service = service
	}
	if opts.operation == "pub" {
		if !required("format") || (values["format"] != "x-only-hex" && values["format"] != "npub") {
			return agentNostrOptions{}, false
		}
		opts.format = values["format"]
	}
	if opts.operation == "sign" {
		if !required("identity") || !required("enrollment-receipt") || !required("digest") || len(values["digest"]) != 64 {
			return agentNostrOptions{}, false
		}
		digest, err := hex.DecodeString(values["digest"])
		if err != nil || len(digest) != 32 {
			return agentNostrOptions{}, false
		}
		opts.identity = values["identity"]
		opts.receiptPath = values["enrollment-receipt"]
		opts.digest = digest
	}
	return opts, true
}

func readAgentNostrEnrollment(path string) (keyvault.AgentNostrEnrollment, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return keyvault.AgentNostrEnrollment{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > keyvault.AgentNostrMaxReceipt || info.Mode().Perm()&0022 != 0 {
		return keyvault.AgentNostrEnrollment{}, fmt.Errorf("unsafe enrollment receipt")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return keyvault.AgentNostrEnrollment{}, fmt.Errorf("unsafe enrollment receipt")
	}
	raw, err := io.ReadAll(io.LimitReader(file, keyvault.AgentNostrMaxReceipt+1))
	if err != nil || len(raw) == 0 || len(raw) > keyvault.AgentNostrMaxReceipt {
		return keyvault.AgentNostrEnrollment{}, fmt.Errorf("invalid enrollment receipt")
	}
	receipt, err := keyvault.ParseAgentNostrEnrollment(raw)
	if err != nil {
		return keyvault.AgentNostrEnrollment{}, fmt.Errorf("invalid enrollment receipt")
	}
	return receipt, nil
}

func normalizeAgentNostrFailure(err error, opts agentNostrOptions) *keyvault.AgentNostrFailure {
	var failure *keyvault.AgentNostrFailure
	if err != nil && errorsAsAgentNostrFailure(err, &failure) && knownAgentNostrCode(failure.Code) {
		copy := *failure
		if copy.Operation == "" {
			copy.Operation = opts.operation
		}
		if copy.Service == "" {
			copy.Service = opts.service
		}
		if copy.Purpose == "" {
			copy.Purpose = "nostr"
		}
		if copy.Version == 0 {
			copy.Version = opts.version
		}
		return &copy
	}
	if opts.operation == "generate" || opts.operation == "sign" {
		return agentNostrUnknown(opts)
	}
	return agentNostrFailure("unavailable", opts.operation, opts.service, opts.version)
}

// Kept as a small wrapper so the command boundary does not need to expose raw
// backend errors or status strings in its public response.
func errorsAsAgentNostrFailure(err error, target **keyvault.AgentNostrFailure) bool {
	return errors.As(err, target)
}

func knownAgentNostrCode(code string) bool {
	code = strings.TrimPrefix(code, "agent_nostr_")
	switch code {
	case "invalid_input", "invalid_enrollment", "enrollment_mismatch", "duplicate", "not_found", "corrupt_record", "unavailable", "untrusted", "unknown":
		return true
	default:
		return false
	}
}

func agentNostrInvalid(operation string) *keyvault.AgentNostrFailure {
	return agentNostrFailure("invalid_input", operation, "", 0)
}

func agentNostrFailure(code, operation, service string, version int) *keyvault.AgentNostrFailure {
	return &keyvault.AgentNostrFailure{Code: code, Operation: operation, Service: service, Purpose: "nostr", Version: version}
}

func agentNostrUnknown(opts agentNostrOptions) *keyvault.AgentNostrFailure {
	return &keyvault.AgentNostrFailure{Code: "unknown", Operation: opts.operation, Service: opts.service, Purpose: "nostr", Version: opts.version, Outcome: "unknown"}
}

func agentNostrResultFailure(opts agentNostrOptions, result any) *keyvault.AgentNostrFailure {
	failure := agentNostrUnknown(opts)
	switch value := result.(type) {
	case keyvault.AgentNostrPublic:
		failure.PublicKey = value.Record.PublicKey
		failure.KeySHA256 = value.KeySHA256
		failure.RecordFingerprint = value.RecordFingerprint
	case keyvault.AgentNostrSignature:
		failure.KeySHA256 = value.KeySHA256
		failure.RecordFingerprint = value.RecordFingerprint
	}
	return failure
}

func agentNostrErrorDetails(code string) (int, agentNostrJSONError) {
	code = strings.TrimPrefix(code, "agent_nostr_")
	switch code {
	case "invalid_input":
		return exitUsage, agentNostrJSONError{Code: "agent_nostr_invalid_input", Message: "Invalid agent Nostr input.", Hint: "Use the exact agent-nostr syntax."}
	case "invalid_enrollment":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_invalid_enrollment", Message: "Agent Nostr enrollment is unavailable or invalid.", Hint: "Ask the issuing manager for the existing enrollment receipt."}
	case "enrollment_mismatch":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_enrollment_mismatch", Message: "Agent Nostr enrollment does not match.", Hint: "Preserve the record and ask the issuing manager."}
	case "duplicate":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_duplicate", Message: "Agent Nostr generation already exists.", Hint: "Preserve the existing generation; do not replace it."}
	case "not_found":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_not_found", Message: "Agent Nostr generation was not found.", Hint: "Check the exact enrolled service and version."}
	case "corrupt_record":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_corrupt_record", Message: "Agent Nostr record was refused.", Hint: "Preserve the record and ask the issuing manager."}
	case "untrusted":
		return exitRefused, agentNostrJSONError{Code: "agent_nostr_untrusted", Message: "Agent Nostr admission was refused.", Hint: "Use the admitted signed tool pair; do not edit trust."}
	case "unknown":
		return exitFailure, agentNostrJSONError{Code: "agent_nostr_unknown", Message: "Agent Nostr outcome is unknown.", Hint: "Preserve the candidate and reconcile; do not repeat the private operation."}
	default:
		return exitFailure, agentNostrJSONError{Code: "agent_nostr_unavailable", Message: "Agent Nostr operation is unavailable.", Hint: "Preserve custody; do not change trust or retry privately."}
	}
}

func deliverAgentNostrFailure(out output, failure *keyvault.AgentNostrFailure, afterPartialSuccess bool) int {
	if failure == nil {
		failure = agentNostrFailure("unavailable", "", "", 0)
	}
	code := strings.TrimPrefix(failure.Code, "agent_nostr_")
	exitCode, publicError := agentNostrErrorDetails(code)
	var result any
	if code == "unknown" {
		result = agentNostrUnknownResult{
			Operation: failure.Operation, Service: failure.Service, Purpose: failure.Purpose, Version: failure.Version,
			Outcome: "unknown", PublicKey: failure.PublicKey, KeySHA256: failure.KeySHA256, RecordFingerprint: failure.RecordFingerprint,
		}
	}
	if afterPartialSuccess {
		agentNostrWriteFallback(out.stderr, failure)
		return exitCode
	}
	if out.json {
		encoded, err := agentNostrJSONEncode(agentNostrResponse{OK: false, Command: "agent-nostr", Result: result, Error: &publicError})
		if err != nil || len(encoded) > keyvault.AgentNostrMaxPublicOutput || !checkedAgentNostrWrite(out.stdout, encoded) {
			agentNostrWriteFallback(out.stderr, failure)
			return exitCode
		}
		return exitCode
	}
	text := []byte(fmt.Sprintf("error: %s: %s\nhint: %s\n", publicError.Code, publicError.Message, publicError.Hint))
	if !checkedAgentNostrWrite(out.stderr, text) {
		return exitCode
	}
	return exitCode
}

func agentNostrWriteFallback(w io.Writer, failure *keyvault.AgentNostrFailure) {
	_, public := agentNostrErrorDetails(failure.Code)
	message := []byte(fmt.Sprintf("%s: %s\n", public.Code, public.Message))
	if len(message) <= 256 {
		_ = checkedAgentNostrWrite(w, message)
	}
}

func checkedAgentNostrWrite(w io.Writer, data []byte) bool {
	if w == nil {
		return false
	}
	if file, ok := w.(*os.File); ok && file == os.Stdout {
		pending := make(chan os.Signal, 1)
		signal.Notify(pending, syscall.SIGPIPE)
		defer func() {
			signal.Stop(pending)
			select {
			case <-pending:
			default:
			}
		}()
	}
	n, err := w.Write(data)
	return err == nil && n == len(data)
}

func agentNostrPlainSuccess(operation string, result any) string {
	switch operation {
	case "generate", "describe":
		public, ok := result.(keyvault.AgentNostrPublic)
		if !ok {
			return ""
		}
		return agentNostrRecordText(public)
	case "list":
		rows, ok := result.([]keyvault.AgentNostrPublic)
		if !ok {
			return ""
		}
		var text strings.Builder
		text.WriteString("service/nostr@version\tpublic_key\tnpub\tkey_sha256\trecord_fingerprint\n")
		for _, row := range rows {
			text.WriteString(agentNostrListLine(row))
		}
		return text.String()
	case "pub":
		public, ok := result.(agentNostrPubResult)
		if !ok {
			return ""
		}
		return public.PublicKey + "\n"
	case "sign":
		signature, ok := result.(keyvault.AgentNostrSignature)
		if !ok {
			return ""
		}
		return signature.Signature + "\n"
	default:
		return ""
	}
}

func agentNostrRecordText(public keyvault.AgentNostrPublic) string {
	var text strings.Builder
	text.WriteString("service/nostr@version\tpublic_key\tnpub\tkey_sha256\trecord_fingerprint\n")
	text.WriteString(agentNostrListLine(public))
	return text.String()
}

func agentNostrListLine(public keyvault.AgentNostrPublic) string {
	return fmt.Sprintf("%s/nostr@%d\t%s\t%s\t%s\t%s\n", public.Record.Service, public.Record.Version, public.Record.PublicKey, public.Record.NPub, public.KeySHA256, public.RecordFingerprint)
}
