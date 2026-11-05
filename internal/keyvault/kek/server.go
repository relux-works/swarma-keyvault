// Package kek is the broker side of KEK contract 1 (see pkg/kekclient): it
// opens a service's KEK envelope with a non-extractable keyvault key and
// hands the KEK only to the code the envelope binds, over one Unix-socket
// connection whose peer it identifies by audit token.
package kek

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

// CodeIdentity is what the broker knows about a piece of code: a running
// peer or a file on disk.
type CodeIdentity struct {
	// Valid is the platform's signature check of the code as it runs (or
	// as it is on disk).
	Valid bool
	// CDHash is the code directory hash, 40 lowercase hex digits.
	CDHash string
	// Identifier and CertificateSHA1 come from the validated code signature.
	// CertificateSHA1 is the lowercase SHA-1 of the leaf certificate DER;
	// ad-hoc signatures have no certificate and leave it empty.
	Identifier      string
	CertificateSHA1 string
	// Runtime and LibraryValidation are the signature's hardened-runtime
	// and library-validation flags.
	Runtime           bool
	LibraryValidation bool
	// GetTaskAllow is the com.apple.security.get-task-allow entitlement.
	GetTaskAllow bool
}

// Problem names why code may not be bound or served, or "" when it may.
// A same-user process could inject into code without these properties and
// act through it, so the binding would mean nothing.
func (c CodeIdentity) Problem() string {
	switch {
	case !c.Valid:
		return "its code signature is not valid"
	case !kekclient.ValidRequirement(`cdhash H"` + c.CDHash + `"`):
		return "its code directory hash is unknown"
	case !c.Runtime:
		return "it is not signed with the hardened runtime"
	case !c.LibraryValidation:
		return "it is not signed with library validation"
	case c.GetTaskAllow:
		return "it carries the get-task-allow entitlement"
	}
	return ""
}

// Vault is the part of keyvault.Manager the broker uses.
type Vault interface {
	Decrypt(addr keyvault.Address, envelope []byte) (keyvault.Key, []byte, error)
}

// Inspector identifies code.
type Inspector interface {
	// Peer identifies the process at the other end of conn.
	Peer(conn *net.UnixConn) (CodeIdentity, error)
	// File identifies the code at path.
	File(path string) (CodeIdentity, error)
}

// Server answers one request.
type Server struct {
	Vault     Vault
	Inspector Inspector
	Audit     *Audit
	// Op is the one operation this process serves and Address the one
	// service/purpose; a request for anything else is refused.
	Op      string
	Address string
	// Timeout bounds the wait for the connection and the request.
	Timeout time.Duration
	Now     func() time.Time
}

// maxRequestBytes bounds the request line.
const maxRequestBytes = 64 << 10

// Serve accepts one connection on l, answers it and returns. The returned
// error is for the operator's log; the peer has already had its answer.
func (s *Server) Serve(l *net.UnixListener) error {
	if s.Timeout > 0 {
		l.SetDeadline(time.Now().Add(s.Timeout))
	}
	conn, err := l.AcceptUnix()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer conn.Close()
	ctx := context.Background()
	if s.Timeout > 0 {
		deadline := time.Now().Add(s.Timeout)
		conn.SetDeadline(deadline)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	resp, outcome := s.handle(ctx, conn)
	line, err := encodeResponse(resp)
	if resp.Result != nil {
		clear(resp.Result.KEK)
	}
	if err != nil {
		return err
	}
	_, werr := conn.Write(line)
	clear(line)
	if outcome != nil {
		return outcome
	}
	return werr
}

// encodeResponse renders the answer line, newline included. An answer that
// carries a KEK is assembled with kekclient.MarshalWithSecret, so the KEK
// never passes through json.Marshal's pooled buffer; every buffer that held
// it is cleared here or by the caller.
func encodeResponse(resp kekclient.Response) ([]byte, error) {
	if resp.Result == nil || resp.Result.KEK == nil {
		line, err := json.Marshal(resp)
		return append(line, '\n'), err
	}
	head := *resp.Result
	head.KEK = nil
	result, err := kekclient.MarshalWithSecret(head, "kek", resp.Result.KEK)
	if err != nil {
		return nil, err
	}
	defer clear(result)
	prefix, err := json.Marshal(struct {
		Contract string `json:"contract"`
		OK       bool   `json:"ok"`
	}{resp.Contract, true})
	if err != nil {
		return nil, err
	}
	line := make([]byte, 0, len(prefix)+len(`,"result":`)+len(result)+2)
	line = append(line, prefix[:len(prefix)-1]...)
	line = append(line, `,"result":`...)
	line = append(line, result...)
	return append(line, '}', '\n'), nil
}

// refusal is an answered error with the operator-side reason.
type refusal struct {
	code    string
	message string
}

func (r *refusal) Error() string { return r.code + ": " + r.message }

func refuse(code, format string, args ...any) *refusal {
	return &refusal{code: code, message: fmt.Sprintf(format, args...)}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) (kekclient.Response, error) {
	entry := AuditEntry{Op: s.Op, Address: s.Address}
	result, err := s.answer(conn, &entry)
	var r *refusal
	if err != nil && !errors.As(err, &r) {
		r = refuse(kekclient.CodeSecurity, "%v", err)
	}
	if r != nil {
		entry.Verdict, entry.Code = "refused", r.code
	} else {
		entry.Verdict = "answered"
	}
	// The answer is given only once the log holds it.
	if aerr := s.Audit.AppendContext(ctx, entry, s.now()); aerr != nil {
		if result != nil {
			clear(result.KEK)
		}
		return failure(kekclient.CodeSecurity, "the audit log cannot be written; nothing is answered"), fmt.Errorf("audit: %w", aerr)
	}
	if r != nil {
		return failure(r.code, r.message), r
	}
	return kekclient.Response{Contract: kekclient.Contract, OK: true, Result: result}, nil
}

func failure(code, message string) kekclient.Response {
	return kekclient.Response{Contract: kekclient.Contract, Error: &kekclient.Error{Code: code, Message: message}}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// answer runs the gates in order: the peer's code properties before the
// request is read, then the request, the envelope, the key, the payload,
// and the peer against the payload's binding.
func (s *Server) answer(conn *net.UnixConn, entry *AuditEntry) (*kekclient.Result, error) {
	peer, err := s.Inspector.Peer(conn)
	if err != nil {
		return nil, refuse(kekclient.CodeCallerRefused, "the caller's code cannot be identified: %v", err)
	}
	entry.Caller = peer.CDHash
	if problem := peer.Problem(); problem != "" {
		return nil, refuse(kekclient.CodeCallerRefused, "the caller is refused: %s", problem)
	}
	req, env, err := readRequest(conn)
	if err != nil {
		return nil, refuse(kekclient.CodeBadRequest, "%v", err)
	}
	if req.Op != s.Op || req.Address != s.Address {
		return nil, refuse(kekclient.CodeBadRequest, "this broker serves %s for %s, not %s for %s", s.Op, s.Address, req.Op, req.Address)
	}
	if env.Address != s.Address {
		return nil, refuse(kekclient.CodeBadRequest, "the envelope is for %s, not %s", env.Address, s.Address)
	}
	entry.Generation = env.Generation
	service, purpose, _ := strings.Cut(env.Address, "/")
	key, plain, err := s.Vault.Decrypt(keyvault.Address{Kind: keyvault.KindKey, Service: service, Purpose: purpose, Version: env.Generation}, env.ECIES)
	defer clear(plain)
	if err != nil {
		return nil, vaultRefusal(err)
	}
	if key.Fingerprint() != env.Fingerprint {
		return nil, refuse(kekclient.CodeEnvelopeInvalid, "the envelope names another key than %s v%d", env.Address, env.Generation)
	}
	payload, err := kekclient.ParsePayload(plain, env)
	defer clear(payload.KEK)
	if err != nil {
		return nil, refuse(kekclient.CodeEnvelopeInvalid, "%v", err)
	}
	// Re-identify after decryption: a connection survives exec. Reapply all
	// hardening gates and require the same observed code facts, even when two
	// builds would individually satisfy a certificate binding. This is a
	// second observation, not an atomic guarantee against a subsequent exec.
	current, err := s.Inspector.Peer(conn)
	if err != nil || current.Problem() != "" || current != peer {
		return nil, refuse(kekclient.CodeCallerRefused, "the caller's code changed or cannot be revalidated")
	}
	if !current.matches(payload.Requirement) {
		return nil, refuse(kekclient.CodeCallerRefused, "the envelope is bound to other code")
	}
	result := &kekclient.Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint}
	switch s.Op {
	case kekclient.OpUnwrap:
		result.KEK = bytes.Clone(payload.KEK)
	case kekclient.OpRebind:
		next, newReq, err := s.rebind(key, payload)
		if err != nil {
			return nil, err
		}
		entry.Requirement = newReq
		result.Envelope = next
	default:
		return nil, refuse(kekclient.CodeBadRequest, "unknown operation %q", s.Op)
	}
	return result, nil
}

// matches evaluates only the two canonical contract forms against facts from
// validated code. No missing certificate, parser failure or identifier alone
// falls back to another binding mode. Callers must also enforce Problem().
func (c CodeIdentity) matches(requirement string) bool {
	if bound, ok := kekclient.RequirementCDHash(requirement); ok {
		return c.CDHash == bound
	}
	identifier, certificate, ok := kekclient.RequirementCertificate(requirement)
	return ok && c.CertificateSHA1 == certificate && c.Identifier == identifier
}

// rebind binds the same KEK to the code now installed at the payload's
// install path. The broker reads that file itself; the caller names nothing.
func (s *Server) rebind(key keyvault.Key, payload kekclient.Payload) (json.RawMessage, string, error) {
	target, err := s.Inspector.File(payload.InstallPath)
	if err != nil {
		return nil, "", refuse(kekclient.CodeRebindRefused, "the code at %s cannot be identified: %v", payload.InstallPath, err)
	}
	if problem := target.Problem(); problem != "" {
		return nil, "", refuse(kekclient.CodeRebindRefused, "the code at %s is refused: %s", payload.InstallPath, problem)
	}
	if _, _, certificate := kekclient.RequirementCertificate(payload.Requirement); certificate {
		if target.matches(payload.Requirement) {
			return nil, "", refuse(kekclient.CodeRebindRefused, "the installed code already matches the certificate binding")
		}
		return nil, "", refuse(kekclient.CodeRebindRefused, "rebind cannot change a certificate binding; explicit provisioning is required")
	}
	newReq, err := kekclient.RequirementForCDHash(target.CDHash)
	if err != nil {
		return nil, "", refuse(kekclient.CodeRebindRefused, "%v", err)
	}
	if newReq == payload.Requirement {
		return nil, "", refuse(kekclient.CodeRebindRefused, "the envelope is already bound to the code at %s", payload.InstallPath)
	}
	next, err := kekclient.Wrap(kekclient.WrapSpec{SPKI: key.SPKI, Fingerprint: payload.Fingerprint, Address: payload.Address, Generation: payload.Generation, Requirement: newReq, InstallPath: payload.InstallPath}, payload.KEK)
	if err != nil {
		return nil, "", err
	}
	return next, newReq, nil
}

// readRequest reads one request line and parses it strictly: one object,
// exact members, nothing repeated, nothing after it on the line.
func readRequest(r io.Reader) (kekclient.Request, kekclient.Envelope, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxRequestBytes)).ReadBytes('\n')
	if err != nil {
		return kekclient.Request{}, kekclient.Envelope{}, fmt.Errorf("no request line: %v", err)
	}
	return kekclient.ParseRequest(bytes.TrimSuffix(line, []byte("\n")))
}

// vaultRefusal maps the vault's gates onto the contract's codes.
func vaultRefusal(err error) error {
	var kv *keyvault.Refusal
	switch {
	case errors.Is(err, keyvault.ErrNotFound):
		return refuse(kekclient.CodeNotFound, "%v", err)
	case errors.Is(err, keyvault.ErrEnvelopeInvalid):
		return refuse(kekclient.CodeEnvelopeInvalid, "the envelope does not open under this key")
	case errors.As(err, &kv):
		switch kv.Code {
		case keyvault.CodeExpired:
			return refuse(kekclient.CodeExpired, "%s", kv.Message)
		case keyvault.CodeUsageRefused:
			return refuse(kekclient.CodeUsageRefused, "%s", kv.Message)
		case keyvault.CodeMetadataUnknown:
			return refuse(kekclient.CodeMetadataUnknown, "%s", kv.Message)
		case keyvault.CodeUnsupportedPrimitive:
			return refuse(kekclient.CodeUnsupported, "%s", kv.Message)
		}
		return refuse(kekclient.CodeSecurity, "%s", kv.Message)
	}
	return refuse(kekclient.CodeSecurity, "%v", err)
}
