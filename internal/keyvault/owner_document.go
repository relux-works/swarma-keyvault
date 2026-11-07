package keyvault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// DocumentBinding travels only over private helper pipes. It is not a signature
// or grant format. Complete bytes, identity and reason cross both handoffs.
type DocumentBinding struct {
	Document []byte `json:"document"`
	Digest   []byte `json:"digest"`
	Point    []byte `json:"point"`
	SPKI     []byte `json:"spki"`
	Label    string `json:"label"`
	Reason   string `json:"reason"`
}

type DocumentReview struct {
	Phase string              `json:"phase"`
	Error *EnclaveHelperError `json:"error,omitempty"`
	DocumentBinding
}

// DocumentHelper keeps the same native process alive between review and final
// dispatch. Implementations must not sign before the check succeeds.
type DocumentHelper interface {
	CallDocument(context.Context, EnclaveRequest, func(DocumentBinding) error) (EnclaveResponse, error)
}

type ownerDocumentSigner interface {
	signOwnerDocument(context.Context, Key, []byte, []byte, func() error) ([]byte, error)
}

func documentReason(digest []byte) string {
	return "mac-keyvault: sign exact UTF-8 document SHA256 " + hex.EncodeToString(digest) + " with alexis/grants-owner-v1 v1"
}

func cloneDocument(a DocumentBinding) DocumentBinding {
	a.Document = bytes.Clone(a.Document)
	a.Digest = bytes.Clone(a.Digest)
	a.Point = bytes.Clone(a.Point)
	a.SPKI = bytes.Clone(a.SPKI)
	return a
}

func sameDocument(a, b DocumentBinding) bool {
	return bytes.Equal(a.Document, b.Document) && bytes.Equal(a.Digest, b.Digest) && bytes.Equal(a.Point, b.Point) && bytes.Equal(a.SPKI, b.SPKI) && a.Label == b.Label && a.Reason == b.Reason
}

func (r RoutedBackend) signOwnerDocument(ctx context.Context, key Key, digest, document []byte, final func() error) ([]byte, error) {
	if r.Enclave == nil {
		return nil, errors.New("owner document: no native store")
	}
	return r.Enclave.signOwnerDocument(ctx, key, digest, document, final)
}

func (s *EnclaveStore) signOwnerDocument(ctx context.Context, key Key, digest, document []byte, final func() error) ([]byte, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	fixed := Address{Kind: KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1}
	if key.Label != fixed.Label() || key.Record.Label() != key.Label || key.Record.Store != StoreEnclave || !key.Record.UserPresence || key.Record.Extraction != ExtractionNone || s.NonInteractive {
		return nil, errors.New("owner document: wrong key policy or noninteractive route")
	}
	sum := sha256.Sum256(document)
	if len(document) == 0 || len(document) > 16384 || !bytes.Equal(digest, sum[:]) {
		return nil, errors.New("owner document: byte/digest mismatch")
	}
	helper, ok := s.Helper.(DocumentHelper)
	if !ok {
		return nil, errors.New("owner document: helper lacks full review protocol")
	}
	file, err := s.read(key.Label)
	if err != nil {
		return nil, err
	}
	want, err := EncodeRecord(key.Record)
	if err != nil || !bytes.Equal([]byte(file.Tag), want) {
		return nil, errors.New("owner document: record changed before review")
	}
	public, err := spkiFromPoint(file.Point)
	if err != nil || !bytes.Equal(public, key.SPKI) {
		return nil, errors.New("owner document: stored public key changed")
	}
	binding := DocumentBinding{Document: bytes.Clone(document), Digest: bytes.Clone(digest), Point: bytes.Clone(file.Point), SPKI: bytes.Clone(public), Label: key.Label, Reason: documentReason(digest)}
	requestBinding := cloneDocument(binding)
	req := EnclaveRequest{Op: "review-document", Blob: bytes.Clone(file.Blob), Presence: enclavePresenceRequired, Document: &requestBinding}
	confirmed := false
	confirmations := 0
	resp, err := helper.CallDocument(ctx, req, func(review DocumentBinding) error {
		confirmations++
		if confirmations != 1 {
			return errors.New("owner document: repeated native confirmation")
		}
		if !sameDocument(binding, review) {
			return errors.New("owner document: native confirmed bytes or identity changed")
		}
		// Re-read policy/custody after the potentially long native UI wait.
		current, e := s.read(key.Label)
		if e != nil || current.Tag != file.Tag || !bytes.Equal(current.Point, file.Point) || !bytes.Equal(current.Blob, file.Blob) {
			return errors.New("owner document: custody changed during review")
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := final(); e != nil {
			return e
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		confirmed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !confirmed || confirmations != 1 {
		return nil, errors.New("owner document: missing or repeated final confirmation")
	}
	if !bytes.Equal(resp.Point, binding.Point) || len(resp.DER) == 0 {
		return nil, errors.New("owner document: native result missing or wrong public key")
	}
	return resp.DER, nil
}

// CallDocument has bounded newline-framed messages. EOF, timeout, malformed
// handoff, failed checks and canceled contexts kill this one process; no retry.
func (h ExecEnclaveHelper) CallDocument(ctx context.Context, req EnclaveRequest, check func(DocumentBinding) error) (EnclaveResponse, error) {
	if req.Document == nil || req.Op != "review-document" || check == nil || ctx == nil {
		return EnclaveResponse{}, errors.New("owner document: invalid protocol call")
	}
	if !filepath.IsAbs(h.Path) {
		return EnclaveResponse{}, errors.New("owner document: helper path must be absolute")
	}
	if err := requireOwnedFile(h.Path); err != nil {
		return EnclaveResponse{}, err
	}
	owned := cloneDocument(*req.Document)
	req.Document = &owned
	req.Blob = bytes.Clone(req.Blob)
	timeout := h.InteractiveTimeout
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path)
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	input, err := cmd.StdinPipe()
	if err != nil {
		return EnclaveResponse{}, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return EnclaveResponse{}, err
	}
	// Closing both private pipes also bounds a peer that leaves inherited
	// descriptors open. A context deadline must unblock framing reads.
	stopPipes := context.AfterFunc(ctx, func() { _ = input.Close(); _ = output.Close() })
	defer stopPipes()
	if err := cmd.Start(); err != nil {
		input.Close()
		return EnclaveResponse{}, err
	}
	defer func() {
		input.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	enc := json.NewEncoder(input)
	if err := enc.Encode(req); err != nil {
		return EnclaveResponse{}, err
	}
	reader := bufio.NewReaderSize(output, 64*1024+1)
	read := func(value any) error {
		raw, e := reader.ReadSlice('\n')
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return e
		}
		if len(raw) > 64*1024 {
			return errors.New("owner document: helper frame too large")
		}
		return DecodeSingleJSON(bytes.TrimSpace(raw), value)
	}
	var review DocumentReview
	if err := read(&review); err != nil {
		return EnclaveResponse{}, err
	}
	if review.Error != nil {
		return EnclaveResponse{}, review.Error
	}
	if review.Phase != "confirmed" || !sameDocument(*req.Document, review.DocumentBinding) {
		return EnclaveResponse{}, errors.New("owner document: invalid native confirmation")
	}
	if err := check(review.DocumentBinding); err != nil {
		return EnclaveResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return EnclaveResponse{}, err
	}
	dispatch := DocumentReview{Phase: "dispatch", DocumentBinding: *req.Document}
	if err := enc.Encode(dispatch); err != nil {
		return EnclaveResponse{}, err
	}
	_ = input.Close()
	var response EnclaveResponse
	if err := read(&response); err != nil {
		return EnclaveResponse{}, err
	}
	// Reject trailing messages/data rather than silently accepting a second result.
	if extra, err := io.ReadAll(io.LimitReader(reader, 2)); err != nil || len(extra) != 0 {
		return EnclaveResponse{}, errors.New("owner document: trailing helper output")
	}
	waitErr := cmd.Wait()
	if response.Error != nil {
		return EnclaveResponse{}, response.Error
	}
	if waitErr != nil {
		return EnclaveResponse{}, fmt.Errorf("owner document: helper failed: %w", waitErr)
	}
	if err := ctx.Err(); err != nil {
		return EnclaveResponse{}, err
	}
	return response, nil
}

// This backend serves only Enclave records. It never constructs or enumerates a
// login-Keychain backend. The regular store still owns record/file validation.
type ownerDocumentBackend struct{ *EnclaveStore }

func (b ownerDocumentBackend) Serves(store StoreKind) bool {
	return store == StoreEnclave && b.EnclaveStore.Serves()
}

// NewOwnerDocumentManager constructs the Enclave-only native document backend.
// It supplies no key enrollment and never instantiates a login-Keychain store.
func NewOwnerDocumentManager(store *EnclaveStore) *Manager {
	return NewManager(ownerDocumentBackend{store}, nil, Origin{})
}
