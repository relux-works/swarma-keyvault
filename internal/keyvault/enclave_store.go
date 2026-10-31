package keyvault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The Secure Enclave store keeps each key as a CryptoKit
// SecureEnclave.P256.Signing.PrivateKey blob (dataRepresentation) in a
// tool-owned file. The blob is wrapped by this device's Secure Enclave and
// useless anywhere else; the private half never exists outside it. This
// route needs no keychain entitlement, which the login-keychain route
// (security_darwin.c) refuses with -34018 for --enclave and --user-presence.
// The Swift helper mac-keyvault-enclave performs every Secure Enclave call;
// this file owns the files, the policy and the checks around it.

// EnclaveFileFormat names the file layout below.
const EnclaveFileFormat = "mac-keyvault-enclave/1"

// enclaveFileMax bounds what is read back: a blob is about 0.5 KiB and the
// record a few KiB.
const enclaveFileMax = 64 * 1024

// Presence modes the helper understands.
const (
	enclavePresenceNone     = "none"
	enclavePresenceUser     = "user-presence"
	enclavePresenceRequired = "required"
)

// enclaveFile is one key on disk. Tag is the schema-2 record, as the
// keychain application tag carries it; Point is the X9.63 public half the
// helper returned at creation.
type enclaveFile struct {
	Format string `json:"format"`
	Label  string `json:"label"`
	Tag    string `json:"tag"`
	Point  []byte `json:"point"`
	Blob   []byte `json:"blob"`
}

// EnclaveRequest is one helper call; byte fields travel as base64.
type EnclaveRequest struct {
	Op       string `json:"op"`
	Presence string `json:"presence,omitempty"`
	Blob     []byte `json:"blob,omitempty"`
	Digest   []byte `json:"digest,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Interaction "none" forbids the presence prompt: a presence key then
	// refuses instead of asking.
	Interaction string `json:"interaction,omitempty"`
}

// EnclaveResponse is the helper's answer; Error is set exactly when the
// helper failed.
type EnclaveResponse struct {
	Blob             []byte              `json:"blob,omitempty"`
	Point            []byte              `json:"point,omitempty"`
	DER              []byte              `json:"der,omitempty"`
	PresenceEnforced *bool               `json:"presence_enforced,omitempty"`
	Error            *EnclaveHelperError `json:"error,omitempty"`
}

// EnclaveHelperError is a failure the helper reported: a short code and the
// OSStatus it maps to (errSecInteractionNotAllowed when presence was needed
// and not given, errSecUserCanceled for a canceled prompt).
type EnclaveHelperError struct {
	Code    string `json:"code"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (e *EnclaveHelperError) Error() string {
	return fmt.Sprintf("mac-keyvault-enclave %s: %s", e.Code, e.Message)
}

// EnclaveHelper runs one request. interactive is true only for a signature
// that may show the Touch ID prompt, so the runner can allow it more time.
type EnclaveHelper interface {
	Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error)
}

// ExecEnclaveHelper runs the mac-keyvault-enclave binary at Path.
type ExecEnclaveHelper struct {
	Path string
	// Timeout bounds a silent call, InteractiveTimeout a call that waits
	// for the owner's finger.
	Timeout            time.Duration
	InteractiveTimeout time.Duration
}

// Call writes the request to the helper's stdin and decodes one response.
func (h ExecEnclaveHelper) Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error) {
	if !filepath.IsAbs(h.Path) {
		return EnclaveResponse{}, fmt.Errorf("enclave helper path %q is not absolute", h.Path)
	}
	if err := requireOwnedFile(h.Path); err != nil {
		return EnclaveResponse{}, fmt.Errorf("enclave helper: %w", err)
	}
	timeout := h.Timeout
	if interactive {
		timeout = h.InteractiveTimeout
	}
	input, err := json.Marshal(req)
	if err != nil {
		return EnclaveResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path)
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: enclaveFileMax}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return EnclaveResponse{}, &StatusError{Op: "enclave " + req.Op + " (timed out)", Status: errSecUserCanceled}
	}
	var resp EnclaveResponse
	if err := DecodeSingleJSON(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		if runErr != nil {
			return EnclaveResponse{}, fmt.Errorf("enclave helper %s: %w", req.Op, runErr)
		}
		return EnclaveResponse{}, fmt.Errorf("enclave helper %s: unreadable response: %w", req.Op, err)
	}
	if resp.Error != nil {
		return EnclaveResponse{}, resp.Error
	}
	if runErr != nil {
		return EnclaveResponse{}, fmt.Errorf("enclave helper %s: %w", req.Op, runErr)
	}
	return resp, nil
}

const errSecUserCanceled = -128

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("enclave helper output exceeds the limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// EnclaveStore is the Backend for store "enclave": one file per label in
// Dir, every Secure Enclave call through Helper.
type EnclaveStore struct {
	Dir    string
	Helper EnclaveHelper
	// NonInteractive never shows the Touch ID prompt: a presence key then
	// refuses with errSecInteractionNotAllowed. Production leaves it false.
	NonInteractive bool
	// Describe, when set, names what a digest signs for the presence prompt
	// (the CLI recognises the data it hashed); "" keeps the generic text.
	// It only words the prompt: a caller able to run the helper can word
	// its own, so the prompt is a check against mistakes, not a boundary.
	Describe func(digest []byte) string
	// err is a construction failure of the directory (no home directory),
	// reported by every call. helperErr is a missing or unresolvable helper:
	// keys are still listed, described and deleted, but nothing is created
	// or signed and Serves reports the store as not served.
	err       error
	helperErr error
}

// NewEnclaveStore returns a store over dir with helper.
func NewEnclaveStore(dir string, helper EnclaveHelper) *EnclaveStore {
	return &EnclaveStore{Dir: dir, Helper: helper}
}

// DefaultEnclaveStore is the production store: files under
// DefaultEnclaveDir, the helper mac-keyvault-enclave next to the running
// executable (symlinks resolved), never looked up on PATH.
func DefaultEnclaveStore() *EnclaveStore {
	dir, err := DefaultEnclaveDir()
	if err != nil {
		return &EnclaveStore{err: fmt.Errorf("enclave store: %w", err)}
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return &EnclaveStore{Dir: dir, helperErr: fmt.Errorf("enclave helper: %w", err)}
	}
	helper := ExecEnclaveHelper{Path: filepath.Join(filepath.Dir(self), "mac-keyvault-enclave"), Timeout: 15 * time.Second, InteractiveTimeout: 60 * time.Second}
	store := NewEnclaveStore(dir, helper)
	if err := requireOwnedFile(helper.Path); err != nil {
		store.helperErr = fmt.Errorf("enclave helper %s: %w", helper.Path, err)
	}
	return store
}

// enclaveReason words the presence prompt: what is signed, then the key.
// The default names the sha256 prefix so the owner can match it against
// what the caller announced.
func enclaveReason(label string, digest []byte, describe func([]byte) string) string {
	key := label
	if addr, ok := ParseLabel(label); ok {
		key = fmt.Sprintf("%s/%s v%d", addr.Service, addr.Purpose, addr.Version)
	}
	what := "sign sha256 " + hex.EncodeToString(digest[:min(len(digest), 4)])
	if describe != nil {
		if d := describe(digest); d != "" {
			what = d
		}
	}
	return fmt.Sprintf("mac-keyvault: %s with %s", what, key)
}

// Serves reports whether the store can create and sign: its directory and
// its helper both resolved.
func (s *EnclaveStore) Serves() bool {
	return s != nil && s.err == nil && s.helperErr == nil && s.Helper != nil
}

func (s *EnclaveStore) usable() error {
	if s.err != nil {
		return s.err
	}
	if s.helperErr != nil {
		return s.helperErr
	}
	if s.Helper == nil {
		return errors.New("enclave store: no helper")
	}
	return nil
}

// DefaultEnclaveDir sits next to the init lock.
func DefaultEnclaveDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "mac-infra", "keyvault", "enclave"), nil
}

// fileName is the key file name of label: the label itself (inside the
// namespace, [A-Za-z0-9._-], no "..") plus ".json", never a path.
func fileName(label string) (string, error) {
	if err := RequireOwnLabel(label); err != nil {
		return "", err
	}
	if !labelPattern.MatchString(label) || strings.Contains(label, "..") {
		return "", fmt.Errorf("enclave store: label %q cannot name a file", label)
	}
	return label + ".json", nil
}

// Create asks the helper for a new Secure Enclave key and stores it. A key
// whose measured presence policy differs from the requested one is refused
// and never stored: the record must not claim a protection the key lacks.
func (s *EnclaveStore) Create(opts CreateOptions) (Item, error) {
	if err := s.usable(); err != nil {
		return Item{}, err
	}
	if opts.Store != StoreEnclave {
		return Item{}, fmt.Errorf("enclave store: cannot create store %q", opts.Store)
	}
	name, err := fileName(opts.Label)
	if err != nil {
		return Item{}, err
	}
	dir, err := s.ensureDir()
	if err != nil {
		return Item{}, err
	}
	defer dir.Close()
	if exists, err := enclaveFileExistsAt(dir, name); err != nil {
		return Item{}, fmt.Errorf("enclave store: %w", err)
	} else if exists {
		return Item{}, &StatusError{Op: "create (Secure Enclave)", Status: -25299}
	}
	presence := enclavePresenceNone
	if opts.UserPresence {
		presence = enclavePresenceUser
	}
	resp, err := s.Helper.Call(EnclaveRequest{Op: "create", Presence: presence}, false)
	if err != nil {
		return Item{}, enclaveError("create (Secure Enclave)", err)
	}
	if len(resp.Blob) == 0 || resp.PresenceEnforced == nil {
		return Item{}, untrusted(opts.Label, "the helper returned no blob or no presence verdict")
	}
	if *resp.PresenceEnforced != opts.UserPresence {
		return Item{}, untrusted(opts.Label, fmt.Sprintf("the new key enforces user presence = %t, the request asked for %t; nothing was stored", *resp.PresenceEnforced, opts.UserPresence))
	}
	spki, err := spkiFromPoint(resp.Point)
	if err != nil {
		return Item{}, untrusted(opts.Label, "the helper returned an invalid public key: "+err.Error())
	}
	file := enclaveFile{Format: EnclaveFileFormat, Label: opts.Label, Tag: string(opts.Tag), Point: resp.Point, Blob: resp.Blob}
	if err := writeEnclaveFile(dir, name, file, false); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Item{}, &StatusError{Op: "create (Secure Enclave)", Status: -25299}
		}
		return Item{}, err
	}
	return Item{Label: opts.Label, Tag: opts.Tag, SPKI: spki}, nil
}

// openDir opens the store directory; ok is false when it does not exist yet.
func (s *EnclaveStore) openDir() (dir *os.File, ok bool, err error) {
	if s.err != nil {
		return nil, false, s.err
	}
	dir, err = openEnclaveDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("enclave store: %w", err)
	}
	return dir, true, nil
}

// List reads every key file. A file that is unsafe or unreadable is still
// listed under its label, with the reason as Problem and no record, so it
// can be seen and deleted but never used.
func (s *EnclaveStore) List() ([]Item, error) {
	dir, ok, err := s.openDir()
	if err != nil || !ok {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("enclave store: %w", err)
	}
	var items []Item
	for _, entry := range entries {
		label, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || RequireOwnLabel(label) != nil {
			continue
		}
		file, err := readEnclaveFile(dir, label)
		if err != nil {
			items = append(items, Item{Label: label, Problem: "enclave file refused: " + err.Error()})
			continue
		}
		spki, err := spkiFromPoint(file.Point)
		if err != nil {
			items = append(items, Item{Label: label, Problem: "enclave file refused: public key: " + err.Error()})
			continue
		}
		items = append(items, Item{Label: label, Tag: []byte(file.Tag), SPKI: spki})
	}
	return items, nil
}

// Has reports whether a key file exists under label.
func (s *EnclaveStore) Has(label string) bool {
	name, err := fileName(label)
	if err != nil {
		return false
	}
	dir, ok, err := s.openDir()
	if err != nil || !ok {
		return false
	}
	defer dir.Close()
	exists, err := enclaveFileExistsAt(dir, name)
	return err == nil && exists
}

// Delete removes the key file; the Secure Enclave key is gone with its blob.
func (s *EnclaveStore) Delete(label string) error {
	name, err := fileName(label)
	if err != nil {
		return err
	}
	dir, ok, err := s.openDir()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	defer dir.Close()
	if err := removeEnclaveFileAt(dir, name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("enclave store: %w", err)
	}
	return nil
}

// UpdateTag rewrites the record of a key; blob and public half stay. A
// failed or oversized write leaves the old file in place.
func (s *EnclaveStore) UpdateTag(label string, tag []byte) error {
	name, err := fileName(label)
	if err != nil {
		return err
	}
	dir, ok, err := s.openDir()
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	defer dir.Close()
	file, err := readEnclaveFile(dir, label)
	if err != nil {
		return err
	}
	file.Tag = string(tag)
	return writeEnclaveFile(dir, name, file, true)
}

// Sign signs digest with the key under label under the record its file
// carries now. The Manager never uses it on a RoutedBackend: it calls
// SignAuthorized through SignIn.
func (s *EnclaveStore) Sign(label string, digest []byte) ([]byte, error) {
	return s.sign(label, digest, nil)
}

// SignAuthorized signs only if the key file still carries exactly the
// authorized record (review r3: a file swapped after authorization for the
// same blob under user_presence false must not skip the presence probe).
func (s *EnclaveStore) SignAuthorized(label string, digest []byte, authorized Record) ([]byte, error) {
	return s.sign(label, digest, &authorized)
}

// sign: the record's user_presence decides whether the helper must find
// presence enforced and ask for it; the public half of the blob must equal
// the stored one.
func (s *EnclaveStore) sign(label string, digest []byte, authorized *Record) ([]byte, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	if len(digest) != DigestSize {
		return nil, ValidateDigest(digest)
	}
	file, err := s.read(label)
	if err != nil {
		return nil, err
	}
	rec, problem := DecodeRecord([]byte(file.Tag))
	if problem != "" || rec.Store != StoreEnclave {
		return nil, untrusted(label, "the stored record is unreadable or not an enclave record; nothing was signed")
	}
	if authorized != nil {
		want, wantErr := EncodeRecord(*authorized)
		have, haveErr := EncodeRecord(rec)
		if wantErr != nil || haveErr != nil || !bytes.Equal(want, have) {
			return nil, untrusted(label, "the key file's record changed after it was authorized; nothing was signed")
		}
	}
	presence := enclavePresenceNone
	if rec.UserPresence {
		presence = enclavePresenceRequired
	}
	reason := enclaveReason(label, digest, s.Describe)
	req := EnclaveRequest{Op: "sign", Blob: file.Blob, Digest: digest, Presence: presence, Reason: reason}
	if s.NonInteractive {
		req.Interaction = "none"
	}
	resp, err := s.Helper.Call(req, rec.UserPresence && !s.NonInteractive)
	if err != nil {
		return nil, enclaveError("sign", err)
	}
	if !bytes.Equal(resp.Point, file.Point) {
		return nil, untrusted(label, "the key blob does not belong to the stored public key; nothing was emitted")
	}
	if len(resp.DER) == 0 {
		return nil, untrusted(label, "the helper returned no signature")
	}
	return resp.DER, nil
}

// enclaveError keeps a helper OSStatus in the Security.framework status
// space (so Translate names it: errSecInteractionNotAllowed,
// errSecUserCanceled, ...), and reports a broken blob or an unenforced
// presence policy as untrusted output.
func enclaveError(op string, err error) error {
	var helper *EnclaveHelperError
	if !errors.As(err, &helper) {
		return err
	}
	switch helper.Code {
	case "presence_not_enforced", "invalid_blob":
		return &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("Secure Enclave %s: %s", op, helper.Message), Hint: "describe the key; a blob that does not match its record is never used, delete --confirm it and init a fresh key"}
	}
	if helper.Status == 0 {
		return fmt.Errorf("Secure Enclave %s: %s", op, helper.Message)
	}
	return &StatusError{Op: op, Status: helper.Status}
}

func untrusted(label, message string) error {
	return &Refusal{Code: CodeSecurity, Failure: true, Message: fmt.Sprintf("%s: %s", label, message), Hint: "nothing was emitted; describe the key, delete --confirm it if its file was altered and init a fresh key"}
}

// ensureDir creates the store directory if needed and opens it.
func (s *EnclaveStore) ensureDir() (*os.File, error) {
	if s.err != nil {
		return nil, s.err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("enclave store: %w", err)
	}
	dir, err := openEnclaveDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("enclave store: %w", err)
	}
	return dir, nil
}

// read loads one key file through a freshly opened directory.
func (s *EnclaveStore) read(label string) (enclaveFile, error) {
	if _, err := fileName(label); err != nil {
		return enclaveFile{}, err
	}
	dir, ok, err := s.openDir()
	if err != nil {
		return enclaveFile{}, err
	}
	if !ok {
		return enclaveFile{}, ErrNotFound
	}
	defer dir.Close()
	return readEnclaveFile(dir, label)
}

// readEnclaveFile loads and checks one key file in dir: checked on its own
// descriptor (regular, one link, this user's, no group or other bits),
// bounded, one JSON document whose format and label match.
func readEnclaveFile(dir *os.File, label string) (enclaveFile, error) {
	name, err := fileName(label)
	if err != nil {
		return enclaveFile{}, err
	}
	data, err := readEnclaveFileAt(dir, name, enclaveFileMax)
	if errors.Is(err, os.ErrNotExist) {
		return enclaveFile{}, ErrNotFound
	}
	if err != nil {
		return enclaveFile{}, err
	}
	var file enclaveFile
	if err := DecodeSingleJSON(data, &file); err != nil {
		return enclaveFile{}, fmt.Errorf("%s: %w", name, err)
	}
	if file.Format != EnclaveFileFormat || file.Label != label || len(file.Blob) == 0 {
		return enclaveFile{}, fmt.Errorf("%s: format or label does not match its name", name)
	}
	return file, nil
}

// writeEnclaveFile publishes file under name atomically; a file the reader
// would refuse as oversized is refused before anything is written.
func writeEnclaveFile(dir *os.File, name string, file enclaveFile, replace bool) error {
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	if len(data) > enclaveFileMax {
		return &Refusal{Code: CodeInvalidMeta, Message: fmt.Sprintf("the key file would be %d bytes, the limit is %d; nothing was written", len(data), enclaveFileMax), Hint: "shorten the description or meta values"}
	}
	if err := writeEnclaveFileAt(dir, name, data, replace); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		return fmt.Errorf("enclave store: %w", err)
	}
	return nil
}

// RoutedBackend serves the keychain and the Secure Enclave store as one
// Backend: create goes by the requested store and a signature goes to the
// store the authorized record names (SignIn). A label present in both stores,
// or a record whose declared store is not the store it was read from, is
// listed with a problem so the Manager never operates on it.
type RoutedBackend struct {
	Keychain Backend
	Enclave  *EnclaveStore
}

// Serves implements StoreServer: the keychain always, the enclave store when
// its helper resolved.
func (r RoutedBackend) Serves(store StoreKind) bool {
	switch store {
	case StoreKeychain:
		return true
	case StoreEnclave:
		return r.Enclave.Serves()
	}
	return false
}

func (r RoutedBackend) Create(opts CreateOptions) (Item, error) {
	if opts.Store == StoreEnclave {
		return r.Enclave.Create(opts)
	}
	return r.Keychain.Create(opts)
}

// declaredElsewhere reports a readable schema-2 record that names another
// store than the one its item came from (review F1: a keychain item that
// claims store enclave must never be signed as if it were one).
func declaredElsewhere(item Item, from StoreKind) bool {
	rec, problem := DecodeRecord(item.Tag)
	return problem == "" && rec.Schema == SchemaVersion && rec.Store != from
}

func (r RoutedBackend) List() ([]Item, error) {
	keychain, err := r.Keychain.List()
	if err != nil {
		return nil, err
	}
	enclave, err := r.Enclave.List()
	if err != nil {
		return nil, err
	}
	mark := func(items []Item, from StoreKind) {
		for i, item := range items {
			if item.Problem == "" && declaredElsewhere(item, from) {
				items[i] = Item{Label: item.Label, Problem: fmt.Sprintf("record declares another store than %s, where it lives", from)}
			}
		}
	}
	keychain = append([]Item{}, keychain...)
	mark(keychain, StoreKeychain)
	mark(enclave, StoreEnclave)
	inKeychain := map[string]bool{}
	for _, item := range keychain {
		inKeychain[item.Label] = true
	}
	items := keychain
	for _, item := range enclave {
		if inKeychain[item.Label] {
			item = Item{Label: item.Label, Problem: "label exists in both the keychain and the enclave store"}
			for i := range items {
				if items[i].Label == item.Label {
					items[i] = Item{Label: item.Label, Problem: item.Problem}
				}
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func (r RoutedBackend) Delete(label string) error {
	if r.Enclave.Has(label) {
		return r.Enclave.Delete(label)
	}
	return r.Keychain.Delete(label)
}

func (r RoutedBackend) UpdateTag(label string, tag []byte) error {
	if r.Enclave.Has(label) {
		return r.Enclave.UpdateTag(label, tag)
	}
	return r.Keychain.UpdateTag(label, tag)
}

// Sign without a store goes by where the label lives; the Manager never uses
// it on a RoutedBackend, it calls SignIn with the authorized record's store.
func (r RoutedBackend) Sign(label string, digest []byte) ([]byte, error) {
	if r.Enclave.Has(label) {
		return r.Enclave.Sign(label, digest)
	}
	return r.Keychain.Sign(label, digest)
}

// SignIn implements StoreSigner: the store and, for the enclave, the whole
// policy come from the authorized record.
func (r RoutedBackend) SignIn(authorized Record, label string, digest []byte) ([]byte, error) {
	switch authorized.Store {
	case StoreEnclave:
		return r.Enclave.SignAuthorized(label, digest, authorized)
	case StoreKeychain:
		return r.Keychain.Sign(label, digest)
	}
	return nil, fmt.Errorf("no store %q to sign in", authorized.Store)
}
