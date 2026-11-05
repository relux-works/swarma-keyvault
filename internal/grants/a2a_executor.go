package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ErrA2AConfig = errors.New("a2a-executor-config-invalid")
var ErrA2AProjection = errors.New("a2a-event-projection-unavailable")

// A2AExecutor is built from separately installed public trust configuration,
// never event/request fields. Same-UID configuration replacement is outside
// this boundary. It does not create keys, export credentials or install tools.
type A2AExecutor struct {
	receiver                                                          *A2AReceiver
	observation                                                       A2AObservationContext
	state                                                             A2AStateConfig
	a2aPath, a2aHash, identity, connection, configDir, ghPath, ghHash string
	now                                                               func() time.Time
}

// ParseA2AExecutor checks the closed public configuration without opening state,
// inspecting a credential store, invoking a process or contacting a provider.
func ParseA2AExecutor(raw []byte) (*A2AExecutor, error) {
	fields := []string{"type", "owner_mxid", "owner_spki", "owner_spki_sha256", "audience", "room_id", "topic", "thread_root", "declared_from", "declared_to", "key_registry", "key_registry_sha256", "grant_registry", "grant_registry_sha256", "state_dir", "state_epoch", "a2a_path", "a2a_sha256", "a2a_identity", "a2a_connection", "a2a_config_dir", "gh_path", "gh_sha256"}
	n, err := strictA2AJSON(raw, 196608)
	if err != nil {
		return nil, ErrA2AConfig
	}
	o, ok := a2aJSONObject(n, fields)
	if !ok {
		return nil, ErrA2AConfig
	}
	s := map[string]string{}
	for _, k := range fields {
		v, ok := o[k].(string)
		if !ok || v == "" {
			return nil, ErrA2AConfig
		}
		s[k] = v
	}
	if s["type"] != "grants-a2a-executor-config-1" {
		return nil, ErrA2AConfig
	}
	owner, err := a2aBase64(s["owner_spki"], 1024)
	if err != nil || !a2aPinnedBytes(owner, s["owner_spki_sha256"]) {
		return nil, ErrA2AConfig
	}
	keys, err := a2aBase64(s["key_registry"], 16384)
	if err != nil {
		return nil, ErrA2AConfig
	}
	grants, err := a2aBase64(s["grant_registry"], 98304)
	if err != nil {
		return nil, ErrA2AConfig
	}
	r, err := NewA2AReceiver(A2AReceiverConfig{OwnerMXID: s["owner_mxid"], OwnerSPKIDER: owner, Audience: s["audience"], RoomID: s["room_id"], Topic: s["topic"], KeyRegistry: keys, KeyRegistrySHA256: s["key_registry_sha256"], GrantRegistry: grants, GrantRegistrySHA256: s["grant_registry_sha256"]})
	if err != nil {
		return nil, ErrA2AConfig
	}
	for _, k := range []string{"state_dir", "a2a_path", "a2a_config_dir", "gh_path"} {
		if !a2aAbsolutePath(s[k]) {
			return nil, ErrA2AConfig
		}
	}
	for _, k := range []string{"a2a_sha256", "gh_sha256", "state_epoch"} {
		if !a2aHashText(s[k]) {
			return nil, ErrA2AConfig
		}
	}
	if s["state_epoch"] == strings.Repeat("0", 64) {
		return nil, ErrA2AConfig
	}
	for _, k := range []string{"a2a_identity", "a2a_connection", "declared_from", "declared_to"} {
		if !a2aDeclaration(s[k]) {
			return nil, ErrA2AConfig
		}
		if _, err := parseOpaqueID(s[k]); err != nil {
			return nil, ErrA2AConfig
		}
	}
	if !a2aContextText(s["thread_root"], '$') || s["declared_to"] != s["a2a_identity"] {
		return nil, ErrA2AConfig
	}
	e := &A2AExecutor{receiver: r, observation: A2AObservationContext{Audience: s["audience"], RoomID: s["room_id"], Topic: s["topic"], ThreadRoot: s["thread_root"], DeclaredFrom: s["declared_from"], DeclaredTo: s["declared_to"]}, state: A2AStateConfig{Directory: s["state_dir"]}, a2aPath: s["a2a_path"], a2aHash: s["a2a_sha256"], identity: s["a2a_identity"], connection: s["a2a_connection"], configDir: s["a2a_config_dir"], ghPath: s["gh_path"], ghHash: s["gh_sha256"], now: time.Now}
	epoch, _ := hex.DecodeString(s["state_epoch"])
	copy(e.state.Epoch[:], epoch)
	return e, nil
}

func a2aHashText(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func a2aPinnedBytes(raw []byte, hash string) bool {
	sum := sha256.Sum256(raw)
	return a2aHashText(hash) && hex.EncodeToString(sum[:]) == hash
}
func a2aAbsolutePath(s string) bool {
	if len(s) > 4096 || !filepath.IsAbs(s) || filepath.Clean(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// A pin is rechecked on the actual regular file before each invocation. This
// prevents accidental version drift, not a same-user executable/path race.
func checkA2APinnedExecutable(path, hash string) error {
	if !a2aAbsolutePath(path) || !a2aHashText(hash) {
		return ErrA2AConfig
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || before.Mode().Perm()&0022 != 0 {
		return ErrA2AConfig
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != uint32(os.Getuid()) && stat.Uid != 0) || before.Size() > 64<<20 {
		return ErrA2AConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrA2AConfig
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return ErrA2AConfig
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if err != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != hash {
		return ErrA2AConfig
	}
	return nil
}

func (e *A2AExecutor) observe(ctx context.Context, eventID string) (A2AEvent, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || !a2aContextText(eventID, '$') {
		return A2AEvent{}, ErrA2AProjection
	}
	if err := checkA2APinnedExecutable(e.a2aPath, e.a2aHash); err != nil {
		return A2AEvent{}, ErrA2AProjection
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.a2aPath, "--profile", e.connection, "--as", e.identity, "read", e.observation.RoomID, "--event", eventID, "--verification-input", "--json")
	cmd.Env = append(os.Environ(), "A2A_CONFIG_DIR="+e.configDir)
	out, diag := &boundedLocalOutput{maximum: 98304}, &boundedLocalOutput{maximum: 8192}
	cmd.Stdout, cmd.Stderr = out, diag
	cmd.WaitDelay = subprocessWaitDelay
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return A2AEvent{}, ErrA2AProjection
	}
	expected := e.observation
	expected.EventID = eventID
	event, err := ParseA2AObservation(bytes.Clone(out.Bytes()), expected)
	if err != nil {
		return A2AEvent{}, err
	}
	return event, nil
}

// Verify reads one actual projected event and performs public verification only.
// Its descriptive result is not a dispatch capability or a use-state check.
func (e *A2AExecutor) Verify(ctx context.Context, eventID string) (*A2AVerifiedEnvelope, error) {
	event, err := e.observe(ctx, eventID)
	if err != nil {
		return nil, err
	}
	return e.receiver.Verify(event, e.now())
}

// InitializeState is explicit and separate from Verify/Execute. It makes no
// projection/provider call; occupied state is never repaired or replaced.
func (e *A2AExecutor) InitializeState() error {
	if e == nil {
		return ErrA2AConfig
	}
	return InitializeA2AState(e.state, e.receiver)
}

// Execute obtains the event only from one successful pinned process; there is
// no supplied-projection overload. The mediator rechecks all signed inputs and
// durable state. UNKNOWN remains held even if output publication later fails.
func (e *A2AExecutor) Execute(ctx context.Context, eventID string) (*A2AOutcome, error) {
	if e == nil {
		return nil, ErrA2AConfig
	}
	if err := checkA2APinnedExecutable(e.ghPath, e.ghHash); err != nil {
		return nil, ErrA2AConfig
	}
	event, err := e.observe(ctx, eventID)
	if err != nil {
		return nil, err
	}
	m := NewA2AMediator(e.receiver, e.state, e.ghPath)
	m.now = e.now
	m.provider = a2aPinnedGHProvider{path: e.ghPath, hash: e.ghHash}
	// Recheck the pin after the projection subprocess before any state writes.
	if err := checkA2APinnedExecutable(e.ghPath, e.ghHash); err != nil {
		return nil, ErrA2AConfig
	}
	return m.Execute(ctx, event)
}

type a2aPinnedGHProvider struct{ path, hash string }

func (p a2aPinnedGHProvider) create(ctx context.Context, checked *a2aCheckedCreate) ([]byte, error) {
	if err := checkA2APinnedExecutable(p.path, p.hash); err != nil {
		return nil, err
	}
	return (a2aGHProvider{path: p.path}).create(ctx, checked)
}
