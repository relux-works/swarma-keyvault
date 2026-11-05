package grants

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// ErrMUConfig refuses a multi-use receiver configuration.
var ErrMUConfig = errors.New("mu-receiver-config-refused")

type muConfigFile struct {
	Type                  string            `json:"type"`
	GrantRoot             string            `json:"grant_root"`
	Audience              string            `json:"audience"`
	Grants                []string          `json:"grants"`
	Agents                []muConfigAgent   `json:"agents"`
	PublisherAttestation  string            `json:"publisher_attestation"`
	PublisherKey          string            `json:"publisher_key"`
	PublisherSnapshotPath string            `json:"publisher_snapshot_path"`
	RootRevocations       []string          `json:"root_revocations"`
	StateDir              string            `json:"state_dir"`
	StateEpoch            string            `json:"state_epoch"`
	Owner                 string            `json:"owner"`
	RoomScope             string            `json:"room_scope"`
	Modules               []string          `json:"modules"`
	Paused                []string          `json:"paused"`
	RegistryOwners        map[string]string `json:"registry_owners"`
	TimeAuthoritySeconds  int               `json:"time_authority_seconds"`
	A2A                   muConfigA2A       `json:"a2a"`
	TaskBoard             muConfigBoard     `json:"task_board"`
}

type muConfigAgent struct {
	MXID        string `json:"mxid"`
	Key         string `json:"key"`
	Attestation string `json:"attestation"`
	Generation  int64  `json:"generation"`
}

type muConfigA2A struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Profile   string `json:"profile"`
	Identity  string `json:"identity"`
	ConfigDir string `json:"config_dir"`
	Room      string `json:"room"`
}

type muConfigBoard struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	BoardDir string `json:"board_dir"`
	Parent   string `json:"parent"`
}

// MUService is a configured multi-use receiver.
type MUService struct {
	receiver  *MUReceiver
	state     MUStateConfig
	binding   MUBinding
	projector func(string) (MUEnvelopeEvent, error)
	room      string
}

type muServiceRegistry struct {
	agents map[string]MUMacAgent
	owners map[string]string
}

func (r muServiceRegistry) AttestedKey(m string) (string, bool) {
	a, ok := r.agents[m]
	return a.Key, ok
}
func (r muServiceRegistry) OwnerOf(a string) (string, bool) { o, ok := r.owners[a]; return o, ok }

func muB64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > 65536 {
		return nil, ErrMUConfig
	}
	return b, nil
}

// LoadMUService admits the configuration file through the trust-configuration
// file rules and builds the receiver; nothing is opened or run yet.
func LoadMUService(path string) (*MUService, error) {
	raw, err := LoadA2AExecutorConfig(path)
	if err != nil {
		return nil, ErrMUConfig
	}
	return ParseMUService(raw)
}

// ParseMUService builds the receiver from configuration bytes.
func ParseMUService(raw []byte) (*MUService, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var c muConfigFile
	if err := d.Decode(&c); err != nil || d.More() || c.Type != "mu-receiver-config-1" {
		return nil, ErrMUConfig
	}
	if c.GrantRoot == "" || c.Audience == "" || len(c.Grants) == 0 || len(c.Agents) == 0 || c.PublisherKey == "" || c.Owner == "" || c.RoomScope == "" || len(c.Modules) == 0 {
		return nil, ErrMUConfig
	}
	for _, p := range []string{c.PublisherSnapshotPath, c.StateDir, c.A2A.Path, c.A2A.ConfigDir, c.TaskBoard.Path, c.TaskBoard.BoardDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrMUConfig
		}
	}
	// The audience is one the issuer can mint (printable ASCII, 1 to 255
	// bytes). A production receiver never serves TEST records: the TEST
	// marker is the signed, case-sensitive audience prefix "test:".
	if !mugrant.ValidAudience(c.Audience) || strings.HasPrefix(c.Audience, "test:") {
		return nil, ErrMUConfig
	}
	if c.TimeAuthoritySeconds < 1 || c.TimeAuthoritySeconds > 300 {
		return nil, ErrMUConfig
	}
	epoch, err := hex.DecodeString(c.StateEpoch)
	if err != nil || len(epoch) != 32 {
		return nil, ErrMUConfig
	}
	var grants [][]byte
	for _, g := range c.Grants {
		b, err := muB64(g)
		if err != nil {
			return nil, err
		}
		grants = append(grants, b)
	}
	agents := map[string]MUMacAgent{}
	for _, a := range c.Agents {
		att, err := muB64(a.Attestation)
		if err != nil || a.Generation < 1 || a.Key == "" || a.MXID == "" || agents[a.MXID].Key != "" {
			return nil, ErrMUConfig
		}
		agents[a.MXID] = MUMacAgent{Key: a.Key, Attestation: att, Generation: a.Generation}
	}
	publisher, err := muB64(c.PublisherAttestation)
	if err != nil {
		return nil, err
	}
	var rootSnaps [][]byte
	for _, r := range c.RootRevocations {
		b, err := muB64(r)
		if err != nil {
			return nil, err
		}
		rootSnaps = append(rootSnaps, b)
	}
	if _, err := VerifyRootRevocations(c.GrantRoot, rootSnaps); err != nil {
		return nil, ErrMUConfig
	}
	modules, paused := map[string]bool{}, map[string]bool{}
	for _, m := range c.Modules {
		modules[m] = true
	}
	for _, p := range c.Paused {
		paused[p] = true
	}
	snapshotPath := c.PublisherSnapshotPath
	projector := MUProjector{Path: c.A2A.Path, SHA256: c.A2A.SHA256, Profile: c.A2A.Profile, Identity: c.A2A.Identity, ConfigDir: c.A2A.ConfigDir, Room: c.A2A.Room}.Read
	platform := NewMUPlatform(MUPlatformConfig{GrantRoot: c.GrantRoot, Audience: c.Audience, Grants: grants, Agents: agents,
		Publisher: publisher, PublisherKey: c.PublisherKey, TimeAuthority: time.Duration(c.TimeAuthoritySeconds) * time.Second,
		Snapshot: func() ([]byte, error) { return readMUSnapshot(snapshotPath) }},
		projector)
	state := MUStateConfig{Directory: c.StateDir}
	copy(state.Epoch[:], epoch)
	binding := MUBinding{Audience: c.Audience, GrantRoot: c.GrantRoot}
	root := c.GrantRoot
	receiver := NewMUReceiver(MUReceiverConfig{Binding: binding, State: state, Owner: c.Owner, RoomScope: c.RoomScope, Modules: modules, Paused: paused,
		RootRevocations: func() ([]MURevocation, error) { return VerifyRootRevocations(root, rootSnaps) }, Signers: map[string]bool{c.PublisherKey: true}},
		platform, muServiceRegistry{agents: agents, owners: c.RegistryOwners},
		map[string]MUEffect{"work.assign": TaskBoardAssign{Path: c.TaskBoard.Path, SHA256: c.TaskBoard.SHA256, BoardDir: c.TaskBoard.BoardDir, Parent: c.TaskBoard.Parent}})
	return &MUService{receiver: receiver, state: state, binding: binding, projector: projector, room: c.A2A.Room}, nil
}

// readMUSnapshot reads the publisher's latest snapshot file (owner-private).
func readMUSnapshot(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 || st.Size() > 65536 {
		return nil, ErrMUState
	}
	b := make([]byte, st.Size())
	if _, err := f.Read(b); err != nil {
		return nil, ErrMUState
	}
	return b, nil
}

// InitState creates the receiver's journal in its empty private directory.
func (s *MUService) InitState() error { return InitializeMUState(s.state, s.binding) }

// Execute handles one event end to end. The authenticated sender comes from
// the pinned projection; the platform adapter re-reads the event and requires
// the same sender.
func (s *MUService) Execute(ctx context.Context, eventID string) (*MUOutcome, error) {
	pe, err := s.projector(eventID)
	if err != nil {
		return nil, err
	}
	return s.receiver.Handle(ctx, MUEvent{SenderMXID: pe.Sender, RoomID: s.room, EventID: eventID})
}
