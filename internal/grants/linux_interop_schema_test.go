package grants

// Schema copied from the published r7 case format, kept local so these tests
// also compile on main's Mac-only muinterop package. The strict loader refuses
// unknown fields; it never changes a record, expectation, or registry fact.

const linuxInteropFormat = "swarma-keyvault/mu-interop-case/1"

// linuxInteropPins are the receiver's protected configuration for one case.
type linuxInteropPins struct {
	GrantRoot       string                 `json:"grant_root"`
	Audience        string                 `json:"audience"`
	PublisherKey    string                 `json:"publisher_key"`
	Room            string                 `json:"room"`
	ReceiverMXID    string                 `json:"receiver_mxid"`
	SenderMXID      string                 `json:"sender_mxid"`
	AgentKey        string                 `json:"agent_key"`
	AgentGeneration int64                  `json:"agent_generation"`
	Owner           string                 `json:"owner"`
	RoomScope       string                 `json:"room_scope"`
	Modules         []string               `json:"modules"`
	RegistryOwners  map[string]string      `json:"registry_owners"`
	Linux           *linuxInteropLinuxPins `json:"linux,omitempty"`
}

// linuxInteropRecords are the exact signed records, unpadded base64url.
type linuxInteropRecords struct {
	Grants               []string `json:"grants"`
	AgentAttestation     string   `json:"agent_attestation"`
	PublisherAttestation string   `json:"publisher_attestation"`
	// RootRevocations are owner-root-signed revocation/1 snapshots the
	// receiver has in its protected configuration (never via the publisher).
	RootRevocations []string `json:"root_revocations,omitempty"`
}

// linuxInteropEvent is one delivered a2a event: the exact envelope and text bytes.
type linuxInteropEvent struct {
	ID       string `json:"event_id"`
	Envelope string `json:"envelope"`
	Text     string `json:"text"`
}

// linuxInteropStep handles one event at one trusted time with one publisher snapshot.
type linuxInteropStep struct {
	Event         string `json:"event"`
	Now           string `json:"now"`
	Snapshot      string `json:"snapshot"`
	AgentSnapshot string `json:"agent_snapshot,omitempty"`
	Expected      string `json:"expected"`
}

// linuxInteropCase is one vector file.
type linuxInteropCase struct {
	Format          string                        `json:"format"`
	ID              string                        `json:"id"`
	Claim           string                        `json:"claim"`
	PositiveControl string                        `json:"positive_control,omitempty"`
	Pins            linuxInteropPins              `json:"pins"`
	Records         linuxInteropRecords           `json:"records"`
	Registry        *linuxInteropRegistryEvidence `json:"registry,omitempty"`
	Events          []linuxInteropEvent           `json:"events"`
	Steps           []linuxInteropStep            `json:"steps"`
}

// linuxInteropLinuxPins are the receiver's protected configuration for Linux authors.
type linuxInteropLinuxPins struct {
	ServiceRoot        string `json:"service_root"`
	AgentRevocationKey string `json:"agent_revocation_key"`
	AgentMXID          string `json:"agent_mxid"`
	AgentKey           string `json:"agent_key"`
	UID                int64  `json:"uid"`
	RegistrationNumber int64  `json:"registration_number"`
}

// linuxInteropRegistryEvidence is the registry evidence a Linux-author case supplies: the
// attestations it serves by content id and the current active generation.
type linuxInteropRegistryEvidence struct {
	Attestations     map[string]string            `json:"attestations"`
	ActiveGeneration linuxInteropActiveGeneration `json:"active_generation"`
}

// linuxInteropActiveGeneration is the protected current active-generation evidence.
type linuxInteropActiveGeneration struct {
	UID                int64  `json:"uid"`
	Generation         string `json:"generation"`
	RegistrationNumber int64  `json:"registration_number"`
	MasterEpoch        string `json:"master_epoch"`
	Owner              string `json:"owner"`
	Path               string `json:"path"`
}
