// Package muinterop builds the cross-platform interop vectors for multi-use
// owner grants: exact records signed by published test keys, the protected
// facts a receiver supplies, and the expected verdict of every step. Keys
// derive from published seeds; they are test keys only and never touch a
// Keychain or Secure Enclave.
package muinterop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Format is the case file format version.
const Format = "swarma-keyvault/mu-interop-case/1"

// Key is one published test key.
type Key struct {
	Name, ID string
	Seed     []byte
	SPKI     []byte
	priv     *ecdsa.PrivateKey
}

// SeedFor is the published seed of a named test key:
// SHA-256("swarma-keyvault mu-interop seed/1 " + name).
func SeedFor(name string) []byte {
	s := sha256.Sum256([]byte("swarma-keyvault mu-interop seed/1 " + name))
	return s[:]
}

// P256 derives the named P-256 test key from its published seed.
func P256(name string) (*Key, error) {
	seed := SeedFor(name)
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed)
	if err != nil {
		return nil, fmt.Errorf("seed for %s is not a valid scalar: %w", name, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	id, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		return nil, err
	}
	return &Key{Name: name, ID: id, Seed: seed, SPKI: spki, priv: k}, nil
}

// Sign signs a plan and assembles the swarm-envelope/2 record.
func (k *Key) Sign(p *mugrant.Plan) ([]byte, error) {
	d := p.Digest()
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, d[:])
	if err != nil {
		return nil, err
	}
	return mugrant.AssembleNative(p, der)
}

// Pins are the receiver's protected configuration for one case.
type Pins struct {
	GrantRoot       string            `json:"grant_root"`
	Audience        string            `json:"audience"`
	PublisherKey    string            `json:"publisher_key"`
	Room            string            `json:"room"`
	ReceiverMXID    string            `json:"receiver_mxid"`
	SenderMXID      string            `json:"sender_mxid"`
	AgentKey        string            `json:"agent_key"`
	AgentGeneration int64             `json:"agent_generation"`
	Owner           string            `json:"owner"`
	RoomScope       string            `json:"room_scope"`
	Modules         []string          `json:"modules"`
	RegistryOwners  map[string]string `json:"registry_owners"`
}

// Records are the exact signed records, unpadded base64url.
type Records struct {
	Grants               []string `json:"grants"`
	AgentAttestation     string   `json:"agent_attestation"`
	PublisherAttestation string   `json:"publisher_attestation"`
}

// Event is one delivered a2a event: the exact envelope and text bytes.
type Event struct {
	ID       string `json:"event_id"`
	Envelope string `json:"envelope"`
	Text     string `json:"text"`
}

// Step handles one event at one trusted time with one publisher snapshot.
type Step struct {
	Event    string `json:"event"`
	Now      string `json:"now"`
	Snapshot string `json:"snapshot"`
	Expected string `json:"expected"`
}

// Case is one vector file.
type Case struct {
	Format          string  `json:"format"`
	ID              string  `json:"id"`
	Claim           string  `json:"claim"`
	PositiveControl string  `json:"positive_control,omitempty"`
	Pins            Pins    `json:"pins"`
	Records         Records `json:"records"`
	Events          []Event `json:"events"`
	Steps           []Step  `json:"steps"`
}

// B64 is the vector byte encoding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

const (
	senderMXID   = "@requester-agent:interop.invalid"
	receiverMXID = "@receiver:interop.invalid"
	room         = "!interop-room:interop.invalid"
	audience     = "swarma-keyvault-receiver"
	product      = "swarma-platform"
)

// T0 is the trusted time of every positive step.
var T0 = time.Date(2026, 11, 5, 18, 0, 0, 0, time.UTC)

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

type world struct {
	root, other, agent, stranger, publisher *Key
}

func newWorld() (*world, error) {
	w := &world{}
	for _, k := range []struct {
		dst  **Key
		name string
	}{{&w.root, "grant-root"}, {&w.other, "foreign-grant-root"}, {&w.agent, "mac-agent"}, {&w.stranger, "stranger"}, {&w.publisher, "publisher"}} {
		key, err := P256(k.name)
		if err != nil {
			return nil, err
		}
		*k.dst = key
	}
	return w, nil
}

// grantSpec describes one grant built under a root.
type grantSpec struct {
	root     *Key
	use      string
	nb, ex   time.Time
	entries  []mugrant.Entry
	nonceTag string
}

func (w *world) attestations(root *Key) (agent, publisher []byte, err error) {
	nb, ex := T0.Add(-60*24*time.Hour), T0.Add(300*24*time.Hour)
	ap, _, err := mugrant.BuildMacAgentAttestation(root.ID, w.agent.SPKI, senderMXID, 1, nb, ex)
	if err != nil {
		return nil, nil, err
	}
	if agent, err = root.Sign(ap); err != nil {
		return nil, nil, err
	}
	pp, _, err := mugrant.BuildPublisherAttestation(root.ID, w.publisher.SPKI, nb, ex)
	if err != nil {
		return nil, nil, err
	}
	publisher, err = root.Sign(pp)
	return agent, publisher, err
}

func (w *world) grant(s grantSpec) ([]byte, error) {
	agent, publisher, err := w.attestations(s.root)
	if err != nil {
		return nil, err
	}
	nonce := sha256.Sum256([]byte("grant nonce " + s.nonceTag))
	g, err := mugrant.BuildGrant(mugrant.GrantSpec{Issuer: s.root.ID, Subject: w.agent.ID, SubjectMXID: senderMXID,
		SubjectAttestation: agent, PublisherAttestation: publisher, Audience: audience, Entries: s.entries,
		NotBefore: s.nb, Expires: s.ex, Use: s.use, Nonce: nonce[:16]})
	if err != nil {
		return nil, err
	}
	return s.root.Sign(g.Plan())
}

// request builds a message/1 signed by signer (normally the agent).
func (w *world) request(signer *Key, attestationID, action, kind, id string, args map[string]string, text, nonceTag string, at time.Time) ([]byte, error) {
	nonce := sha256.Sum256([]byte("request nonce " + nonceTag))
	r, err := mugrant.BuildRequest(mugrant.RequestSpec{Author: w.agent.ID, AuthorAttestation: attestationID, Audience: audience, Room: room, To: receiverMXID,
		Action: action, Target: mugrant.Target{Kind: kind, ID: id}, Arguments: args, Text: text, Nonce: nonce[:16], IssuedAt: at, Lifetime: 120 * time.Second})
	if err != nil {
		return nil, err
	}
	if signer == w.agent {
		return signer.Sign(r.Plan())
	}
	// A foreign signature over the agent's request: assemble refuses it, so
	// the record is built by hand with the stranger's raw signature.
	return foreignSigned(signer, w.agent.ID, r.Plan())
}

func (w *world) snapshot(at time.Time, entries []mugrant.SnapshotEntry) ([]byte, error) {
	p, err := mugrant.BuildSnapshot(w.publisher.ID, at, entries)
	if err != nil {
		return nil, err
	}
	return w.publisher.Sign(p)
}

func hexDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var errBuild = errors.New("muinterop: case build failed")

// KeyNames lists the published test keys in the vector set.
var KeyNames = []string{"grant-root", "foreign-grant-root", "mac-agent", "stranger", "publisher"}
