package mugrant

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrRequestSpec refuses a request that cannot be built as a message/1.
var ErrRequestSpec = errors.New("mugrant-request-spec-invalid")

// MaxMessageLifetime is the platform bound for message/1 (ENV §2.1).
const MaxMessageLifetime = 120 * time.Second

// MaxRequestText bounds the human-readable event text the envelope hashes.
const MaxRequestText = 4096

// RequestSpec is one agent request under an owner grant (seams r1 P4).
type RequestSpec struct {
	Author            string // agent p256 key id
	AuthorAttestation string // content id of its Mac agent attestation
	Audience          string // receiver's grant/1 aud
	Room, To          string // actual room id and full receiver MXID
	Action            string // vocabulary-v2 action
	Target            Target
	Arguments         map[string]string
	Text              string // exact event text; body_sha256 binds it
	Nonce             []byte // 16 CSPRNG bytes in production
	IssuedAt          time.Time
	Lifetime          time.Duration
}

// Request is a prepared, unsigned message/1 with its signing plan.
type Request struct {
	plan *Plan
	text string
}

// BuildRequest validates the spec and builds the canonical message/1 body:
// exactly the common members plus author, author_attestation, action, target,
// arguments, room, to and body_sha256. Nothing is signed.
func BuildRequest(spec RequestSpec) (*Request, error) {
	a, _, ok := lookupAction(spec.Action)
	if !ok || spec.Target.Kind != a.TargetKind || !printableToken(spec.Target.ID, 255) {
		return nil, ErrRequestSpec
	}
	if record.ValidateKey(spec.Author) != nil || !record.IsContentID(spec.AuthorAttestation) {
		return nil, ErrRequestSpec
	}
	if !printableToken(spec.Audience, 255) || !validMXID(spec.To) || len(spec.Room) < 2 || spec.Room[0] != '!' || !printableToken(spec.Room, 255) {
		return nil, ErrRequestSpec
	}
	if spec.Text == "" || len(spec.Text) > MaxRequestText || !utf8.ValidString(spec.Text) || len(spec.Nonce) != 16 {
		return nil, ErrRequestSpec
	}
	if spec.Lifetime <= 0 || spec.Lifetime > MaxMessageLifetime || spec.Lifetime%time.Second != 0 || spec.IssuedAt.Location() != time.UTC || spec.IssuedAt.Nanosecond() != 0 {
		return nil, ErrRequestSpec
	}
	if len(spec.Arguments) > 16 {
		return nil, ErrRequestSpec
	}
	keys := make([]string, 0, len(spec.Arguments))
	for k, v := range spec.Arguments {
		if !printableToken(k, 64) || len(v) > 512 || !utf8.ValidString(v) {
			return nil, ErrRequestSpec
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := map[string]any{}
	for _, k := range keys {
		args[k] = spec.Arguments[k]
	}
	sum := sha256.Sum256([]byte(spec.Text))
	body := map[string]any{
		"type": "message/1", "aud": spec.Audience, "nonce": base64.RawURLEncoding.EncodeToString(spec.Nonce),
		"iat": wireTime(spec.IssuedAt), "exp": wireTime(spec.IssuedAt.Add(spec.Lifetime)),
		"author": spec.Author, "author_attestation": spec.AuthorAttestation,
		"action": spec.Action, "target": map[string]any{"kind": spec.Target.Kind, "id": spec.Target.ID},
		"arguments": args, "room": spec.Room, "to": spec.To, "body_sha256": hex.EncodeToString(sum[:]),
	}
	canonical, err := record.Canonical(body)
	if err != nil {
		return nil, ErrRequestSpec
	}
	plan, err := Prepare("message/1", spec.Author, canonical)
	if err != nil {
		return nil, err
	}
	return &Request{plan: plan, text: spec.Text}, nil
}

// Plan returns the request's signing plan (the agent key signs Digest()).
func (r *Request) Plan() *Plan { return r.plan }

// Text returns the exact event text that body_sha256 binds.
func (r *Request) Text() string { return r.text }
