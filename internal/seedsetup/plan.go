package seedsetup

import "fmt"

type publicPlan struct {
	Schema           string `json:"schema"`
	Advisory         bool   `json:"advisory"`
	NostrIdentity    string `json:"nostr_identity"`
	NamecoinIdentity string `json:"namecoin_identity"`
	Version          int    `json:"version"`
	NostrVersion     int    `json:"nostr_version"`
	NamecoinVersion  int    `json:"namecoin_version"`
	Group            string `json:"group"`
	NostrRecord      string `json:"nostr_record"`
	NamecoinRecord   string `json:"namecoin_record"`
}

func (t publicTarget) group() string {
	return fmt.Sprintf("%s/recovery@%d", t.NostrIdentity, t.Version)
}
func (t publicTarget) nostr() string {
	return fmt.Sprintf("%s/nostr@%d", t.NostrIdentity, t.NostrVersion)
}
func (t publicTarget) namecoin() string {
	return fmt.Sprintf("%s/namecoin@%d", t.NamecoinIdentity, t.NamecoinVersion)
}

// acceptPlan binds an advisory response to independently supplied identities
// and explicit generations. An omitted generation may be selected only by this
// read-only planning response, never by a later mutation receipt or retry.
func acceptPlan(raw []byte, c Config) (publicTarget, error) {
	var zero publicTarget
	var p publicPlan
	if decode(raw, &p) != nil {
		return zero, refused("plan_schema")
	}
	t := publicTarget{p.NostrIdentity, p.NamecoinIdentity, p.Version, p.NostrVersion, p.NamecoinVersion}
	if t.validate() != nil || !validIdentity(c.NostrIdentity) || !validIdentity(c.NamecoinIdentity) || p.Schema != "keyvault-recovery-plan/1" || !p.Advisory || t.NostrIdentity != c.NostrIdentity || t.NamecoinIdentity != c.NamecoinIdentity || p.Group != t.group() || p.NostrRecord != t.nostr() || p.NamecoinRecord != t.namecoin() {
		return zero, refused("plan_binding")
	}
	for _, v := range [][2]int{{c.Version, t.Version}, {c.NostrVersion, t.NostrVersion}, {c.NamecoinVersion, t.NamecoinVersion}} {
		if v[0] < 0 || v[0] > 2147483647 || v[0] != 0 && v[0] != v[1] {
			return zero, refused("plan_generation")
		}
	}
	return t, nil
}

func (t publicTarget) mutationArguments() []string {
	return []string{"--nostr-identity", t.NostrIdentity, "--namecoin-identity", t.NamecoinIdentity, "--version", fmt.Sprint(t.Version), "--nostr-version", fmt.Sprint(t.NostrVersion), "--namecoin-version", fmt.Sprint(t.NamecoinVersion)}
}
