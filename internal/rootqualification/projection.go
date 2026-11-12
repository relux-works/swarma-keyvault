package rootqualification

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrProjection = errors.New("public ACL projection refused")

// Projection is observation, never a root-storage allowlist or permission.
// Native multiplicity, order, unknown authorization values and missing/opaque
// subjects are retained. Receipt parsing must not promote them to authority.
type Projection struct {
	OwnerUID  uint32          `json:"owner_uid"`
	OwnerGID  uint32          `json:"owner_gid"`
	OwnerType uint32          `json:"owner_type"`
	ACLs      []ACLProjection `json:"acls"`
}

type ACLProjection struct {
	AuthorizationNamesState string                  `json:"authorization_names_state"`
	Authorizations          []string                `json:"authorizations"`
	AuthorizationNumbers    []uint32                `json:"authorization_numbers"`
	ContentsState           string                  `json:"contents_state"`
	DescriptionState        string                  `json:"description_state"`
	Description             string                  `json:"description"`
	PromptBits              uint32                  `json:"prompt_bits"`
	RawPromptState          string                  `json:"raw_prompt_state"`
	RawPromptVersion        uint32                  `json:"raw_prompt_version"`
	RawPromptFlags          uint32                  `json:"raw_prompt_flags"`
	ApplicationsState       string                  `json:"applications_state"`
	Applications            []ApplicationProjection `json:"applications"`
}

type ApplicationProjection struct {
	RequirementState string `json:"requirement_state"`
	Requirement      []byte `json:"requirement"`
	RequirementText  string `json:"requirement_text"`
}

type projectionReader struct{ *bytes.Reader }

func (p projectionReader) u32() (uint32, error) {
	var b [4]byte
	if _, e := io.ReadFull(p, b[:]); e != nil {
		return 0, ErrProjection
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
func (p projectionReader) count() (int, error) {
	n, e := p.u32()
	if e != nil || n > 64 {
		return 0, ErrProjection
	}
	return int(n), nil
}
func (p projectionReader) field(max uint32) ([]byte, error) {
	n, e := p.u32()
	if e != nil || n > max || uint64(n) > uint64(p.Len()) {
		return nil, ErrProjection
	}
	b := make([]byte, int(n))
	_, e = io.ReadFull(p, b)
	if e != nil {
		return nil, ErrProjection
	}
	return b, nil
}
func (p projectionReader) text(max uint32) (string, error) {
	b, e := p.field(max)
	if e != nil || !utf8.Valid(b) {
		return "", ErrProjection
	}
	return string(b), nil
}
func (p projectionReader) state(names ...string) (string, error) {
	n, e := p.u32()
	if e != nil || uint64(n) >= uint64(len(names)) {
		return "", ErrProjection
	}
	return names[n], nil
}

// DecodeNativeProjection reads KVQP1's closed bounded public frame. All scalar
// fields/lengths are BE32, followed by exact field bytes; no trailing data.
// Applications distinguish NULL, explicitly empty and unreadable lists.
func DecodeNativeProjection(raw []byte) (Projection, error) {
	var result Projection
	if len(raw) > 1048576 || !bytes.HasPrefix(raw, []byte("KVQP1")) {
		return result, ErrProjection
	}
	p := projectionReader{bytes.NewReader(raw[5:])}
	var err error
	if result.OwnerUID, err = p.u32(); err != nil {
		return Projection{}, err
	}
	if result.OwnerGID, err = p.u32(); err != nil {
		return Projection{}, err
	}
	if result.OwnerType, err = p.u32(); err != nil {
		return Projection{}, err
	}
	n, err := p.count()
	if err != nil {
		return Projection{}, err
	}
	result.ACLs = make([]ACLProjection, n)
	for i := range result.ACLs {
		a := &result.ACLs[i]
		a.AuthorizationNamesState, err = p.state("readable", "unreadable")
		if err != nil {
			return Projection{}, err
		}
		count, e := p.count()
		if e != nil {
			return Projection{}, e
		}
		a.Authorizations = make([]string, count)
		if a.AuthorizationNamesState == "unreadable" && count != 0 {
			return Projection{}, ErrProjection
		}
		for j := range a.Authorizations {
			a.Authorizations[j], e = p.text(1024)
			if e != nil {
				return Projection{}, e
			}
		}
		count, e = p.count()
		if e != nil {
			return Projection{}, e
		}
		a.AuthorizationNumbers = make([]uint32, count)
		for j := range a.AuthorizationNumbers {
			a.AuthorizationNumbers[j], e = p.u32()
			if e != nil {
				return Projection{}, e
			}
		}
		a.ContentsState, e = p.state("readable", "unreadable")
		if e != nil {
			return Projection{}, e
		}
		a.DescriptionState, e = p.state("null", "present", "unreadable")
		if e != nil {
			return Projection{}, e
		}
		a.Description, e = p.text(32768)
		if e != nil {
			return Projection{}, e
		}
		a.PromptBits, e = p.u32()
		if e != nil || a.PromptBits > 65535 {
			return Projection{}, ErrProjection
		}
		a.RawPromptState, e = p.state("readable", "unreadable")
		if e != nil {
			return Projection{}, e
		}
		a.RawPromptVersion, e = p.u32()
		if e != nil {
			return Projection{}, e
		}
		a.RawPromptFlags, e = p.u32()
		if e != nil {
			return Projection{}, e
		}
		if a.RawPromptState == "unreadable" && (a.RawPromptVersion != 0 || a.RawPromptFlags != 0) {
			return Projection{}, ErrProjection
		}
		a.ApplicationsState, e = p.state("null", "present", "unreadable")
		if e != nil {
			return Projection{}, e
		}
		count, e = p.count()
		if e != nil {
			return Projection{}, e
		}
		a.Applications = make([]ApplicationProjection, count)
		if a.ApplicationsState != "present" && count != 0 {
			return Projection{}, ErrProjection
		}
		if a.DescriptionState != "present" && a.Description != "" {
			return Projection{}, ErrProjection
		}
		if a.ContentsState == "unreadable" && (a.DescriptionState != "unreadable" || a.ApplicationsState != "unreadable" || a.PromptBits != 0) {
			return Projection{}, ErrProjection
		}
		if a.ContentsState == "readable" && (a.DescriptionState == "unreadable" || a.ApplicationsState == "unreadable") {
			return Projection{}, ErrProjection
		}
		for j := range a.Applications {
			app := &a.Applications[j]
			app.RequirementState, e = p.state("present", "missing", "unreadable", "unexpected-type")
			if e != nil {
				return Projection{}, e
			}
			app.Requirement, e = p.field(65536)
			if e != nil {
				return Projection{}, e
			}
			app.RequirementText, e = p.text(65536)
			if e != nil {
				return Projection{}, e
			}
			if app.RequirementState == "present" && (len(app.Requirement) == 0 || app.RequirementText == "") {
				return Projection{}, ErrProjection
			}
			if app.RequirementState != "present" && (len(app.Requirement) != 0 || app.RequirementText != "") {
				return Projection{}, ErrProjection
			}
		}
	}
	if p.Len() != 0 {
		return Projection{}, ErrProjection
	}
	return result, nil
}
