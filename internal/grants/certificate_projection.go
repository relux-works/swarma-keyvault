package grants

import (
	"errors"
	"time"
)

var errBadLifecycleReference = errors.New("bad-lifecycle-reference")

// These projections prove only closed canonical representation and internal
// structural consistency. They are never verified grants, active authorities,
// enrolled identities, durable reservations or provider capabilities.
type entryProjection struct {
	entryID, action string
	createTarget    *createTargetProjection
	deleteTarget    *deleteGrantTargetProjection
	uses            []*useProjection
}
type certificateProjection struct {
	raw                  []byte
	certificateID        string
	issuer               *issuerProjection
	subject              *subjectProjection
	audience             *audienceProjection
	notBefore, expiresAt time.Time
	supersedes           []string
	cycles               []*cycleProjection
	entries              []*entryProjection
}

func boundedWireArray(node *wireValue, maximum int, required bool) ([]*wireValue, error) {
	if node == nil || node.kind != arrayValue {
		return nil, errBadSchema
	}
	if len(node.elements) > maximum {
		return nil, errInputLimit
	}
	if required && len(node.elements) == 0 {
		return nil, errBadSchema
	}
	return node.elements, nil
}
func parseEntryNode(node *wireValue) (*entryProjection, error) {
	f, err := closedObject(node, "entry_id", "action", "target", "uses")
	if err != nil {
		return nil, err
	}
	if f["entry_id"] == nil || f["entry_id"].kind != stringValue || f["action"] == nil || f["action"].kind != stringValue {
		return nil, errBadSchema
	}
	id, err := parseOpaqueID(f["entry_id"].text)
	if err != nil {
		return nil, err
	}
	action := f["action"].text
	if !oneOf(action, "repository.create", "repository.delete") {
		return nil, errBadSchema
	}
	value := &entryProjection{entryID: id, action: action}
	if action == "repository.create" {
		value.createTarget, err = parseCreateTargetNode(f["target"])
	} else {
		value.deleteTarget, err = parseDeleteGrantTargetNode(f["target"])
	}
	if err != nil {
		return nil, err
	}
	nodes, err := boundedWireArray(f["uses"], 16, true)
	if err != nil {
		return nil, err
	}
	useIDs := make(map[string]bool, len(nodes))
	cycles := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		use, e := parseUseNode(node)
		if e != nil {
			return nil, e
		}
		if useIDs[use.operationUseID] || cycles[use.cycleID] {
			return nil, errBadSchema
		}
		useIDs[use.operationUseID] = true
		cycles[use.cycleID] = true
		value.uses = append(value.uses, use)
	}
	return value, nil
}
func parseCertificateProjection(raw []byte) (*certificateProjection, error) {
	node, err := parseCanonical(raw, certificateWire)
	if err != nil {
		return nil, err
	}
	f, err := closedObject(node, "type", "certificate_id", "issuer", "subject", "audience", "not_before", "expires_at", "supersedes", "cycles", "entries")
	if err != nil {
		return nil, err
	}
	kind, err := memberText(node, "type")
	if err != nil || kind != "grants-certificate-1" {
		return nil, errBadSchema
	}
	subject, err := parseSubjectNode(f["subject"])
	if err != nil {
		return nil, err
	}
	value, err := parseCertificateBody(raw, f)
	if err != nil {
		return nil, err
	}
	value.subject = subject
	return value, nil
}

// Profile-neutral fields are used only after a caller enforces its own closed
// schema and distinct subject. No Matrix subject or synthetic key is supplied.
func parseCertificateBody(raw []byte, f map[string]*wireValue) (*certificateProjection, error) {
	for _, name := range []string{"type", "certificate_id", "not_before", "expires_at"} {
		if f[name] == nil || f[name].kind != stringValue {
			return nil, errBadSchema
		}
	}
	id, err := parseOpaqueID(f["certificate_id"].text)
	if err != nil {
		return nil, err
	}
	value := &certificateProjection{certificateID: id}
	value.issuer, err = parseIssuerNode(f["issuer"])
	if err != nil {
		return nil, err
	}
	value.audience, err = parseAudienceNode(f["audience"])
	if err != nil {
		return nil, err
	}
	value.notBefore, err = parseWireTime(f["not_before"].text)
	if err != nil {
		return nil, err
	}
	value.expiresAt, err = parseWireTime(f["expires_at"].text)
	if err != nil {
		return nil, err
	}
	if err := ValidateInterval(value.notBefore, value.expiresAt); err != nil {
		return nil, err
	}
	predecessors, err := boundedWireArray(f["supersedes"], 16, false)
	if err != nil {
		return nil, err
	}
	seenPredecessors := make(map[string]bool, len(predecessors))
	for _, node := range predecessors {
		if node == nil || node.kind != stringValue {
			return nil, errBadSchema
		}
		predecessor, e := parseOpaqueID(node.text)
		if e != nil {
			return nil, e
		}
		if predecessor == id || seenPredecessors[predecessor] {
			return nil, errBadLifecycleReference
		}
		seenPredecessors[predecessor] = true
		value.supersedes = append(value.supersedes, predecessor)
	}
	cycleNodes, err := boundedWireArray(f["cycles"], 16, true)
	if err != nil {
		return nil, err
	}
	cycles := make(map[string]bool, len(cycleNodes))
	for _, node := range cycleNodes {
		cycle, e := parseCycleNode(node)
		if e != nil {
			return nil, e
		}
		if cycles[cycle.cycleID] {
			return nil, errBadSchema
		}
		cycles[cycle.cycleID] = true
		value.cycles = append(value.cycles, cycle)
	}
	entryNodes, err := boundedWireArray(f["entries"], 16, true)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]*entryProjection, len(entryNodes))
	usedCycles := make(map[string]bool, len(cycles))
	totalUses := 0
	for _, node := range entryNodes {
		entry, e := parseEntryNode(node)
		if e != nil {
			return nil, e
		}
		if _, exists := entries[entry.entryID]; exists {
			return nil, errBadSchema
		}
		totalUses += len(entry.uses)
		if totalUses > 256 {
			return nil, errInputLimit
		}
		for _, use := range entry.uses {
			if !cycles[use.cycleID] {
				return nil, errBadSchema
			}
			usedCycles[use.cycleID] = true
		}
		entries[entry.entryID] = entry
		value.entries = append(value.entries, entry)
	}
	if len(usedCycles) != len(cycles) {
		return nil, errBadSchema
	}
	for _, entry := range value.entries {
		if entry.action != "repository.delete" {
			continue
		}
		paired := entries[entry.deleteTarget.pairedCreateEntry]
		if paired == nil || paired.action != "repository.create" || paired.createTarget == nil || paired.createTarget.visibility != "private" || paired.createTarget.organization != entry.deleteTarget.organization || paired.createTarget.name != entry.deleteTarget.name {
			return nil, errBadSchema
		}
		// Entry parsing already forbids multiple uses of one cycle. Count again
		// explicitly so this invariant remains visible at the pairing boundary.
		for _, use := range entry.uses {
			matches := 0
			for _, createUse := range paired.uses {
				if createUse.cycleID == use.cycleID {
					matches++
				}
			}
			if matches != 1 {
				return nil, errBadSchema
			}
		}
	}
	value.raw = append([]byte(nil), raw...)
	return value, nil
}
