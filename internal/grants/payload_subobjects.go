package grants

// These internal projections consume nodes from parseCanonical, and check
// closed subobject shapes and scalar representations only. No projection is
// authenticated enrollment, a verified schedule, a receipt or a capability.
type audienceProjection struct{ deploymentID, executorID string }
type cycleProjection struct{ cycleID, runtime, channel string }
type useProjection struct{ cycleID, operationUseID string }
type resourceTargetText struct{ organization, name string }
type createTargetProjection struct {
	resourceTargetText
	visibility string
}
type deleteGrantTargetProjection struct {
	resourceTargetText
	pairedCreateEntry string
}
type deleteRequestTargetProjection struct {
	resourceTargetText
	repositoryID         uint64
	createOperationUseID string
	createResultDigest   [32]byte
}

func subobjectTexts(node *wireValue, names ...string) (map[string]string, error) {
	fields, err := closedObject(node, names...)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(fields))
	for name, field := range fields {
		if field == nil || field.kind != stringValue {
			return nil, errBadSchema
		}
		values[name] = field.text
	}
	return values, nil
}
func parseAudienceNode(node *wireValue) (*audienceProjection, error) {
	f, err := subobjectTexts(node, "deployment_id", "executor_id")
	if err != nil {
		return nil, err
	}
	deployment, err := parseOpaqueID(f["deployment_id"])
	if err != nil {
		return nil, err
	}
	executor, err := parseOpaqueID(f["executor_id"])
	if err != nil {
		return nil, err
	}
	return &audienceProjection{deploymentID: deployment, executorID: executor}, nil
}
func parseCycleNode(node *wireValue) (*cycleProjection, error) {
	f, err := subobjectTexts(node, "cycle_id", "runtime", "channel")
	if err != nil {
		return nil, err
	}
	id, err := parseOpaqueID(f["cycle_id"])
	if err != nil {
		return nil, err
	}
	if !oneOf(f["runtime"], "claude", "codex") || !oneOf(f["channel"], "encrypted-dm", "encrypted-group") {
		return nil, errBadSchema
	}
	return &cycleProjection{cycleID: id, runtime: f["runtime"], channel: f["channel"]}, nil
}
func parseUseNode(node *wireValue) (*useProjection, error) {
	f, err := subobjectTexts(node, "cycle_id", "operation_use_id")
	if err != nil {
		return nil, err
	}
	cycle, err := parseOpaqueID(f["cycle_id"])
	if err != nil {
		return nil, err
	}
	use, err := parseOpaqueID(f["operation_use_id"])
	if err != nil {
		return nil, err
	}
	return &useProjection{cycleID: cycle, operationUseID: use}, nil
}
func parseCreateTargetNode(node *wireValue) (*createTargetProjection, error) {
	f, err := subobjectTexts(node, "organization", "name", "visibility")
	if err != nil {
		return nil, err
	}
	if f["visibility"] != "private" {
		return nil, errBadSchema
	}
	// The canonical scanner enforces ordinary text bounds. These exact strings
	// acquire provider meaning only through later admitted resource binding.
	return &createTargetProjection{resourceTargetText: resourceTargetText{organization: f["organization"], name: f["name"]}, visibility: f["visibility"]}, nil
}
func parseDeleteGrantTargetNode(node *wireValue) (*deleteGrantTargetProjection, error) {
	f, err := subobjectTexts(node, "organization", "name", "paired_create_entry")
	if err != nil {
		return nil, err
	}
	paired, err := parseOpaqueID(f["paired_create_entry"])
	if err != nil {
		return nil, err
	}
	return &deleteGrantTargetProjection{resourceTargetText: resourceTargetText{organization: f["organization"], name: f["name"]}, pairedCreateEntry: paired}, nil
}
func parseDeleteRequestTargetNode(node *wireValue) (*deleteRequestTargetProjection, error) {
	f, err := subobjectTexts(node, "organization", "name", "repository_id", "create_operation_use_id", "create_result_digest")
	if err != nil {
		return nil, err
	}
	id, err := parsePositiveDecimal(f["repository_id"])
	if err != nil {
		return nil, err
	}
	use, err := parseOpaqueID(f["create_operation_use_id"])
	if err != nil {
		return nil, err
	}
	digest, err := parseWireDigest(f["create_result_digest"])
	if err != nil {
		return nil, err
	}
	return &deleteRequestTargetProjection{resourceTargetText: resourceTargetText{organization: f["organization"], name: f["name"]}, repositoryID: id, createOperationUseID: use, createResultDigest: digest}, nil
}
