package reviewedsession

// inputPaths are LOAD instructions only. This parser opens no paths and cannot
// create an admitted/frozen plan. A future loader must enforce regular-file,
// limit+1 and total-loaded-size bounds before owning the bytes exactly once.
type inputPaths struct {
	profile                                                 profile
	payload, spec, subjectAttestation, publisherAttestation string
}

func parseInput(raw []byte) (inputPaths, error) {
	var result inputPaths
	m, err := strictObject(raw, inputMax)
	if err != nil {
		return result, err
	}
	if err := closed(m, "schema", "profile", "inputs"); err != nil {
		return result, err
	}
	if m["schema"] != "kv-reviewed-input/1" {
		return result, errSchema
	}
	p, err := text(m, "profile")
	if err != nil {
		return result, err
	}
	result.profile = profile(p)
	if !result.profile.included() {
		return inputPaths{}, errSchema
	}
	paths, ok := m["inputs"].(map[string]any)
	if !ok {
		return inputPaths{}, errSchema
	}
	if result.profile != muGrantMac {
		if err := closed(paths, "payload_path"); err != nil {
			return inputPaths{}, err
		}
		result.payload, err = explicitPath(paths, "payload_path")
	} else {
		if err := closed(paths, "spec_path", "subject_attestation_path", "publisher_attestation_path"); err != nil {
			return inputPaths{}, err
		}
		for name, dest := range map[string]*string{
			"spec_path": &result.spec, "subject_attestation_path": &result.subjectAttestation, "publisher_attestation_path": &result.publisherAttestation,
		} {
			*dest, err = explicitPath(paths, name)
			if err != nil {
				return inputPaths{}, err
			}
		}
	}
	if err != nil {
		return inputPaths{}, err
	}
	return result, nil
}

func explicitPath(m map[string]any, name string) (string, error) {
	s, err := text(m, name)
	if err != nil || s == "-" {
		return "", errSchema
	}
	return s, nil
}
