//go:build darwin && cgo

package keyvault

/*
#include <stdlib.h>
#include "security_darwin.h"
*/
import "C"

import (
	"bytes"
	"errors"
	"unsafe"
)

type AgentNostrSecurityStore struct{}

func NewAgentNostrSecurityStore() *AgentNostrSecurityStore { return &AgentNostrSecurityStore{} }

func (*AgentNostrSecurityStore) ListAgentNostr() ([]AgentNostrItem, error) {
	var raw *C.char
	var length C.size_t
	status := int(C.MacKeyVaultAgentNostrList(&raw, &length))
	if status != 0 {
		return nil, agentNostrNativeError(status, false)
	}
	if raw == nil {
		return []AgentNostrItem{}, nil
	}
	defer C.free(unsafe.Pointer(raw))
	if length > 4*1024*1024 {
		return nil, agentNostrFailure(AgentNostrCodeUnavailable, "", "", 0)
	}
	data := C.GoBytes(unsafe.Pointer(raw), C.int(length))
	rows := make([]AgentNostrItem, 0)
	for _, row := range bytes.Split(data, []byte{byte(C.MacKeyVaultRecordSeparator)}) {
		if len(row) == 0 {
			continue
		}
		account, metadata, ok := bytes.Cut(row, []byte{byte(C.MacKeyVaultFieldSeparator)})
		if !ok || len(account) == 0 || len(metadata) == 0 || bytes.Contains(metadata, []byte{byte(C.MacKeyVaultFieldSeparator)}) {
			return nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "", "", 0)
		}
		rows = append(rows, AgentNostrItem{Account: string(account), Metadata: bytes.Clone(metadata)})
	}
	return rows, nil
}

func (*AgentNostrSecurityStore) SelectAgentNostr(account string) (AgentNostrSelection, error) {
	name := C.CString(account)
	defer C.free(unsafe.Pointer(name))
	var selected *C.MacKeyVaultAgentNostrSelection
	var metadata *C.uchar
	var metadataLength C.size_t
	status := int(C.MacKeyVaultAgentNostrSelect(name, &selected, &metadata, &metadataLength))
	if status != 0 {
		return nil, agentNostrNativeError(status, false)
	}
	if selected == nil || metadata == nil || metadataLength == 0 || metadataLength > AgentNostrMaxMetadata {
		if selected != nil {
			C.MacKeyVaultAgentNostrCloseSelection(selected)
		}
		if metadata != nil {
			C.free(unsafe.Pointer(metadata))
		}
		return nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "", "", 0)
	}
	defer C.free(unsafe.Pointer(metadata))
	return &agentNostrSecuritySelection{handle: selected, metadata: C.GoBytes(unsafe.Pointer(metadata), C.int(metadataLength))}, nil
}

func (*AgentNostrSecurityStore) AddAgentNostr(account string, metadata, envelope []byte) (bool, error) {
	if len(metadata) == 0 || len(metadata) > AgentNostrMaxMetadata || len(envelope) == 0 || len(envelope) > AgentNostrMaxEnvelope {
		return false, agentNostrFailure(AgentNostrCodeCorruptRecord, "generate", "", 0)
	}
	name := C.CString(account)
	defer C.free(unsafe.Pointer(name))
	meta := C.CBytes(metadata)
	defer C.free(meta)
	value := C.CBytes(envelope)
	defer func() {
		wipeAgentNostrCBuffer(value, C.size_t(len(envelope)), AgentNostrMaxEnvelope)
		C.free(value)
	}()
	var attempted C.int
	status := int(C.MacKeyVaultAgentNostrCreate(name, (*C.uchar)(meta), C.size_t(len(metadata)), (*C.uchar)(value), C.size_t(len(envelope)), &attempted))
	if status != 0 {
		return attempted != 0, agentNostrNativeError(status, attempted != 0)
	}
	return attempted != 0, nil
}

type agentNostrSecuritySelection struct {
	handle   *C.MacKeyVaultAgentNostrSelection
	metadata []byte
}

func (s *agentNostrSecuritySelection) Metadata() []byte {
	return bytes.Clone(s.metadata)
}

func (s *agentNostrSecuritySelection) LoadEnvelope() ([]byte, []byte, error) {
	if s == nil || s.handle == nil || len(s.metadata) == 0 {
		return nil, nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", "", 0)
	}
	expected := C.CBytes(s.metadata)
	defer C.free(expected)
	var metadata *C.uchar
	var metadataLength C.size_t
	var envelope *C.uchar
	var envelopeLength C.size_t
	status := int(C.MacKeyVaultAgentNostrReadSelected(s.handle, (*C.uchar)(expected), C.size_t(len(s.metadata)), &metadata, &metadataLength, &envelope, &envelopeLength))
	if status != 0 {
		return nil, nil, agentNostrNativeError(status, false)
	}
	if metadata == nil || envelope == nil || metadataLength == 0 || metadataLength > AgentNostrMaxMetadata || envelopeLength == 0 || envelopeLength > AgentNostrMaxEnvelope {
		if metadata != nil {
			C.free(unsafe.Pointer(metadata))
		}
		if envelope != nil {
			wipeAgentNostrCBuffer(unsafe.Pointer(envelope), envelopeLength, AgentNostrMaxEnvelope)
			C.free(unsafe.Pointer(envelope))
		}
		return nil, nil, agentNostrFailure(AgentNostrCodeCorruptRecord, "sign", "", 0)
	}
	defer C.free(unsafe.Pointer(metadata))
	defer func() {
		wipeAgentNostrCBuffer(unsafe.Pointer(envelope), envelopeLength, AgentNostrMaxEnvelope)
		C.free(unsafe.Pointer(envelope))
	}()
	metadataCopy := C.GoBytes(unsafe.Pointer(metadata), C.int(metadataLength))
	envelopeCopy := C.GoBytes(unsafe.Pointer(envelope), C.int(envelopeLength))
	return metadataCopy, envelopeCopy, nil
}

func (s *agentNostrSecuritySelection) Close() {
	if s == nil || s.handle == nil {
		return
	}
	C.MacKeyVaultAgentNostrCloseSelection(s.handle)
	s.handle = nil
	clear(s.metadata)
	s.metadata = nil
}

func agentNostrNativeError(status int, mutationAttempted bool) error {
	switch status {
	case -25299:
		return &AgentNostrFailure{Code: AgentNostrCodeDuplicate}
	case -25300:
		return ErrNotFound
	case -25293, -67050:
		return &AgentNostrFailure{Code: AgentNostrCodeUntrusted}
	case -26275:
		return &AgentNostrFailure{Code: AgentNostrCodeCorruptRecord}
	case -25308:
		return &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
	default:
		if status == int(C.MAC_KEYVAULT_AGENT_NOSTR_TOO_LARGE) {
			return &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
		}
		if mutationAttempted {
			return errors.New("agent Nostr add outcome is unconfirmed")
		}
		return &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
	}
}

func wipeAgentNostrCBuffer(pointer unsafe.Pointer, length C.size_t, maximum int) {
	if pointer == nil || length == 0 || uint64(length) > uint64(maximum) {
		return
	}
	clear(unsafe.Slice((*byte)(pointer), int(length)))
}
