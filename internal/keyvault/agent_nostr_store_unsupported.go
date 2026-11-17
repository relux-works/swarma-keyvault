//go:build !darwin || !cgo

package keyvault

type AgentNostrSecurityStore struct{}

func NewAgentNostrSecurityStore() *AgentNostrSecurityStore { return &AgentNostrSecurityStore{} }

func (*AgentNostrSecurityStore) ListAgentNostr() ([]AgentNostrItem, error) {
	return nil, &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
}

func (*AgentNostrSecurityStore) SelectAgentNostr(string) (AgentNostrSelection, error) {
	return nil, &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
}

func (*AgentNostrSecurityStore) AddAgentNostr(string, []byte, []byte) (bool, error) {
	return false, &AgentNostrFailure{Code: AgentNostrCodeUnavailable}
}
