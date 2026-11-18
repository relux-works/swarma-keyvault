//go:build !darwin || !cgo

package keyvault

type agentNostrUnavailablePrivate struct{}

func NewAgentNostrPrivate() AgentNostrPrivate { return agentNostrUnavailablePrivate{} }

func (agentNostrUnavailablePrivate) CreateWrap() (AgentNostrWrap, error) {
	return AgentNostrWrap{}, &AgentNostrPrivateError{Code: "unavailable"}
}

func (agentNostrUnavailablePrivate) UnwrapAgentNostr(AgentNostrEnvelope) ([]byte, error) {
	return nil, &AgentNostrPrivateError{Code: "unavailable"}
}
