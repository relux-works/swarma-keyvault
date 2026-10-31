//go:build darwin && cgo && keyvault_gate_regression

package keyvault

// keyvault_gate_regression is reserved for sandbox regression probes. This
// deliberately ungated non-test helper reproduces the source scanner escape.
func sandboxHiddenBackend() Backend { return NewSecurityStore() }
