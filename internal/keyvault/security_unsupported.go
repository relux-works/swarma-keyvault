//go:build !darwin || !cgo

package keyvault

import "fmt"

var errUnsupported = fmt.Errorf("keyvault: Security.framework store requires darwin with cgo")

// SecurityStore is unavailable off macOS or without cgo; every call refuses.
type SecurityStore struct{}

func NewSecurityStore() *SecurityStore { return &SecurityStore{} }

func (s *SecurityStore) Create(CreateOptions) (Item, error) { return Item{}, errUnsupported }

func (s *SecurityStore) List() ([]Item, error) { return nil, errUnsupported }

func (s *SecurityStore) Delete(string) error { return errUnsupported }

func (s *SecurityStore) UpdateTag(string, []byte) error { return errUnsupported }

func (s *SecurityStore) Sign(string, []byte) ([]byte, error) { return nil, errUnsupported }

func (s *SecurityStore) Decrypt(string, []byte) ([]byte, error) { return nil, errUnsupported }

// DisableKeychainUI refuses off macOS: there is no Keychain to protect.
func DisableKeychainUI() error { return errUnsupported }
