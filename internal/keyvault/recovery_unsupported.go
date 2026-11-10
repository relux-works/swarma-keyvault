//go:build !darwin || !cgo

package keyvault

func verifyRecoveryCode(int, []byte) error                             { return errUnsupported }
func (*NostrSecurityStore) RecoveryList() ([]RecoveryRecord, error)    { return nil, errUnsupported }
func (*NostrSecurityStore) RecoveryStore(RecoveryRecord, []byte) error { return errUnsupported }
func (*NostrSecurityStore) RecoveryDelete(RecoveryRecord) error        { return errUnsupported }
func (*NostrSecurityStore) NostrDelete(NostrRecord) error              { return errUnsupported }
