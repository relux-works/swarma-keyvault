// Package namecoinlocalgate provides process-owned kernel exclusion for native
// Namecoin state operations. It carries no application traffic.
package namecoinlocalgate

import "errors"

// These fixed refusals contain no operating-system or request data.
var (
	ErrAccountBusy = errors.New("account_busy")
	ErrOperational = errors.New("local_gate_unavailable")
)
