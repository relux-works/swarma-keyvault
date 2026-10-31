//go:build !darwin

package kekclient

import "time"

// awaitExit cannot observe a zombie here without reaping it, so it waits
// the whole grace period: a broker that answered and exits within it keeps
// its exit status, at the cost of that wait on every exchange.
func awaitExit(pid int, grace time.Duration) { time.Sleep(grace) }
