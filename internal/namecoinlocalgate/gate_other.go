//go:build !darwin && !linux

package namecoinlocalgate

// Guard is unavailable on unqualified platforms.
type Guard struct{}

func Acquire() (*Guard, error) { return nil, ErrOperational }
func (*Guard) Close() error    { return ErrOperational }
