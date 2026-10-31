//go:build !windows

package tpmsecrets

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive lock on f, returning the unlock function.
func lockFile(f *os.File) (func(), error) {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }, nil
}
