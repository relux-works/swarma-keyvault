//go:build darwin || linux

package namecoinjournal

import (
	"golang.org/x/sys/unix"
	"os"
)

// CheckPublicAbsent is read-only under this reservation's SAME kernel gate.
// A failed/unknown check consumes the reservation; removing a collision cannot
// revive it. Close, never the check, releases the private-lifetime guard.
func (r *InitializationReservation) CheckPublicAbsent() (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.used || r.gate == nil {
		return ErrUnknown
	}
	passed := false
	defer func() {
		if !passed {
			r.used = true
		}
	}()
	if err = checkInitializationPublicAbsent(r.home, r.sidecar); err != nil {
		return err
	}
	passed = true
	return nil
}

// Validate held versus named ancestry using the very same owner/mode predicate
// as public journal storage. A missing descendant is no proof if an existing
// parent was renamed, substituted or made unsafe during the read-only walk.
func initializationPrefixValid(links []directoryLink, uid uint32) bool {
	if len(links) == 0 {
		return false
	}
	for i, link := range links {
		var held, named unix.Stat_t
		if unix.Fstat(link.fd, &held) != nil || !directoryOK(link.fd, uid, i >= 3) {
			return false
		}
		if link.parent < 0 {
			if unix.Lstat(link.name, &named) != nil {
				return false
			}
		} else {
			if unix.Fstatat(link.parent, link.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return false
			}
		}
		if !sameFile(&held, &named) || named.Mode&unix.S_IFMT != unix.S_IFDIR {
			return false
		}
	}
	return true
}

func checkInitializationPublicAbsent(home string, sidecar Sidecar) error {
	locator, err := Locator(sidecar.Binding)
	if err != nil {
		return ErrUnknown
	}
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnknown
	}
	links := []directoryLink{{parent: -1, name: home, fd: fd}}
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = unix.Close(links[i].fd)
		}
	}()
	uid := uint32(os.Getuid())
	if !initializationPrefixValid(links, uid) {
		return ErrUnknown
	}
	components := []string{"Library", "Application Support", "mac-keyvault", "namecoin-journal", "v1", locator}
	for i, name := range components {
		if i == len(components)-1 {
			var st unix.Stat_t
			err = unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if err == unix.ENOENT && initializationPrefixValid(links, uid) {
				return nil
			}
			// Every selected existing object is a collision; never inspect/repair it.
			return ErrUnknown
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			// Library/Application Support are existing ancestors, never bootstrapped.
			if e == unix.ENOENT && i >= 2 && initializationPrefixValid(links, uid) {
				return nil
			}
			return ErrUnknown
		}
		links = append(links, directoryLink{parent: fd, name: name, fd: next})
		fd = next
		if !initializationPrefixValid(links, uid) {
			return ErrUnknown
		}
	}
	return ErrUnknown
}
