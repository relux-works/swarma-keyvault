// Command codesignclient is the owned Unix-socket code-identity test fixture.
package main

import (
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-keyvault/internal/codesigntest"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "inherited" {
		fd, err := strconv.Atoi(os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		f := os.NewFile(uintptr(fd), "inherited-socket")
		_, _ = f.Write([]byte{'r'})
		_, _ = f.Read(make([]byte, 1))
		return
	}
	c, err := net.Dial("unix", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	_, _ = c.Read(make([]byte, 1))
	if len(os.Args) == 3 {
		f, err := c.(*net.UnixConn).File()
		if err != nil {
			os.Exit(3)
		}
		fd := f.Fd()
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, 0); errno != 0 {
			os.Exit(4)
		}
		if err := codesigntest.RunHealthy(func() error {
			return syscall.Exec(os.Args[2], []string{os.Args[2], "inherited", strconv.Itoa(int(fd))}, os.Environ())
		}); err != nil {
			os.Exit(5)
		}
	}
}
