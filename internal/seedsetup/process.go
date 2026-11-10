package seedsetup

import (
	"bytes"
	"errors"
)

type capped struct {
	bytes.Buffer
	limit int
	full  bool
}

func (b *capped) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.full = true
		return 0, errors.New("child output limit")
	}
	return b.Buffer.Write(p)
}

func childEnv(home string) []string {
	return []string{"HOME=" + home, "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
}
