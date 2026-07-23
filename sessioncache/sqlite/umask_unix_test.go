//go:build unix

package sqlite

import "golang.org/x/sys/unix"

func syscallUmask(mask int) int { return unix.Umask(mask) }
