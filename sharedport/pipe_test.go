package sharedport

import "syscall"

// socketpairStream returns a connected pair of stream sockets (AF_UNIX,
// SOCK_STREAM). Used by tests as a stand-in for the real TCP fd
// shared_port_server would forward — the receiving net.FileConn cares
// only that the fd is a stream socket, not what protocol family it's in.
func socketpairStream() ([2]int, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{pair[0], pair[1]}, nil
}
