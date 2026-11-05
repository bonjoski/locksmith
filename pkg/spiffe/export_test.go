package spiffe

import "net"

// ParseVsockAddrForTest exports parseVsockAddr for unit testing.
func ParseVsockAddrForTest(addr net.Addr) (uint32, error) {
	return parseVsockAddr(addr)
}
