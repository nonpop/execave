package proxy

import "net"

// Export unexported functions for testing.

func (p *Proxy) Addr() net.Addr {
	return p.addr()
}
