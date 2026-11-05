// Minimal SOCKS5 CONNECT dialer (RFC 1928, no-auth). Replaces the former
// `curl --socks5-hostname` invocation in Verify: the target hostname is
// resolved by the proxy side, so tunnel routing rules apply to domains —
// and kgate no longer shells out to curl (removed from ipk Depends).
package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// socksConnect dials proxyAddr and issues CONNECT to host:port; returns the
// tunnelled connection ready for TLS.
func socksConnect(ctx context.Context, proxyAddr, host string, port int) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	// greet: version 5, one method (no auth)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greet: %w", err)
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greet reply: %w", err)
	}
	if hdr[0] != 5 || hdr[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5: сервер выбрал метод %d вместо no-auth", hdr[1])
	}
	// CONNECT with ATYP=domain: the proxy resolves the hostname
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(port))
	req = append(req, portB[:]...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if rep[0] != 5 || rep[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks5: код ошибки %d (rep)", rep[1])
	}
	// skip the bound address so the connection is ready for payload
	switch rep[3] {
	case 1: // IPv4
		skip := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, err
		}
		skip := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	case 4: // IPv6
		skip := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: неизвестный ATYP %d", rep[3])
	}
	return conn, nil
}
