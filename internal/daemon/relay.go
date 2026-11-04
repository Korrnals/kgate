// Tolerant SOCKS relay. Its only purpose is compatibility with the broken
// ndm client (BadVPN tun2socks + InternetChecker), which sends a non-standard
// SOCKS verb ("command 5") that strict servers reject (sing-box/xray).
// This listener accepts ANY command, replies with success and translates
// the connection into a CONNECT towards sing-box.
package daemon

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func (d *Daemon) relayAlive() bool {
	c, err := net.DialTimeout("tcp", d.cfg.Daemon.RelayListen, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (d *Daemon) relayListen(addr, upstream string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", addr, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.relayHandle(conn, upstream)
		}
	}()
	return nil
}

func (d *Daemon) relayHandle(conn net.Conn, upstream string) {
	defer conn.Close()
	defer func() {
		// a malformed probe/client must never take the whole daemon down
		if r := recover(); r != nil {
			fmt.Println("relay: recovered:", r)
		}
	}()
	logl := func(s string) {
		if f, err := os.OpenFile(d.cfg.Daemon.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "%s relay: %s\n", time.Now().Format("Jan 02 15:04:05"), s)
			f.Close()
		}
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second)) // handshake phase only

	// 1) greeting: VER, NMETHODS, METHODS... accepted as-is, reply "no auth"
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		logl("greeting read err: " + err.Error())
		return
	}
	if head[0] != 5 {
		logl("not SOCKS5 - closing")
		return
	}
	n := int(head[1])
	if n > 0 {
		if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
			return
		}
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// 2) request: VER CMD RSV ATYP ADDR PORT — the command byte is ignored
	//    (including "command 5"); every request is translated into a CONNECT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != 5 {
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		logl("unknown ATYP " + strconv.Itoa(int(req[3])))
		return
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(conn, portB); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portB)

	// 3) success to the client (bogus bind) — the traffic stream is transparent after this
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	logl(fmt.Sprintf("cmd=%d %s:%d -> upstream accepted", req[1], host, port))
	conn.SetDeadline(time.Time{}) // clear the handshake deadline

	// 4) CONNECT to sing-box with the same target address
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		logl("upstream dial err: " + err.Error())
		return
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(5 * time.Second))
	// sing-box: greeting + CONNECT target
	if _, err := up.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(up, resp); err != nil || resp[1] != 0 {
		return
	}
	var tgt []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			tgt = append([]byte{1}, ip4...)
		} else {
			tgt = append([]byte{4}, ip...)
		}
	} else {
		tgt = append([]byte{3, byte(len(host))}, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	req2 := append([]byte{5, 1, 0}, append(tgt, pb...)...)
	if _, err := up.Write(req2); err != nil {
		return
	}
	// sing-box CONNECT reply: VER REP RSV ATYP ADDR PORT
	rspHdr := make([]byte, 4)
	if _, err := io.ReadFull(up, rspHdr); err != nil {
		return
	}
	atyp := rspHdr[3]
	skip := map[byte]int{1: 4, 3: -1, 4: 16}[atyp]
	if skip == -1 {
		l := make([]byte, 1)
		if _, err := io.ReadFull(up, l); err != nil {
			return
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(up, make([]byte, skip+2)); err != nil {
		return
	}
	up.SetDeadline(time.Time{})

	// 5) pipe
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

var _ = strings.TrimSpace // keep import if unused in future edits
