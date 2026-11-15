// Tolerant SOCKS relay. Its only purpose is compatibility with the broken
// ndm client (BadVPN tun2socks + InternetChecker), which sends a non-standard
// SOCKS verb ("command 5") that strict servers reject (sing-box/xray).
// TCP requests (CONNECT, and the broken cmd=5 with a real target) are
// translated into a CONNECT towards sing-box.
//
// kgate-003: UDP ASSOCIATE is no longer translated into a TCP CONNECT. The
// ndm client associates UDP with dst 0.0.0.0:0 (correct per RFC 1928); the
// old CONNECT translation made sing-box dial tcp 0.0.0.0:0 through the direct
// outbound — 5s i/o timeout per association (143 029 errors in singbox.log
// over the kgate-001-dev deploy, ~17/min) and dead UDP flows on the LAN.
// The relay now terminates a real SOCKS5 UDP framing session locally
// (RFC 1928 §7) and pumps framed datagrams to sing-box's UDP endpoint:
// client ⇄ relay-UDP ⇄ sing-box-mixed-UDP, transparent header passthrough.
package daemon

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// udpIdleTimeout — жизнь UDP-ассоциации без пакетов. Ассоциация оканчивается
// и по закрытию control-conn (RFC 1928 §7: TCP-сессия держит UDP-состояние),
// и по простою — иначе зависшие клиенты копят UDP-сокеты.
const udpIdleTimeout = 2 * time.Minute

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
	//    (including "command 5") EXCEPT the UDP class, see dispatch below
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

	// 2') dispatch: kgate-003 — UDP ASSOCIATE в UDP-фрейминг, остальное — в
	// CONNECT (TCP-совместимость tun2socks сохранена: cmd=1 и сломанный
	// cmd=5 с РЕАЛЬНОЙ целью работают как раньше). UDP-класс: честный cmd=3
	// (любой dst — RFC разрешает не-нулевой DST, клиенты его всё равно
	// игнорируют) и сломанный cmd=5 с any-адресом (0.0.0.0:0 / "::":0) —
	// именно он лавил tcp 0.0.0.0:0-dial в sing-box.
	isZeroDst := (host == "0.0.0.0" || host == "::") && port == 0
	if req[1] == 3 || (req[1] == 5 && isZeroDst) {
		logl(fmt.Sprintf("cmd=%d %s:%d -> udp associate", req[1], host, port))
		d.relayUDPAssociate(conn, logl, upstream)
		return
	}

	// 3) success to the client (bogus bind) — the traffic stream is transparent after this
	if err := socksReply(conn, 0, 1, net.IPv4zero, 0); err != nil {
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
	// CONNECT request with the same target address (ATYP passthrough)
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
	if _, err := up.Write(append([]byte{5, 1, 0}, append(tgt, pb...)...)); err != nil {
		return
	}
	// sing-box CONNECT reply: VER REP RSV ATYP ADDR PORT
	if _, _, _, err := socksServerReply(up); err != nil {
		return
	}
	up.SetDeadline(time.Time{})

	// 5) pipe
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, up); done <- struct{}{} }()
	<-done
}

// socksReply writes a SOCKS5 reply (VER REP RSV ATYP ADDR PORT) to a client.
func socksReply(conn net.Conn, rep byte, atyp byte, ip net.IP, port uint16) error {
	hdr := []byte{5, rep, 0, atyp}
	if atyp == 1 {
		ip4 := ip.To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		hdr = append(hdr, ip4...)
	} else {
		hdr = append(hdr, ip.To16()...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	_, err := conn.Write(append(hdr, pb...))
	return err
}

// socksServerReply reads a SOCKS5 server reply (VER REP RSV ATYP ADDR PORT)
// and returns the BND address/port. Shared by the CONNECT and UDP-associate
// upstream handshakes.
func socksServerReply(r io.Reader) (net.IP, uint16, byte, error) {
	rspHdr := make([]byte, 4)
	if _, err := io.ReadFull(r, rspHdr); err != nil {
		return nil, 0, 0, err
	}
	if rspHdr[1] != 0 {
		return nil, 0, rspHdr[1], fmt.Errorf("upstream rejected: rep=%d", rspHdr[1])
	}
	atyp := rspHdr[3]
	var addr net.IP
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, 0, err
		}
		addr = net.IP(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, 0, err
		}
		addr = net.IP(b)
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return nil, 0, 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, 0, 0, err
		}
		addr = net.ParseIP(string(b)) // may be nil (domain) — caller tolerates
	default:
		return nil, 0, 0, fmt.Errorf("upstream reply: unknown ATYP %d", atyp)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return nil, 0, 0, err
	}
	return addr, binary.BigEndian.Uint16(pb), atyp, nil
}

// relayUDPAssociate terminates a real SOCKS5 UDP ASSOCIATE (RFC 1928 §7).
//
// Поле: sing-box mixed inbound НЕ диалит TCP на cmd=3 — он открывает свой
// UDP-сокет и отвечает BND.ADDR/BND.PORT. Релей становится UDP-фрейм-пампой:
// клиентские датаграммы (RSV FRAG ATYP DST.PORT | data) идут в BND sing-box
// как есть, ответы sing-box — обратно клиенту. Демультиплекс по адресу
// источника датаграммы (первый не-sing-box отправитель = клиент сессии;
// чужие дропаются). FRAG>0 не поддерживается (дроп + лог) — туннельные
// клиенты фрагментацию SOCKS-UDP не используют.
//
// Якорь сессии — control-conn: закрытие любой стороны (клиент/sing-box) или
// udpIdleTimeout молчания завершает ассоциацию и закрывает UDP-сокет.
func (d *Daemon) relayUDPAssociate(conn net.Conn, logl func(string), upstream string) {
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		logl("udp: upstream dial err: " + err.Error())
		_ = socksReply(conn, 5, 1, net.IPv4zero, 0)
		return
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting: VER=5, NMETHODS=1, METHOD=0 (no auth) — same shape as CONNECT
	if _, err := up.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(up, resp); err != nil || resp[1] != 0 {
		return
	}
	// UDP ASSOCIATE request: any-dst (sing-box routes by the per-datagram
	// header, not by this field)
	if _, err := up.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	bnd, bndPort, _, err := socksServerReply(up)
	if err != nil {
		logl("udp: upstream associate rejected: " + err.Error())
		_ = socksReply(conn, 5, 1, net.IPv4zero, 0)
		return
	}
	up.SetDeadline(time.Time{}) // control conn lives as long as the session

	// client-facing UDP socket on the same host as the TCP listener
	bindHost := "127.0.0.1"
	if h, _, perr := net.SplitHostPort(d.cfg.Daemon.RelayListen); perr == nil && h != "" {
		bindHost = h
	}
	bindIP := net.ParseIP(bindHost)
	if bindIP == nil {
		bindIP = net.IPv4zero
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		logl("udp: listen err: " + err.Error())
		_ = socksReply(conn, 1, 1, net.IPv4zero, 0)
		return
	}
	defer uc.Close()
	localPort := uint16(uc.LocalAddr().(*net.UDPAddr).Port)

	// BND to the client: the address the client itself reached (its TCP
	// destination IP) + our UDP port — RFC 1928 says the client should use
	// the TCP server address for BND 0.0.0.0, and conn.LocalAddr IS that
	// address; echoing it removes the guess entirely.
	localIP := net.IPv4zero
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && !tcpAddr.IP.IsUnspecified() {
		localIP = tcpAddr.IP
	}
	if err := socksReply(conn, 0, 1, localIP, localPort); err != nil {
		return
	}
	conn.SetDeadline(time.Time{}) // the session is no longer handshake-bound

	// resolve the sing-box UDP endpoint; a 0.0.0.0/unspecified BND means
	// "same host as the inbound" — use the host we dialed
	sbIP := bnd
	if sbIP == nil || sbIP.IsUnspecified() {
		h, _, _ := net.SplitHostPort(upstream)
		sbIP = net.ParseIP(h)
		if sbIP == nil {
			sbIP = net.IPv4(127, 0, 0, 1)
		}
	}
	sbAddr := &net.UDPAddr{IP: sbIP, Port: int(bndPort)}

	// control-conn monitor: its closure ends the association (unblocks the
	// UDP read via socket close)
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		_ = uc.Close()
	}()

	buf := make([]byte, 65535)
	var clientAddr *net.UDPAddr
	sbKey := sbAddr.String()
	for {
		uc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			break // idle timeout / control-conn close / shutdown
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 {
			continue // malformed frame
		}
		if buf[2] != 0 { // FRAG — unsupported (see doc comment)
			logl("udp: SOCKS fragment dropped (FRAG=" + strconv.Itoa(int(buf[2])) + ")")
			continue
		}
		switch {
		case src.String() == sbKey:
			if clientAddr != nil {
				_, _ = uc.WriteToUDP(buf[:n], clientAddr) // upstream reply, header as-is
			}
		case clientAddr == nil:
			clientAddr = src // first client datagram locks the session peer
			_, _ = uc.WriteToUDP(buf[:n], sbAddr)
		case src.String() == clientAddr.String():
			_, _ = uc.WriteToUDP(buf[:n], sbAddr)
		default:
			// a datagram from a stranger: not this association's client
		}
	}
	logl("udp: associate closed")
}
