package daemon

// kgate-003 regression tests: UDP ASSOCIATE must terminate as a real SOCKS5
// UDP framing session — sing-box (mocked) must NEVER see a TCP CONNECT for
// it (the old translation dialled tcp 0.0.0.0:0 → 5s i/o timeout flood,
// 143 029 errors). The tun2socks TCP compatibility (cmd=1 and the broken
// cmd=5 with a real target) must stay on the CONNECT path.
import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"kgate/internal/model"
)

// mockSingbox mimics the parts of sing-box mixed inbound the relay uses:
// SOCKS5 greeting, CONNECT (echo) and UDP ASSOCIATE (BND → a UDP echo with
// the same frame header). Records every request it sees.
type mockSingbox struct {
	serveAddr string       // upstream TCP listener address
	cmdSeen   chan byte    // upstream request CMD byte (per session)
	reqSeen   chan []byte  // raw upstream request bytes (VER..PORT)
	udpFrames chan []byte  // datagrams the mock upstream UDP endpoint received
	udpAddr   *net.UDPAddr // mock upstream UDP endpoint
}

func startMockSingbox(t *testing.T) *mockSingbox {
	t.Helper()
	m := &mockSingbox{
		cmdSeen:   make(chan byte, 4),
		reqSeen:   make(chan []byte, 4),
		udpFrames: make(chan []byte, 16),
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("mock udp listen: %v", err)
	}
	t.Cleanup(func() { uc.Close() })
	m.udpAddr = uc.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			frame := append([]byte(nil), buf[:n]...)
			select {
			case m.udpFrames <- frame:
			default:
			}
			// echo: same header, payload swapped for "pong"
			hdrLen, perr := socksUDPHeaderLen(frame)
			if perr != nil {
				continue
			}
			pong := append(append([]byte(nil), frame[:hdrLen]...), []byte("pong")...)
			_, _ = uc.WriteToUDP(pong, src)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serveConn(c)
		}
	}()
	m.serveAddr = ln.Addr().String()
	return m
}

// serveAddr is set by startMockSingbox after the listener is bound.
// (declared here to keep the struct together — Go allows struct field use
// only after declaration, so it lives below the constructor in review order)

func (m *mockSingbox) serveConn(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	n := int(hdr[1])
	if n > 0 {
		if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
			return
		}
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var addrLen int
	switch req[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		addrLen = int(l[0])
	default:
		return
	}
	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		return
	}
	fullReq := append(append([]byte(nil), req...), rest...)
	select {
	case m.cmdSeen <- req[1]:
	default:
	}
	select {
	case m.reqSeen <- fullReq:
	default:
	}
	switch req[1] {
	case 3: // UDP ASSOCIATE: BND = mock UDP endpoint, keep the control conn
		if err := socksReply(c, 0, 1, m.udpAddr.IP, uint16(m.udpAddr.Port)); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c) // hold until closed
	case 1, 5: // CONNECT: reply success, then echo (pipe target)
		if err := socksReply(c, 0, 1, net.IPv4(127, 0, 0, 1), 1080); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
}

// socksUDPHeaderLen parses a SOCKS5 UDP request header (RSV FRAG ATYP ADDR PORT).
func socksUDPHeaderLen(f []byte) (int, error) {
	if len(f) < 4 {
		return 0, io.ErrShortBuffer
	}
	switch f[3] {
	case 1:
		return 4 + 4 + 2, nil
	case 4:
		return 4 + 16 + 2, nil
	case 3:
		return 4 + 1 + int(f[4]) + 2, nil
	}
	return 0, io.ErrUnexpectedEOF
}

// startTestRelay runs the daemon relay listener on a free localhost port.
func startTestRelay(t *testing.T, upstream string) (relayAddr string, d *Daemon) {
	t.Helper()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	relayAddr = free.Addr().String()
	free.Close()
	cfg := &model.Config{}
	cfg.Daemon.RelayListen = relayAddr
	cfg.Daemon.RelayUpstream = upstream
	cfg.Daemon.Log = filepath.Join(t.TempDir(), "relay.log")
	d = &Daemon{cfg: cfg}
	if err := d.relayListen(relayAddr, upstream); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	return relayAddr, d
}

// socksClient performs the client side of the SOCKS5 handshake and sends a
// request, returning the server reply bytes.
func socksClient(t *testing.T, addr string, cmd byte, dstHdr []byte) (net.Conn, []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("client greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0 {
		t.Fatalf("client greeting reply: %v", err)
	}
	req := append([]byte{5, cmd, 0}, dstHdr...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("client request: %v", err)
	}
	rhdr := make([]byte, 4)
	if _, err := io.ReadFull(c, rhdr); err != nil {
		t.Fatalf("client reply hdr: %v", err)
	}
	var skip int
	switch rhdr[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			t.Fatalf("client reply domlen: %v", err)
		}
		skip = 1 + int(l[0])
	}
	rest := make([]byte, skip+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("client reply rest: %v", err)
	}
	return c, append(rhdr, rest...)
}

func ipv4Hdr(ip byte, ip2, ip3, ip4 byte, port uint16) []byte {
	h := []byte{1, ip, ip2, ip3, ip4}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	return append(h, pb...)
}

func await[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
		var zero T
		return zero
	}
}

// TestRelayUDPAssociate_NoTCPDial — ядро kgate-003: cmd=3 UDP ASSOCIATE
// превращается в UDP-фрейминг (upstream видит cmd=3, НЕ cmd=1 CONNECT), и
// датаграмма ходит по кругу клиент ⇄ релей ⇄ sing-box.
func TestRelayUDPAssociate_NoTCPDial(t *testing.T) {
	m := startMockSingbox(t)
	relayAddr, _ := startTestRelay(t, m.serveAddr)

	conn, rep := socksClient(t, relayAddr, 3, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("associate rejected: rep=%d", rep[1])
	}
	bndPort := binary.BigEndian.Uint16(rep[8:10])
	if bndPort == 0 {
		t.Fatalf("BND port = 0 — релей вернул фиктивный bind (старый баг)")
	}

	// upstream MUST have received UDP ASSOCIATE (cmd=3), never CONNECT
	cmd := await(t, m.cmdSeen, "upstream cmd")
	if cmd != 3 {
		t.Fatalf("upstream cmd = %d, want 3 (UDP ASSOCIATE; 1 = TCP-dial регрессия)", cmd)
	}
	req := await(t, m.reqSeen, "upstream request")
	if req[1] != 3 {
		t.Fatalf("upstream request cmd = %d", req[1])
	}
	_ = conn

	// UDP roundtrip: client frame → sing-box mock → echo back
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	defer udpSock.Close()
	frame := append([]byte{0, 0, 0}, append(ipv4Hdr(8, 8, 8, 8, 53), []byte("ping-kgate-003")...)...)
	relayUDP := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(bndPort)}
	if _, err := udpSock.WriteToUDP(frame, relayUDP); err != nil {
		t.Fatalf("client udp write: %v", err)
	}
	got := await(t, m.udpFrames, "mock upstream udp frame")
	if !equalBytes(got, frame) {
		t.Fatalf("upstream frame = %x, want %x (заголовок/полезная нагрузка искажены)", got, frame)
	}
	buf := make([]byte, 65535)
	udpSock.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := udpSock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client udp reply: %v", err)
	}
	wantReply := append([]byte{0, 0, 0}, append(ipv4Hdr(8, 8, 8, 8, 53), []byte("pong")...)...)
	if !equalBytes(buf[:n], wantReply) {
		t.Fatalf("client reply = %x, want %x", buf[:n], wantReply)
	}
}

// TestRelayCmd5ZeroDst_UDPAssociate — сломанный ndm-клиент (cmd=5, dst
// 0.0.0.0:0): обязан пойти в UDP-фрейминг, НЕ в CONNECT (это тот самый
// класс ошибок `dial tcp 0.0.0.0:0: i/o timeout`).
func TestRelayCmd5ZeroDst_UDPAssociate(t *testing.T) {
	m := startMockSingbox(t)
	relayAddr, _ := startTestRelay(t, m.serveAddr)

	_, rep := socksClient(t, relayAddr, 5, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("cmd=5 associate rejected: rep=%d", rep[1])
	}
	cmd := await(t, m.cmdSeen, "upstream cmd")
	if cmd != 3 {
		t.Fatalf("upstream cmd = %d, want 3 — cmd=5 0.0.0.0:0 всё ещё диалится как CONNECT", cmd)
	}
}

// TestRelayCmd5RealDst_StillConnect — TCP-совместимость tun2socks: cmd=5 с
// РЕАЛЬНОЙ целью остаётся CONNECT-путём (upstream видит cmd=1, TCP-труба
// работает).
func TestRelayCmd5RealDst_StillConnect(t *testing.T) {
	m := startMockSingbox(t)
	relayAddr, _ := startTestRelay(t, m.serveAddr)

	conn, rep := socksClient(t, relayAddr, 5, ipv4Hdr(1, 2, 3, 4, 443))
	if rep[1] != 0 {
		t.Fatalf("connect rejected: rep=%d", rep[1])
	}
	cmd := await(t, m.cmdSeen, "upstream cmd")
	if cmd != 1 {
		t.Fatalf("upstream cmd = %d, want 1 (CONNECT) — TCP-совместимость сломана", cmd)
	}
	if _, err := conn.Write([]byte("tcp-payload")); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "tcp-payload" {
		t.Fatalf("tcp echo = %q err=%v, want tcp-payload", buf[:n], err)
	}
}

// TestRelayUDPFragmentDropped — FRAG≠0 не доходит до sing-box (минимальная
// честность: релей не тихо проглатывает неподдерживаемое без лога — лог
// проверяется фактом дропа).
func TestRelayUDPFragmentDropped(t *testing.T) {
	m := startMockSingbox(t)
	relayAddr, _ := startTestRelay(t, m.serveAddr)

	_, rep := socksClient(t, relayAddr, 3, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("associate rejected: rep=%d", rep[1])
	}
	bndPort := binary.BigEndian.Uint16(rep[8:10])

	frag := append([]byte{0, 0, 0}, append(ipv4Hdr(8, 8, 8, 8, 53), []byte("framed")...)...)
	frag[2] = 1 // FRAG=1
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client udp: %v", err)
	}
	defer udpSock.Close()
	relayUDP := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(bndPort)}
	if _, err := udpSock.WriteToUDP(frag, relayUDP); err != nil {
		t.Fatalf("client udp write: %v", err)
	}
	select {
	case f := <-m.udpFrames:
		t.Fatalf("фрагмент утёк в sing-box: %x", f)
	case <-time.After(400 * time.Millisecond):
		// дропнут как и ожидается
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
