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
//
// kgate-004: the "BND reply is enough" assumption was wrong for the ndm
// client. Packet capture on the live router (16.11, lo:1090) showed cmd=5
// 0.0.0.0:0 is NOT an RFC ASSOCIATE — it opens the client's UDP-over-TCP
// channel: right after the BND reply the client streams length-prefixed
// datagrams INTO the control connection
//
//	[data_len:2 BE][dst_ip:4][src_port:2 BE][dst_port:2 BE][data]
//
// (verified frames: NTP → :123, CoAP → :5683). kgate-003's silent monitor
// (io.Copy(io.Discard, conn)) ate them: the client got no answers and
// closed every association after 1-3s — 13 792/13 792 dead associations
// on 16.11, LAN UDP down. The session is now dual-path: TCP-framed ndm
// datagrams are terminated locally and bridged into the same sing-box UDP
// endpoint (kgate-003 semantics preserved: upstream is a real SOCKS5 UDP
// ASSOCIATE, never a tcp 0.0.0.0:0 dial); RFC-framed datagrams to the BND
// socket keep working for RFC clients (cmd=3, e.g. KeeneticOS socks5-udp).
// Replies go back over whichever transport the peer locked first.
package daemon

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// udpIdleTimeout — жизнь UDP-ассоциации без пакетов. Ассоциация оканчивается
// и по закрытию control-conn (RFC 1928 §7: TCP-сессия держит UDP-состояние),
// и по простою — иначе зависшие клиенты копят UDP-сокеты.
const udpIdleTimeout = 2 * time.Minute

// udpPeerGraceTimeout — короткое grace-окно, которое ассоциация переживает
// закрытие control-conn (kgate-004, решение АрхКома фазы S): RFC 1928 §7
// связывает жизнь ассоциации с TCP-ногой, но клиенты диалекта ndm и часть
// RFC-клиентов рвут control-conn, продолжая слать датаграммы на BND. Тишина
// дольше окна убивает сессию — дескрипторы не копятся.
const udpPeerGraceTimeout = 15 * time.Second

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

// relayUDPAssociate terminates a real SOCKS5 UDP ASSOCIATE (RFC 1928 §7) —
// upstream — and a dual-path client leg (kgate-004).
//
// Upstream нога (kgate-003, без изменений): sing-box mixed inbound на cmd=3
// НЕ диалит TCP — он открывает свой UDP-сокет и отвечает BND.ADDR/BND.PORT.
// Никаких tcp 0.0.0.0:0-dials: это приёмка владельца по kgate-003.
//
// Клиентская нога — две транспортные формы одной сессии:
//   - RFC 1928 §7: датаграммы (RSV FRAG ATYP DST.PORT | data) приходят на
//     UDP-сокет BND; ответы возвращаются на тот же сокет с заголовком как
//     есть (cmd=3 и KeeneticOS `socks5-udp`);
//   - ndm UDP-over-TCP (cmd=5 0.0.0.0:0): датаграммы приходят в САМ control
//     -конн в форме [len:2][dst_ip:4][src_port:2][dst_port:2][data]; релей
//     терминирует их локально, строит SOCKS-фрейм и шлёт в тот же UDP-сокет
//     sing-box; ответы распаковываются и кадрируются обратно в TCP-поток
//     (заголовок эхом: ровно тот, что прислал клиент).
//
// Демультиплекс ответов sing-box по transport-пeer'у: whichever транспорт
// клиент использовал первым, тот и получает ответы; второй — только вперёд.
// FRAG>0 в RFC-пути дропается с логом. Якорь сессии: udpIdleTimeout молчания
// при живом control-conn; закрытие control-conn переводит ассоциацию в
// grace-режим (udpPeerGraceTimeout) — датаграммы продолжают ходить, тишина
// дольше окна завершает сессию (решение АрхКома фазы S по kgate-004).
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

	// kgate-004 session state: the client leg is dual-path (RFC UDP socket
	// or ndm UDP-over-TCP framing inside the control conn)
	s := &udpSession{conn: conn, uc: uc, sbAddr: sbAddr, logl: logl}

	// control-conn reader: for the ndm client this is the DATA transport;
	// for RFC clients it is just the liveness anchor (RFC: closing the TCP
	// connection ends the association). Its closure ends the session via
	// socket close.
	go s.readControlFrames()

	buf := make([]byte, 65535)
	sbKey := sbAddr.String()
	for {
		s.armRead()
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			break // idle timeout / grace истёк / shutdown
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 {
			continue // malformed frame
		}
		if buf[2] != 0 { // FRAG — unsupported (see doc comment)
			logl("udp: SOCKS fragment dropped (FRAG=" + strconv.Itoa(int(buf[2])) + ")")
			continue
		}
		if src.String() == sbKey {
			s.deliverUpstreamReply(buf[:n])
			continue
		}
		if s.acceptClientDatagram(src) {
			_, _ = uc.WriteToUDP(buf[:n], sbAddr)
		}
		// datagrams from anyone else: not this association's client
	}
	logl("udp: associate closed")
}

// peer kinds of a UDP association's client leg (kgate-004).
const (
	peerNone = iota
	peerUDP  // RFC 1928 §7: datagrams to the BND socket
	peerNDM  // ndm UDP-over-TCP: frames inside the control conn
)

// udpSession — клиентская нога одной UDP-ассоциации (kgate-004): контрольный
// TCP-конн (транспорт ndm-фреймов + сигнал закрытия), UDP-сокет BND и пир,
// первым захвативший право на ответы. mu защищает kind/udpPeer/hdr/peerClosed
// и арминг read-дедлайна: кадры в control-конн читает одна горутина, ответы
// sing-box раскладывает другая.
type udpSession struct {
	conn   net.Conn
	uc     *net.UDPConn
	sbAddr *net.UDPAddr
	logl   func(string)

	mu         sync.Mutex
	kind       int          // peerNone / peerUDP / peerNDM
	udpPeer    *net.UDPAddr // RFC-пир (peerUDP)
	hdr        [8]byte      // последний ndm-заголовок: dst_ip(4) src_port(2) dst_port(2)
	peerClosed bool         // control-conn закрыт → дедлайн сессии = grace-окно
}

// readControlFrames читает UDP-over-TCP кадры ndm-клиента
// [len:2 BE][dst_ip:4][src_port:2 BE][dst_port:2 BE][data] из control-конна
// и мостит их в sing-box как обычные SOCKS-UDP фреймы. Для RFC-пиров горутина
// просто держит конн: EOF/ошибка = peerGone (grace-режим ассоциации), а
// рассинхрон потока (oversized-кадр) — жёсткое закрытие сессии.
func (s *udpSession) readControlFrames() {
	lhdr := make([]byte, 2)
	meta := make([]byte, 8)
	for {
		if _, err := io.ReadFull(s.conn, lhdr); err != nil {
			s.peerGone()
			return
		}
		n := int(binary.BigEndian.Uint16(lhdr))
		if n == 0 {
			continue // 0-длинник — пустой кадр/keepalive: мимо upstream
		}
		if n > 65507 {
			// за пределами датаграммы UDP — рассинхрон потока, дальше
			// честных границ не будет: сессию закрываем, не угадывая
			s.logl("udp: ndm-tcp frame too big (" + strconv.Itoa(n) + ") — session closed")
			_ = s.conn.Close()
			_ = s.uc.Close()
			return
		}
		if _, err := io.ReadFull(s.conn, meta); err != nil {
			s.peerGone()
			return
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(s.conn, data); err != nil {
			s.peerGone()
			return
		}
		first := s.lockNDMPeer(meta, n)
		if first {
			s.logl(fmt.Sprintf("udp: ndm-tcp first frame %dB (sport=%d -> dst %s:%d)",
				n,
				binary.BigEndian.Uint16(meta[4:6]),
				net.IP(meta[0:4]).String(),
				binary.BigEndian.Uint16(meta[6:8])))
		}
		frame := make([]byte, 10+n)
		frame[0], frame[1], frame[2], frame[3] = 0, 0, 0, 1 // RSV FRAG ATYP=IPv4
		copy(frame[4:8], meta[0:4])
		binary.BigEndian.PutUint16(frame[8:10], binary.BigEndian.Uint16(meta[6:8]))
		copy(frame[10:], data)
		if _, err := s.uc.WriteToUDP(frame, s.sbAddr); err != nil {
			_ = s.uc.Close()
			return
		}
	}
}

// peerGone — control-conn закрылся (EOF/ошибка). Ассоциация НЕ умирает
// мгновенно: она переживает udpPeerGraceTimeout (решение АрхКома фазы S),
// датаграммы на BND продолжают ходить; мгновенно взводим grace-дедлайн,
// чтобы прервать текущий idle-вэйтом read-цикл сессии.
func (s *udpSession) peerGone() {
	s.mu.Lock()
	s.peerClosed = true
	_ = s.uc.SetReadDeadline(time.Now().Add(udpPeerGraceTimeout))
	s.mu.Unlock()
}

// armRead взводит read-дедлайн UDP-сокета: полное idle-окно при живом
// control-conn, grace-окно после его закрытия. Под mu вместе с peerClosed,
// чтобы арминг не перезаписал только что взведённый grace-дедлайн.
func (s *udpSession) armRead() {
	s.mu.Lock()
	dl := udpIdleTimeout
	if s.peerClosed {
		dl = udpPeerGraceTimeout
	}
	_ = s.uc.SetReadDeadline(time.Now().Add(dl))
	s.mu.Unlock()
}

// lockNDMPeer фиксирует ndm-пира (первый кадр) и запоминает его заголовок
// для эха в ответах. Возвращает true на первом кадре сессии.
func (s *udpSession) lockNDMPeer(meta []byte, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy(s.hdr[:], meta)
	if s.kind == peerNone {
		s.kind = peerNDM
		return true
	}
	return false
}

// acceptClientDatagram обрабатывает датаграмму, пришедшую не от sing-box:
// первый отправитель блокирует RFC-пира (kgate-003 семантика), дальше
// датаграммы того же пира идут вперёд, чужие дропаются. true — вперёд.
func (s *udpSession) acceptClientDatagram(src *net.UDPAddr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.kind == peerNone:
		s.kind = peerUDP
		s.udpPeer = src
		return true
	case s.kind == peerUDP && s.udpPeer.String() == src.String():
		return true
	default:
		return false
	}
}

// deliverUpstreamReply раскладывает ответ sing-box по пиру сессии:
// peerUDP — фрейм как есть в UDP-сокет (kgate-003), peerNDM — данные
// распаковываются из SOCKS-фрейма и кадрируются в control-конн
// [len:2][hdr-эхо 8Б][data]. До лока пира ответы дропаются (kgate-003).
func (s *udpSession) deliverUpstreamReply(frame []byte) {
	s.mu.Lock()
	kind := s.kind
	peer := s.udpPeer
	var hdr [8]byte
	copy(hdr[:], s.hdr[:])
	s.mu.Unlock()

	switch kind {
	case peerUDP:
		if peer != nil {
			_, _ = s.uc.WriteToUDP(frame, peer)
		}
	case peerNDM:
		hl, err := socksUDPHeaderLen(frame)
		if err != nil || hl+2 > len(frame) {
			return // кривой фрейм от upstream — молча мимо
		}
		payload := frame[hl:]
		out := make([]byte, 10+len(payload))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(payload)))
		copy(out[2:10], hdr[:])
		copy(out[10:], payload)
		_, _ = s.conn.Write(out)
	}
	// peerNone: клиент ещё не заявил себя — ответ некуда класть
}

// socksUDPHeaderLen возвращает длину заголовка SOCKS5 UDP-фрейма
// (RSV FRAG ATYP ADDR PORT) по ATYP.
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
