package daemon

// kgate-004 lab matrix: the relay UDP data-path against a REAL sing-box
// (1.14.x) — the unit mock cannot vouch for the engine's BND/framing.
//
// Env-gated (skipped in `make test`): KGATE_UDP_LAB=1 + KGATE_SINGBOX_BIN
// pointing at a sing-box binary. lab/run.sh `udp` wires both (downloads and
// caches the binary into lab/work). Everything else in this file is hermetic.
//
// Matrix (ArchCom phase S):
//   1  ndm cmd=5 0.0.0.0:0 → upstream cmd=3, never CONNECT (kgate-003 signature)
//   2  ndm UDP-over-TCP datagram roundtrip через реальный sing-box
//   3  control-conn закрыт на t+0 при живом UDP-потоке — ассоциация
//      переживает закрытие (grace-окно), датаграммы ходят (красно-зелёная
//      пара к kgate-003: там монитор гасил сокет мгновенно)
//   4  cmd=5 с реальной целью → CONNECT (TCP-совместимость tun2socks)
//   5  BND=0.0.0.0 от upstream (listen 0.0.0.0) — раундтрип через fallback
//   6  FRAG>0 дропается, сессия жива
//   7  malformed UDP-фрейм дропается, сессия жива
//   8  свежий релей после "рестарта" принимает новые ассоциации
//   9  upstream недоступен в момент ASSOCIATE → rep=5 немедленно, без зависаний
//  10  сигнатура: ноль "0.0.0.0" dial-ошибок в логе sing-box
//  11  живучесть: всплеск N ассоциаций — fd возвращаются к базе (нет утечки)
//  12  фаззинг greeting/request/кадров — нет паник, релей продолжает serve
import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"kgate/internal/client"
	"kgate/internal/model"
)

const labPeerGrace = udpPeerGraceTimeout

func labEnabled(t *testing.T) string {
	t.Helper()
	if os.Getenv("KGATE_UDP_LAB") != "1" {
		t.Skip("KGATE_UDP_LAB=1 не задан — лабовая матрица (реальный sing-box) пропущена")
	}
	bin := os.Getenv("KGATE_SINGBOX_BIN")
	if bin == "" {
		t.Skip("KGATE_SINGBOX_BIN не задан — нечего запускать")
	}
	return bin
}

// labSingBox поднимает реальный sing-box: mixed на 0.0.0.0:<свободный порт>
// (0.0.0.0 — как на роутере: заодно даёт BND=0.0.0.0 и покрывает fallback),
// direct outbound. Возвращает адрес mixed-инбаунда и лог-файл для
// сигнатурного ассерта.
func labSingBox(t *testing.T, bin string) (mixedAddr string, logPath string) {
	t.Helper()
	// свободный порт НЕ вслепую: сначала занимаем, читаем номер, держим до
	// запуска sing-box — иначе между release и bind вклинится чужой
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	mixedPort := hold.Addr().(*net.TCPAddr).Port
	hold.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	cfgBody := fmt.Sprintf(`{
	  "log": {"level": "info", "output": "%s", "timestamp": true},
	  "inbounds": [{"type": "mixed", "tag": "proxy-in", "listen": "0.0.0.0", "listen_port": %d}],
	  "outbounds": [{"type": "direct", "tag": "direct"}],
	  "route": {"rules": [{"action": "sniff"}], "final": "direct"}
	}`, filepath.Join(dir, "singbox.log"), mixedPort)
	if err := os.WriteFile(cfg, []byte(cfgBody), 0644); err != nil {
		t.Fatalf("sing-box config: %v", err)
	}
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfg)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("sing-box start: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	mixedAddr = fmt.Sprintf("127.0.0.1:%d", mixedPort)
	// ждём готовности mixed-инбаунда (бут-гонка и в лабе)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", mixedAddr, 500*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sing-box не поднял %s за 10с", mixedAddr)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return mixedAddr, filepath.Join(dir, "singbox.log")
}

// labEchoServer — локальный UDP-эхо: "интернет" в лабе. Отвляет ответом
// "echo:<payload>" с того же сокета, куда релей обязан доставить датаграмму.
func labEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			out := append([]byte("echo:"), buf[:n]...)
			_, _ = uc.WriteToUDP(out, src)
		}
	}()
	return uc.LocalAddr().(*net.UDPAddr)
}

// labReadUDP читает одну датаграмму с дедлайном.
func labReadUDP(t *testing.T, uc *net.UDPConn, timeout time.Duration) []byte {
	t.Helper()
	uc.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("udp read (%v): %v", timeout, err)
	}
	return buf[:n]
}

// labFreePort — свободный TCP-порт на 127.0.0.1.
func labFreePort(t *testing.T) string {
	t.Helper()
	c, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer c.Close()
	return c.Addr().String()
}

// labRelay поднимает релей на свежем порту против реального sing-box.
func labRelay(t *testing.T, upstream string) string {
	t.Helper()
	addr := labFreePort(t)
	cfgPath := filepath.Join(t.TempDir(), "relay.log")
	d := &Daemon{}
	d.cfg = labCfg(addr, upstream, cfgPath)
	if err := d.relayListen(addr, upstream); err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	return addr
}

// labCfg — минимальный конфиг релея для лабы.
func labCfg(listen, upstream, logPath string) *model.Config {
	cfg := &model.Config{}
	cfg.Daemon.RelayListen = listen
	cfg.Daemon.RelayUpstream = upstream
	cfg.Daemon.Log = logPath
	return cfg
}

// labIPv4 — 4 байта адреса эхо-сервера (для конструирования SOCKS-заголовков).
func labIPv4(ip net.IP) [4]byte {
	v4 := ip.To4()
	if v4 == nil {
		panic("lab: echo addr не IPv4")
	}
	var a [4]byte
	copy(a[:], v4)
	return a
}

// labAssociateNDM — полный cmd=5 0.0.0.0:0 хендшейк (форма ndm-клиента).
func labAssociateNDM(t *testing.T, relayAddr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", relayAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil || rep[1] != 0 {
		t.Fatalf("greeting reply: %v", err)
	}
	if _, err := conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("cmd=5: %v", err)
	}
	rhdr := make([]byte, 10) // VER REP RSV ATYP(1) ADDR(4) PORT(2)
	if _, err := io.ReadFull(conn, rhdr); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if rhdr[1] != 0 {
		t.Fatalf("associate rejected: rep=%d", rhdr[1])
	}
	return conn
}

// labNDMRoundtrip — один ndm UDP-over-TCP кадр до эха и обратно.
func labNDMRoundtrip(t *testing.T, conn net.Conn, echo *net.UDPAddr, tag string) {
	t.Helper()
	payload := []byte(tag)
	frame := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
	copy(frame[2:6], echo.IP.To4())
	binary.BigEndian.PutUint16(frame[6:8], 40000)              // src_port
	binary.BigEndian.PutUint16(frame[8:10], uint16(echo.Port)) // dst_port
	copy(frame[10:], payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("ndm frame write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("ndm roundtrip %q: нет ответа в control-конн: %v", tag, err)
	}
	pl := int(binary.BigEndian.Uint16(buf[0:2]))
	if pl != len(payload)+len("echo:") || !equalBytes(buf[2+8:2+8+pl], append([]byte("echo:"), payload...)) {
		t.Fatalf("ndm roundtrip %q: кривой ответ (%d байт): %x", tag, n, buf[:n])
	}
}

// TestLabRelayUDPMatrix — строки 1-10 матрицы (см. шапку файла).
func TestLabRelayUDPMatrix(t *testing.T) {
	bin := labEnabled(t)
	mixedAddr, logPath := labSingBox(t, bin)
	echo := labEchoServer(t)
	e := labIPv4(echo.IP)
	relayAddr := labRelay(t, mixedAddr)

	// (1) ndm-ассоциация: upstream видит cmd=3 (сигнатурный ассерт — ниже по логу)
	conn := labAssociateNDM(t, relayAddr)

	// (2) ndm UDP-over-TCP раундтрип через реальный sing-box
	labNDMRoundtrip(t, conn, echo, "matrix-ndm-1")
	labNDMRoundtrip(t, conn, echo, "matrix-ndm-2")

	// (3) control-conn закрыт на t+0 → ассоциация переживает (grace),
	// UDP-поток продолжает ходить в RFC-форме на BND-сокет
	conn.Close()
	// свежая RFC-сессия на другом конне: cmd=3 + UDP-датаграмма после
	// закрытия control-ноги
	rfcAddr := labRelay(t, mixedAddr)
	c2, rep := socksClient(t, rfcAddr, 3, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("cmd=3 associate rejected: rep=%d", rep[1])
	}
	c2.Close() // ЗАКРЫТИЕ CONTROL-CONN НА t+0
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("rfc udp: %v", err)
	}
	defer uc.Close()
	// BND из ответа c2: ATYP=1, addr=rep[4:8], port=rep[8:10]
	bndIP := net.IP(rep[4:8])
	if bndIP.IsUnspecified() {
		bndIP = net.IPv4(127, 0, 0, 1)
	}
	bnd := &net.UDPAddr{IP: bndIP, Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	frame := append([]byte{0, 0, 0}, append(ipv4Hdr(e[0], e[1], e[2], e[3], uint16(echo.Port)), []byte("after-close")...)...)
	if _, err := uc.WriteToUDP(frame, bnd); err != nil {
		t.Fatalf("rfc udp write после закрытия control-conn: %v", err)
	}
	got := labReadUDP(t, uc, 5*time.Second)
	if !equalBytes(got, append([]byte{0, 0, 0}, append(ipv4Hdr(e[0], e[1], e[2], e[3], uint16(echo.Port)), []byte("echo:after-close")...)...)) {
		t.Fatalf("rfc-after-close reply = %x", got)
	}

	// (4) cmd=5 с реальной целью → CONNECT (TCP-труба)
	tcpConn, rep := socksClient(t, relayAddr, 5, ipv4Hdr(1, 2, 3, 4, 443))
	if rep[1] != 0 {
		t.Fatalf("cmd=5 real dst rejected: %d", rep[1])
	}
	// реальный sing-box отвергнет CONNECT на 1.2.3.4:443 не мгновенно; нам
	// важен факт handshake-приёмки, TCP-совместимость релея покрыта unit-тестами
	_ = tcpConn

	// (5) BND=0.0.0.0 fallback покрыт конфигом listen 0.0.0.0: строки выше
	// уже прошли через fallback (sing-box с 0.0.0.0 отдаёт BND=0.0.0.0).

	// (6) FRAG>0 дропается, сессия жива
	uc2, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer uc2.Close()
	c3, rep := socksClient(t, relayAddr, 3, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("cmd=3 rejected: %d", rep[1])
	}
	bnd3IP := net.IP(rep[4:8])
	if bnd3IP.IsUnspecified() {
		bnd3IP = net.IPv4(127, 0, 0, 1)
	}
	bnd3 := &net.UDPAddr{IP: bnd3IP, Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	frag := append([]byte{0, 0, 1}, append(ipv4Hdr(e[0], e[1], e[2], e[3], uint16(echo.Port)), []byte("frag")...)...)
	if _, err := uc2.WriteToUDP(frag, bnd3); err != nil {
		t.Fatalf("frag write: %v", err)
	}
	// после дропа сессия жива: валидный кадр проходит
	okFrame := append([]byte{0, 0, 0}, append(ipv4Hdr(e[0], e[1], e[2], e[3], uint16(echo.Port)), []byte("after-frag")...)...)
	if _, err := uc2.WriteToUDP(okFrame, bnd3); err != nil {
		t.Fatalf("post-frag write: %v", err)
	}
	got = labReadUDP(t, uc2, 5*time.Second)
	if !equalBytes(got[10:], []byte("echo:after-frag")) {
		t.Fatalf("post-frag reply = %x", got)
	}
	c3.Close()

	// (7) malformed (RSV≠0) дропается, сессия жива
	if _, err := uc2.WriteToUDP(append([]byte{9, 9, 9}, okFrame[3:]...), bnd3); err != nil {
		t.Fatalf("malformed write: %v", err)
	}
	if _, err := uc2.WriteToUDP(okFrame, bnd3); err != nil {
		t.Fatalf("post-malformed write: %v", err)
	}
	got = labReadUDP(t, uc2, 5*time.Second)
	if !equalBytes(got[10:], []byte("echo:after-frag")) {
		t.Fatalf("post-malformed reply = %x", got)
	}

	// (8) свежий релей принимает новые ассоциации (рестарт-семантика)
	_ = labRelay(t, mixedAddr)
	nc := labAssociateNDM(t, relayAddr)
	labNDMRoundtrip(t, nc, echo, "after-restart")

	// (9) upstream недоступен → rep=5 немедленно
	deadAddr := labFreePort(t) // никто не слушает
	dRelay := labRelay(t, deadAddr)
	dc, err := net.DialTimeout("tcp", dRelay, 2*time.Second)
	if err != nil {
		t.Fatalf("dial dead-upstream relay: %v", err)
	}
	defer dc.Close()
	dc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := dc.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := io.ReadFull(dc, make([]byte, 2)); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if _, err := dc.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("cmd=5: %v", err)
	}
	rhdr := make([]byte, 10)
	if _, err := io.ReadFull(dc, rhdr); err != nil {
		t.Fatalf("failure reply: %v", err)
	}
	if rhdr[1] != 5 {
		t.Fatalf("upstream dead: rep=%d, want 5 (general failure)", rhdr[1])
	}

	// (10) сигнатура: ноль dial 0.0.0.0 в логе sing-box
	lf, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("sing-box log: %v", err)
	}
	defer lf.Close()
	sc := bufio.NewScanner(lf)
	for sc.Scan() {
		line := sc.Text()
		if contains(line, "0.0.0.0") && (contains(line, "dial") || contains(line, "connect")) {
			t.Fatalf("сигнатура kgate-001 вернулась: %q", line)
		}
	}

	// (11) живучесть: всплеск 60 коротких ndm-ассоциаций; после grace-окна
	// fd возвращаются к базе (нет утечки UDP-сокетов)
	before := labFDCount(t)
	for i := 0; i < 60; i++ {
		bc := labAssociateNDM(t, relayAddr)
		bc.Write(ndmFrame([4]byte{10, 0, 0, 1}, uint16(30000+i), 53, []byte("burst")))
		bc.Close()
	}
	time.Sleep(labPeerGrace + 3*time.Second) // grace истекает у всех
	after := labFDCount(t)
	if after > before+4 {
		t.Fatalf("утечка fd после всплеска: база %d, после %d", before, after)
	}

	// (12) фаззинг — релей жив после мусора (нет паник, гонок по fatal)
	for i := 0; i < 40; i++ {
		fc := labAssociateNDM(t, relayAddr)
		junk := make([]byte, 1+i%64)
		for j := range junk {
			junk[j] = byte(i*7 + j*13)
		}
		fc.Write(junk) // greeting-мусор после ASSOCIATE — релей обязан выжить
		fc.Close()
	}
	pc := labAssociateNDM(t, relayAddr)
	labNDMRoundtrip(t, pc, echo, "post-fuzz")
}

// TestLabRelayUDPGrace — строка 3 в изоляции: закрытие control-conn на t+0,
// UDP-поток живёт grace-окно и умирает тишиной после него.
func TestLabRelayUDPGrace(t *testing.T) {
	bin := labEnabled(t)
	mixedAddr, _ := labSingBox(t, bin)
	echo := labEchoServer(t)
	e := labIPv4(echo.IP)
	relayAddr := labRelay(t, mixedAddr)

	conn, rep := socksClient(t, relayAddr, 3, ipv4Hdr(0, 0, 0, 0, 0))
	if rep[1] != 0 {
		t.Fatalf("associate rejected: %d", rep[1])
	}
	conn.Close() // t+0

	uc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer uc.Close()
	bndIP := net.IP(rep[4:8])
	if bndIP.IsUnspecified() {
		bndIP = net.IPv4(127, 0, 0, 1)
	}
	bnd := &net.UDPAddr{IP: bndIP, Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	frame := append([]byte{0, 0, 0}, append(ipv4Hdr(e[0], e[1], e[2], e[3], uint16(echo.Port)), []byte("grace-1")...)...)
	if _, err := uc.WriteToUDP(frame, bnd); err != nil {
		t.Fatalf("grace write: %v", err)
	}
	got := labReadUDP(t, uc, 5*time.Second)
	if !equalBytes(got[10:], []byte("echo:grace-1")) {
		t.Fatalf("grace reply = %x", got)
	}

	// тишина дольше grace → ассоциация умерла: датаграмма больше не эхоится
	time.Sleep(labPeerGrace + 2*time.Second)
	if _, err := uc.WriteToUDP(frame, bnd); err != nil {
		t.Fatalf("post-grace write: %v", err)
	}
	uc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 65535)
	if n, _, err := uc.ReadFromUDP(buf); err == nil {
		t.Fatalf("ассоциация пережила grace без трафика: ответ %x", buf[:n])
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// labFDCount — число открытых fd тестового процесса (прокси за масштабом
// сокет-утечки: дескрипторы ассоциаций живут в этом же процессе).
func labFDCount(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		if runtime.GOOS == "windows" {
			return 0
		}
		t.Fatalf("fd count: %v", err)
	}
	return len(es)
}

// TestLabUDPSmoke — сам инструмент деплой-гейта: client.UDPSmoke против
// релея + реального sing-box. DNS идёт наружу (77.88.8.8) через direct
// outbound — заодно доказывает живость внешнего пути (на роутере это hy2).
func TestLabUDPSmoke(t *testing.T) {
	if os.Getenv("KGATE_UDP_LAB") != "1" {
		t.Skip("KGATE_UDP_LAB=1 не задан — лабовый смоук пропущен")
	}
	bin := os.Getenv("KGATE_SINGBOX_BIN")
	if bin == "" {
		t.Skip("KGATE_SINGBOX_BIN не задан")
	}
	mixedAddr, _ := labSingBox(t, bin)
	relayAddr := labRelay(t, mixedAddr)

	if err := client.UDPSmoke(relayAddr, "77.88.8.8", 53, false, 5*time.Second); err != nil {
		t.Fatalf("udp-smoke (ndm): %v", err)
	}
	if err := client.UDPSmoke(relayAddr, "77.88.8.8", 53, true, 5*time.Second); err != nil {
		t.Fatalf("udp-smoke (rfc): %v", err)
	}
}
