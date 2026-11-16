// UDP smoke — круговой датаграммный тест релея (kgate-004, деплой-гейт).
//
// Проходит РОВНО тот путь, которым LAN-клиенты несут UDP через туннель:
// SOCKS5 cmd=5 0.0.0.0:0 к релею (диалект ndm-клиента) → ndm UDP-over-TCP
// кадр [len][dst_ip][src_port][dst_port][DNS-запрос] в control-конн →
// релей бриджит в sing-box UDP endpoint → туннель → DNS-сервер → ответ
// возвращается кадром в control-конн. Провал = ненулевой rc: деплоер
// использует это как гейт live-swap (провал = автооткат бинаря).
//
// Режим --rfc проверяет вторую клиентскую ногу (cmd=3 + RFC 1928 §7
// фрейминг на BND-сокете) — путь KeeneticOS socks5-udp и обычных клиентов.
package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// UDPSmoke делает один круговой UDP-тест через релей на socksAddr.
// dnsIP/dnsPort — резолвер, через который обязан пройти датаграммный запрос
// (выбирай общедоступный — так тест заодно доказывает живость туннеля).
// rfc — RFC-нога (cmd=3 + UDP-сокет) вместо ndm-диалекта.
// Возвращает ошибку с человеческой причиной или nil при полном круге.
func UDPSmoke(socksAddr, dnsIP string, dnsPort int, rfc bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	conn, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return fmt.Errorf("релей %s недоступен: %w", socksAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	// greeting
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	if rep[0] != 5 || rep[1] != 0 {
		return fmt.Errorf("релей не SOCKS5/no-auth: %x", rep)
	}

	// cmd=5 (ndm) или cmd=3 (RFC), dst 0.0.0.0:0
	cmdByte := byte(5)
	if rfc {
		cmdByte = 3
	}
	if _, err := conn.Write([]byte{5, cmdByte, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("cmd=%d write: %w", cmdByte, err)
	}
	rhdr := make([]byte, 10) // VER REP RSV ATYP(1) ADDR(4) PORT(2)
	if _, err := io.ReadFull(conn, rhdr); err != nil {
		return fmt.Errorf("associate reply: %w", err)
	}
	if rhdr[1] != 0 {
		return fmt.Errorf("ассоциация отвергнута: rep=%d", rhdr[1])
	}
	bndIP := net.IP(rhdr[4:8])
	bndPort := binary.BigEndian.Uint16(rhdr[8:10])
	verb := "ndm UDP-over-TCP (cmd=5)"
	if rfc {
		verb = "RFC 1928 §7 (cmd=3)"
	}
	fmt.Printf("smoke: ассоциация ok (%s), bnd=%s:%d\n", verb, bndIP, bndPort)

	query := dnsQueryA(0x1234, "ya.ru")

	if !rfc {
		// ndm-диалект: DNS-датаграмма в control-конн
		frame := make([]byte, 10+len(query))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(query)))
		copy(frame[2:6], net.ParseIP(dnsIP).To4())
		binary.BigEndian.PutUint16(frame[6:8], 53535) // src_port (любой)
		binary.BigEndian.PutUint16(frame[8:10], uint16(dnsPort))
		copy(frame[10:], query)
		if _, err := conn.Write(frame); err != nil {
			return fmt.Errorf("ndm-кадр write: %w", err)
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("ответ не пришёл в control-конн (%v) — UDP data-path релея мёртв", err)
		}
		if n < 10 {
			return fmt.Errorf("короткий ответ %d байт", n)
		}
		return checkDNSReply(buf[10:n])
	}

	// RFC-нога: фрейм на BND-сокет
	if bndIP.IsUnspecified() {
		h, _, err := net.SplitHostPort(socksAddr)
		if err != nil || h == "" {
			h = "127.0.0.1"
		}
		bndIP = net.ParseIP(h)
	}
	uc, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", bndIP, bndPort), timeout)
	if err != nil {
		return fmt.Errorf("bnd udp dial: %w", err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(deadline)
	frame := append([]byte{0, 0, 0, 1}, net.ParseIP(dnsIP).To4()...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(dnsPort))
	frame = append(frame, pb[:]...)
	frame = append(frame, query...)
	if _, err := uc.Write(frame); err != nil {
		return fmt.Errorf("bnd udp write: %w", err)
	}
	buf := make([]byte, 65535)
	n, err := uc.Read(buf)
	if err != nil {
		return fmt.Errorf("ответ не пришёл на BND-сокет (%v) — UDP data-path релея мёртв", err)
	}
	return checkDNSReply(buf[10:n]) // RSV FRAG ATYP(1)+ADDR(4)+PORT(2)
}

// dnsQueryA собирает минимальный DNS-запрос A-записи (рекурсия желательна).
func dnsQueryA(id uint16, name string) []byte {
	q := make([]byte, 0, 512)
	q = append(q, byte(id>>8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // RD, QDCOUNT=1
	for _, label := range splitDots(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	return q
}

func splitDots(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, name[start:])
	}
	return out
}

// checkDNSReply проверяет, что payload — валидный DNS-ответ на наш запрос.
func checkDNSReply(payload []byte) error {
	if len(payload) < 12 {
		return fmt.Errorf("DNS-ответ короткий: %d байт", len(payload))
	}
	id := binary.BigEndian.Uint16(payload[0:2])
	if id != 0x1234 {
		return fmt.Errorf("DNS id %04x, want 1234", id)
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return fmt.Errorf("DNS: бит QR не выставлен (это не ответ)")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return fmt.Errorf("DNS rcode=%d", rcode)
	}
	fmt.Printf("smoke: DNS-ответ ok (%d байт) — UDP data-path жив\n", len(payload))
	return nil
}
