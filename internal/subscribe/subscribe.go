// Package subscribe parses VPN-provider subscriptions (base64 URI lists:
// vless://, hysteria2://, trojan://, ss:// — and sing-box JSON configs) and
// merges the resulting outbounds into the kgate sing-box skeleton, keeping
// kgate's own inbounds and RU-split routing intact.
package subscribe

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node is one parsed subscription entry, ready to become a sing-box outbound.
type Node struct {
	Tag       string         `json:"tag"`
	Type      string         `json:"type"` // vless|hysteria2|trojan|shadowsocks
	Outbound  map[string]any `json:"outbound"`
	RawServer string         `json:"raw_server"`
}

const selectorTag = "sub-proxy" // selector outbound kgate's route rules point at
const legacyTag = "hy2-out"     // static skeleton's tunnel tag (rewritten)
const directTag = "direct"      // kept as-is
const tagPrefix = "sub"         // node tag prefix

// Parse detects the payload format and returns nodes.
// Formats: sing-box JSON (object with "outbounds"), or base64/plain URI list
// (vless:// hysteria2:// trojan:// ss:// lines).
func Parse(payload []byte) ([]Node, error) {
	trimmed := strings.TrimSpace(string(payload))
	if strings.HasPrefix(trimmed, "{") {
		return parseSingboxJSON([]byte(trimmed))
	}
	// base64? (subscription servers commonly return base64 of the URI list)
	if !strings.Contains(trimmed, "://") {
		if dec, err := base64.StdEncoding.DecodeString(trimmed); err == nil &&
			strings.Contains(string(dec), "://") {
			trimmed = strings.TrimSpace(string(dec))
		} else if dec, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil &&
			strings.Contains(string(dec), "://") {
			trimmed = strings.TrimSpace(string(dec))
		}
	}
	return parseURIList(trimmed)
}

func parseURIList(list string) ([]Node, error) {
	var nodes []Node
	seen := map[string]bool{}
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var (
			n   Node
			err error
		)
		switch {
		case strings.HasPrefix(line, "vless://"):
			n, err = parseVLESS(line)
		case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
			n, err = parseHysteria2(line)
		case strings.HasPrefix(line, "trojan://"):
			n, err = parseTrojan(line)
		case strings.HasPrefix(line, "ss://"):
			n, err = parseSS(line)
		default:
			continue // vmess:// и прочие — позже
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", short(line), err)
		}
		if seen[n.Tag] {
			continue
		}
		seen[n.Tag] = true
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("подписка не содержит поддерживаемых узлов (vless/hysteria2/trojan/ss)")
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Tag < nodes[j].Tag })
	return nodes, nil
}

func short(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}

// parseSingboxJSON extracts usable outbounds from a sing-box client config.
func parseSingboxJSON(b []byte) ([]Node, error) {
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	skip := map[string]bool{"direct": true, "block": true, "dns": true, "selector": true, "urltest": true}
	var nodes []Node
	for _, ob := range cfg.Outbounds {
		tag, _ := ob["tag"].(string)
		typ, _ := ob["type"].(string)
		if tag == "" || skip[typ] {
			continue
		}
		server, _ := ob["server"].(string)
		nodes = append(nodes, Node{Tag: tagPrefix + "-" + tag, Type: typ,
			Outbound: ob, RawServer: server})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("в JSON-подписке нет клиентских outbounds")
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Tag < nodes[j].Tag })
	return nodes, nil
}

// ---- URI parsers ----

func parseVLESS(uri string) (Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Node{}, err
	}
	if u.Scheme != "vless" {
		return Node{}, fmt.Errorf("не vless")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return Node{}, fmt.Errorf("vless: нет host/port")
	}
	q := u.Query()
	get := func(k string) string { return q.Get(k) }
	name := shortName(u.Fragment)
	// uuid: userinfo или query
	uuid := u.User.Username()
	if uuid == "" {
		uuid = get("uuid")
	}
	if uuid == "" {
		return Node{}, fmt.Errorf("vless: нет uuid")
	}
	security := get("security") // tls|reality|none
	out := map[string]any{
		"type":            "vless",
		"tag":             "",
		"server":          host,
		"server_port":     atoi(port, 443),
		"uuid":            uuid,
		"packet_encoding": "xudp",
	}
	if flow := get("flow"); flow != "" {
		out["flow"] = flow // xtls-rprx-vision
	}
	if security == "tls" || security == "reality" || get("sni") != "" {
		tls := map[string]any{"enabled": true}
		if sni := get("sni"); sni != "" {
			tls["server_name"] = sni
		}
		if ins := get("allowInsecure"); ins == "1" || ins == "true" {
			tls["insecure"] = true
		}
		if fp := get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if security == "reality" {
			reality := map[string]any{"enabled": true}
			if pbk := get("pbk"); pbk != "" {
				reality["public_key"] = pbk
			}
			if sid := get("sid"); sid != "" {
				reality["short_id"] = sid
			}
			tls["reality"] = reality
		}
		out["tls"] = tls
	}
	net_ := get("type")
	switch net_ {
	case "ws":
		tr := map[string]any{"type": "ws"}
		if p := get("path"); p != "" {
			tr["path"] = p
		}
		if h := get("host"); h != "" {
			tr["headers"] = map[string]any{"Host": h}
		}
		out["transport"] = tr
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if sn := get("serviceName"); sn != "" {
			tr["service_name"] = sn
		}
		out["transport"] = tr
	}
	out["tag"] = name
	return Node{Tag: name, Type: "vless", Outbound: out, RawServer: host}, nil
}

func parseHysteria2(uri string) (Node, error) {
	u, err := url.Parse(strings.Replace(uri, "hy2://", "hysteria2://", 1))
	if err != nil {
		return Node{}, err
	}
	if u.Scheme != "hysteria2" {
		return Node{}, fmt.Errorf("не hysteria2")
	}
	host := u.Hostname()
	port := u.Port()
	password := u.User.Username()
	if host == "" || port == "" {
		return Node{}, fmt.Errorf("hysteria2: нет host/port")
	}
	q := u.Query()
	name := shortName(u.Fragment)
	out := map[string]any{
		"type":        "hysteria2",
		"tag":         name,
		"server":      host,
		"server_port": atoi(port, 443),
		"password":    password,
	}
	if sni := q.Get("sni"); sni != "" {
		tls := map[string]any{"enabled": true, "server_name": sni}
		if q.Get("insecure") == "1" || q.Get("insecure") == "true" {
			tls["insecure"] = true
		}
		out["tls"] = tls
	}
	if obfs := q.Get("obfs"); obfs != "" {
		o := map[string]any{"type": obfs}
		if op := q.Get("obfs-password"); op != "" {
			o["password"] = op
		}
		out["obfs"] = o
	}
	return Node{Tag: name, Type: "hysteria2", Outbound: out, RawServer: host}, nil
}

func parseTrojan(uri string) (Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Node{}, err
	}
	if u.Scheme != "trojan" {
		return Node{}, fmt.Errorf("не trojan")
	}
	host, port := u.Hostname(), u.Port()
	password := u.User.Username()
	if host == "" || port == "" || password == "" {
		return Node{}, fmt.Errorf("trojan: неполный URI")
	}
	q := u.Query()
	name := shortName(u.Fragment)
	out := map[string]any{
		"type": "trojan", "tag": name,
		"server": host, "server_port": atoi(port, 443),
		"password": password,
	}
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	out["tls"] = tls
	if t := q.Get("type"); t == "ws" {
		tr := map[string]any{"type": "ws"}
		if p := q.Get("path"); p != "" {
			tr["path"] = p
		}
		out["transport"] = tr
	}
	return Node{Tag: name, Type: "trojan", Outbound: out, RawServer: host}, nil
}

func parseSS(uri string) (Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Node{}, err
	}
	if u.Scheme != "ss" {
		return Node{}, fmt.Errorf("не ss")
	}
	host, port := u.Hostname(), u.Port()
	name := shortName(u.Fragment)
	method, password := "", ""
	if u.User != nil {
		// ss://base64(method:pass)@host:port
		if info, err := base64.RawStdEncoding.DecodeString(u.User.Username()); err == nil {
			parts := strings.SplitN(string(info), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		} else if info, err := base64.StdEncoding.DecodeString(u.User.Username()); err == nil {
			parts := strings.SplitN(string(info), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		}
	}
	// альтернативная форма: ss://base64(method:pass@host:port)#name
	if method == "" {
		body := strings.TrimPrefix(strings.SplitN(uri, "//", 2)[1], "")
		if q := strings.IndexAny(body, "?#"); q != -1 {
			body = body[:q]
		}
		if dec, err := base64.RawStdEncoding.DecodeString(body); err == nil && strings.Contains(string(dec), ":") {
			last := strings.LastIndex(string(dec), "@")
			info := string(dec[:last])
			parts := strings.SplitN(info, ":", 2)
			hostport := string(dec[last+1:])
			hp := strings.Split(hostport, ":")
			method, password = parts[0], parts[1]
			host, port = hp[0], hp[1]
		}
	}
	if method == "" || password == "" || host == "" {
		return Node{}, fmt.Errorf("ss: не удалось разобрать URI")
	}
	return Node{
		Tag:  name,
		Type: "shadowsocks",
		Outbound: map[string]any{
			"type": "shadowsocks", "tag": name,
			"server": host, "server_port": atoi(port, 443),
			"method": method, "password": password,
		},
		RawServer: host,
	}, nil
}

// ---- merge ----

// Merge injects node outbounds into the kgate sing-box skeleton: drops the
// static tunnel outbound (hy2-out), adds nodes + a selector, and rewrites
// route references so RU-split rules keep working unchanged.
func Merge(skeleton []byte, nodes []Node) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(skeleton, &cfg); err != nil {
		return nil, fmt.Errorf("скелет конфига: %w", err)
	}
	var obs []any
	// direct из скелета сохраняем
	if sk, ok := cfg["outbounds"].([]any); ok {
		for _, o := range sk {
			om, _ := o.(map[string]any)
			if t, _ := om["tag"].(string); t == directTag {
				obs = append(obs, o)
			}
		}
	}
	var candidates []string
	for _, n := range nodes {
		om := n.Outbound
		om["tag"] = n.Tag // shortName уже дал префикс sub-
		candidates = append(candidates, om["tag"].(string))
		obs = append(obs, om)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("нет узлов для selector")
	}
	selector := map[string]any{
		"type":      "selector",
		"tag":       selectorTag,
		"outbounds": candidates,
		"default":   candidates[0],
	}
	obs = append(obs, selector)
	cfg["outbounds"] = obs

	// route: переписать ссылки legacyTag -> selectorTag; final тоже
	if route, ok := cfg["route"].(map[string]any); ok {
		if route["final"] == legacyTag {
			route["final"] = selectorTag
		}
		if rules, ok := route["rules"].([]any); ok {
			for _, rr := range rules {
				if rm, ok := rr.(map[string]any); ok {
					if rm["outbound"] == legacyTag {
						rm["outbound"] = selectorTag
					}
				}
			}
		}
		cfg["route"] = route
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	return out, err
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil && v > 0 {
		return v
	}
	return def
}

// Fetch downloads a subscription payload (provider endpoint).
func Fetch(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kgate/1.4")
	req.Header.Set("Accept", "*/*")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func shortName(frag string) string {
	n := strings.TrimSpace(frag)
	if n == "" {
		n = "node"
	}
	// тег сингбокса: буквы/цифры/-/_/.
	var b strings.Builder
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return tagPrefix + "-" + b.String()
}
