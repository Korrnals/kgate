package subscribe

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	uri := "vless://d3361c9a-1cf5-4e4f-b7a1-7a3f7afbcc85@cdn.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBLICKEY123&sid=abcd&type=tcp#RU-Front"
	n, err := parseVLESS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "vless" || n.Tag != "sub-RU-Front" {
		t.Fatalf("tag/type: %+v", n)
	}
	ob := n.Outbound
	if ob["uuid"] != "d3361c9a-1cf5-4e4f-b7a1-7a3f7afbcc85" || ob["server"] != "cdn.example.com" {
		t.Fatalf("outbound: %+v", ob)
	}
	if ob["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow missing")
	}
	tls := ob["tls"].(map[string]any)
	if tls["server_name"] != "www.microsoft.com" {
		t.Fatalf("sni: %+v", tls)
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "PUBLICKEY123" || reality["short_id"] != "abcd" {
		t.Fatalf("reality: %+v", reality)
	}
}

func TestParseHysteria2(t *testing.T) {
	uri := "hysteria2://secretpw@hy2.example.net:8443/?sni=hy2.example.net&obfs=salamander&obfs-password=obfspw#Backup-HY2"
	n, err := parseHysteria2(uri)
	if err != nil {
		t.Fatal(err)
	}
	if n.Outbound["password"] != "secretpw" || n.Outbound["server"] != "hy2.example.net" {
		t.Fatalf("outbound: %+v", n.Outbound)
	}
	if n.Outbound["server_port"] != 8443 {
		t.Fatalf("port: %+v", n.Outbound)
	}
	obfs := n.Outbound["obfs"].(map[string]any)
	if obfs["password"] != "obfspw" {
		t.Fatalf("obfs: %+v", obfs)
	}
}

func TestParseSS(t *testing.T) {
	// форма ss://base64(method:pass@host:port)#name
	inner := "chacha20-ietf-poly1305:sspass@10.2.3.4:8388"
	uri := "ss://" + base64.RawStdEncoding.EncodeToString([]byte(inner)) + "#SS-Node"
	n, err := parseSS(uri)
	if err != nil {
		t.Fatal(err)
	}
	ob := n.Outbound
	if ob["method"] != "chacha20-ietf-poly1305" || ob["password"] != "sspass" || ob["server"] != "10.2.3.4" {
		t.Fatalf("ss outbound: %+v", ob)
	}
}

func TestParseURIListBase64(t *testing.T) {
	list := "vless://uuid-1@a.example:443?sni=a.example#Node-A\nhysteria2://pw@b.example:443?sni=b.example#Node-B"
	b64 := base64.StdEncoding.EncodeToString([]byte(list))
	nodes, err := Parse([]byte(b64))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes: %d", len(nodes))
	}
}

func TestParseSingboxJSON(t *testing.T) {
	cfg := `{"outbounds":[
		{"type":"vless","tag":"my-vless","server":"x","server_port":443,"uuid":"u"},
		{"type":"direct","tag":"direct"},
		{"type":"selector","tag":"sel","outbounds":["my-vless"]}
	]}`
	nodes, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "sub-my-vless" {
		t.Fatalf("json nodes: %+v", nodes)
	}
}

func TestMergeRewritesRoute(t *testing.T) {
	skeleton := []byte(`{
		"inbounds":[{"type":"mixed","tag":"proxy-in"}],
		"outbounds":[{"type":"hysteria2","tag":"hy2-out"},{"type":"direct","tag":"direct"}],
		"route":{"final":"hy2-out","rules":[
			{"clash_mode":"Global","outbound":"hy2-out"},
			{"ip_is_private":true,"outbound":"direct"},
			{"rule_set":["geoip-ru"],"outbound":"direct"}
		]}
	}`)
	nodes, _ := Parse([]byte("vless://u1@n1.example:443#Exit-1\nvless://u2@n2.example:443#Exit-2"))
	merged, err := Merge(skeleton, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(merged, &cfg); err != nil {
		t.Fatal(err)
	}
	obs := cfg["outbounds"].([]any)
	var tags []string
	var sel map[string]any
	for _, o := range obs {
		om := o.(map[string]any)
		tags = append(tags, om["tag"].(string))
		if om["tag"] == "sub-proxy" {
			sel = om
		}
	}
	if len(tags) != 4 { // direct + 2 nodes + selector
		t.Fatalf("tags: %v", tags)
	}
	if sel == nil || sel["default"] != "sub-Exit-1" {
		t.Fatalf("selector: %+v", sel)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "sub-proxy" {
		t.Fatalf("final: %v", route["final"])
	}
	for _, r := range route["rules"].([]any) {
		rm := r.(map[string]any)
		if rm["outbound"] == "hy2-out" {
			t.Fatalf("stale hy2-out reference: %+v", rm)
		}
	}
	if !strings.Contains(string(merged), "sub-Exit-2") {
		t.Fatalf("второй узел потерян")
	}
}

// ---- wave-2: hostile-input coverage for the wave-1 hardening ----

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseSS_NoAt_NoPanic(t *testing.T) {
	// wave-1 MAJOR-1: "method:pass" без @ — было паникой (slice [:-1])
	cases := []string{
		"ss://" + b64("method:pass") + "#x",
		"ss://" + b64("m:p@host") + "#x", // без порта
	}
	for i, uri := range cases {
		n, err := parseSS(uri)
		if err == nil {
			t.Fatalf("case %d: ожидалась ошибка, получен узел %+v", i, n)
		}
	}
}

func TestParseURIList_HostileLinesErrorNotPanic(t *testing.T) {
	// wave-1 MAJOR-1 регрессия: мусор в фиде = чистая ошибка (fail-loud),
	// НИКОГДА паника — скомпрометированный фид не роняет management-тул
	hostile := []string{
		"ss://" + b64("method:pass") + "#x",
		"ss://" + b64("m:p@host") + "#x",
		"ss://!!!bad-b64!!!",
		"vless://",
		"hysteria2://",
		"trojan://",
		"not a uri at all",
		"×«»garbage×«»",
	}
	for _, uri := range hostile {
		nodes, err := parseURIList(uri)
		if err == nil && len(nodes) == 0 {
			t.Fatalf("%q: ни ошибки, ни узлов — тихий no-op?", uri)
		}
	}
	list := strings.Join(hostile, "\n")
	if _, err := Parse([]byte(b64(list))); err == nil {
		t.Fatal("фид целиком из мусора должен дать чистую ошибку")
	}
}

func TestParseSingboxJSON_DuplicateTagsDeduped(t *testing.T) {
	// wave-1 MAJOR-3: два outbound с одним тегом → дубль валит sing-box
	j := []byte(`{"outbounds":[
		{"type":"vless","tag":"proxy","server":"a","server_port":443,"uuid":"u"},
		{"type":"trojan","tag":"proxy","server":"b","server_port":443,"password":"p"}
	]}`)
	nodes, err := parseSingboxJSON(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1 (дубликат отброшен)", len(nodes))
	}
}

func TestParseSingboxJSON_PortBoundsAndTypes(t *testing.T) {
	bad := []byte(`{"outbounds":[{"type":"vless","tag":"p","server":"a","server_port":99999,"uuid":"u"}]}`)
	if _, err := parseSingboxJSON(bad); err == nil {
		t.Fatal("99999 прошёл — ожидалась ошибка границ порта")
	}
	nonNum := []byte(`{"outbounds":[{"type":"vless","tag":"p","server":"a","server_port":"443","uuid":"u"}]}`)
	if _, err := parseSingboxJSON(nonNum); err == nil {
		t.Fatal("строковый server_port прошёл — ожидалась ошибка типа")
	}
}

func TestParseSingboxJSON_DanglingDetourDropped(t *testing.T) {
	// wave-1 MINOR-4: detour на отфильтрованный outbound (selector/пустой тег)
	j := []byte(`{"outbounds":[
		{"type":"selector","tag":"sel","outbounds":["x"]},
		{"type":"vless","tag":"p","server":"a","server_port":443,"uuid":"u","detour":"sel"}
	]}`)
	nodes, err := parseSingboxJSON(j)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if _, has := n.Outbound["detour"]; has {
			t.Fatalf("висячий detour остался: %+v", n.Outbound)
		}
	}
}

func TestMerge_SelectorTagCollisionRenamed(t *testing.T) {
	// wave-1 MAJOR-2: селектор "sub-proxy" священен — узел с фрагментом
	// "sub-proxy" коллидирует и переименовывается (дубль тега валит sing-box)
	nodes := []Node{
		{Tag: "sub-proxy", Outbound: map[string]any{"type": "vless", "server": "a", "server_port": 443}},
		{Tag: "proxy", Outbound: map[string]any{"type": "trojan", "server": "b", "server_port": 443}},
	}
	out, err := Merge([]byte(`{"outbounds":[{"type":"hysteria2","tag":"hy2-out","server":"s","server_port":1}],"route":{"rules":[{"outbound":"hy2-out"}]}}`), nodes)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	tags := map[string]int{}
	for _, ob := range cfg["outbounds"].([]any) {
		m := ob.(map[string]any)
		tags[m["tag"].(string)]++
	}
	if tags[selectorTag] != 1 {
		t.Fatalf("селектор задублирован: %v", tags)
	}
	if tags["sub-proxy-2"] != 1 {
		t.Fatalf("коллидирующий узел не переименован в sub-proxy-2: %v", tags)
	}
	if tags["proxy"] != 1 {
		t.Fatalf("обычный узел 'proxy' должен сохранить тег: %v", tags)
	}
}

// wave-2 F9: политика редиректов подписочного клиента — только https и тот же
// host: https→http downgrade и чужой host отклонены (утечка URL фида и
// plaintext-загрузка конфигов).
func TestFetch_RedirectPolicy(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload-ok"))
	}))
	defer final.Close()

	start := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.Write([]byte("payload-ok"))
			return
		}
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	}))
	defer start.Close()
	// прод-политика fetchClient + доверие к тестовому серту start-сервера
	client := fetchClient()
	client.Transport = start.Client().Transport

	// ok: редирект на свой же https-путь (тот же host)
	b, err := fetch(start.URL+"/start?to="+url.QueryEscape(start.URL+"/final"), client)
	if err != nil {
		t.Fatalf("same-host https redirect должен пройти: %v", err)
	}
	if string(b) != "payload-ok" {
		t.Fatalf("body = %q", string(b))
	}

	// отказ: редирект на http (downgrade)
	httpTarget := "http://" + strings.TrimPrefix(start.URL, "https://") + "/plain"
	if _, err := fetch(start.URL+"/start?to="+url.QueryEscape(httpTarget), client); err == nil {
		t.Fatal("редирект на http должен быть отклонён")
	} else if !strings.Contains(err.Error(), "только https") {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	// отказ: редирект на чужой host (другой тестовый сервер)
	if _, err := fetch(start.URL+"/start?to="+url.QueryEscape(final.URL+"/elsewhere"), client); err == nil {
		t.Fatal("редирект на чужой host должен быть отклонён")
	} else if !strings.Contains(err.Error(), "чужой host") {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	// тот же клиент с прод-политикой отклоняет и редирект-цепочку глубже 1-го шага
	if _, err := fetch(start.URL+"/start?to="+url.QueryEscape(httpTarget), client); err == nil {
		t.Fatal("клиент с прод-политикой должен отклонять redirect на http")
	}
}
