// Package update implements the `kgate update` self-update flow:
// GitHub Releases API -> version compare -> download the platform archive
// -> sha256 verify -> atomic replace of the running binary -> (on the
// router) restart of the S99kgate service.
// Pure net/http over TLS: no curl/wget dependency.
package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const repo = "Korrnals/kgate"

// checksumAsset is the goreleaser checksum file published with every release
// (checksum.name_template in .goreleaser.yaml). Integrity is mandatory:
// without it the download is refused.
const checksumAsset = "checksums-sha256.txt"

// Release mirrors the fields of GET /repos/{repo}/releases/latest we need.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset is one downloadable release artifact.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// ArchiveName builds the goreleaser asset name for a platform
// (kgate_<ver>_<os>_<arch>.tar.gz, ver without the "v" prefix).
func ArchiveName(ver, goos, goarch string) string {
	return "kgate_" + ver + "_" + goos + "_" + goarch + ".tar.gz"
}

// parseVer turns "v1.2.0", "1.2.0-1" or "1.2.0-dev" into a triple.
func parseVer(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Compare returns -1/0/1 for dotted versions; unparseable input falls back to
// lexicographic order (a locally built "dev" binary always updates).
func Compare(a, b string) int {
	av, aok := parseVer(a)
	bv, bok := parseVer(b)
	if !aok || !bok {
		return strings.Compare(a, b)
	}
	if av == bv {
		return 0
	}
	for i := range av {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (r *Release) pickAsset(goos, goarch string) *Asset {
	ver := strings.TrimPrefix(r.TagName, "v")
	want := ArchiveName(ver, goos, goarch)
	for i := range r.Assets {
		if r.Assets[i].Name == want {
			return &r.Assets[i]
		}
	}
	return nil
}

func (r *Release) assetByName(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// ---- TLS-capable HTTP clients ----

// poolFromFile parses a PEM bundle; a missing/unparsable file yields nil.
func poolFromFile(path string) *x509.CertPool {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil
	}
	return pool
}

// clients returns HTTP clients in fallback order: the default Go client
// (honours SSL_CERT_FILE and system stores, incl. firmware /etc/ssl/certs)
// first, then explicit CA files shipped with the ipk or installed by Entware —
// a safety net for firmware builds without a system cert directory.
func clients() []*http.Client {
	mk := func(pool *x509.CertPool) *http.Client {
		tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
		if pool != nil {
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		return &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	var list []*http.Client
	list = append(list, mk(nil))
	for _, p := range []string{"/opt/etc/kgate/ca-bundle.crt", "/opt/etc/ssl/cert.pem"} {
		if pool := poolFromFile(p); pool != nil {
			list = append(list, mk(pool))
		}
	}
	return list
}

// fetch streams url to w trying each client in turn (a TLS failure on the
// system store falls back to the shipped CA bundle).
func fetch(url string, w io.Writer) (int64, error) {
	var lastErr error
	for _, hc := range clients() {
		resp, err := hc.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		n, err := io.Copy(w, resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return n, nil
	}
	if lastErr == nil {
		lastErr = errors.New("нет доступных HTTP-клиентов")
	}
	return 0, lastErr
}

// wantedSha extracts the checksum line for name from goreleaser's
// checksums-sha256.txt ("<hex>  <name>" format).
func wantedSha(sums []byte, name string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			return strings.ToLower(fields[0])
		}
	}
	return ""
}

// extractMember pulls a single file out of a tar.gz archive into dst.
func extractMember(archivePath, member, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("файл %q не найден в архиве", member)
		}
		if err != nil {
			return err
		}
		if h.Name == member || strings.HasSuffix(h.Name, "/"+member) {
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
	}
}

// latestRelease queries the GitHub Releases API (anonymous; the repo is public).
func latestRelease() (*Release, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	var lastErr error
	for _, hc := range clients() {
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("в %s ещё нет релизов", repo)
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GitHub API: HTTP %d", resp.StatusCode)
			continue
		}
		var rel Release
		if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
			return nil, err
		}
		return &rel, nil
	}
	if lastErr == nil {
		lastErr = errors.New("нет доступных HTTP-клиентов")
	}
	return nil, lastErr
}

// Run executes the self-update and returns the process exit code.
func Run(appVersion string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("FAIL: не могу определить путь бинарника:", err)
		return 1
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	fmt.Printf("kgate %s — проверяю обновления (github.com/%s)\n", appVersion, repo)

	rel, err := latestRelease()
	if err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	switch Compare(appVersion, rel.TagName) {
	case 0:
		fmt.Printf("установлена последняя версия (%s) — обновление не требуется\n", appVersion)
		return 0
	case 1:
		fmt.Printf("локальная версия (%s) новее релиза (%s) — обновление не выполняю\n", appVersion, rel.TagName)
		return 0
	}

	asset := rel.pickAsset(runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		fmt.Printf("FAIL: в релизе %s нет артефакта для %s/%s. Доступны:\n", rel.TagName, runtime.GOOS, runtime.GOARCH)
		for _, a := range rel.Assets {
			fmt.Println("  -", a.Name)
		}
		return 1
	}
	fmt.Printf("обновление: %s → %s (%s, %d байт)\n", appVersion, rel.TagName, asset.Name, asset.Size)

	// integrity: refuse to install anything without a matching checksum
	sumsAsset := rel.assetByName(checksumAsset)
	if sumsAsset == nil {
		fmt.Printf("FAIL: в релизе нет %s — целостность проверить нельзя, установка отменена\n", checksumAsset)
		return 1
	}
	var sumsBuf strings.Builder
	if _, err := fetch(sumsAsset.URL, &sumsBuf); err != nil {
		fmt.Println("FAIL: не могу скачать", checksumAsset+":", err)
		return 1
	}
	want := wantedSha([]byte(sumsBuf.String()), asset.Name)
	if want == "" {
		fmt.Printf("FAIL: в %s нет строки для %s — установка отменена\n", checksumAsset, asset.Name)
		return 1
	}

	// download to a temp file next to the target (same fs => atomic rename)
	tmp := filepath.Join(filepath.Dir(exe), ".kgate-update.tmp")
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Println("FAIL:", err)
		return 1
	}
	hash := sha256.New()
	n, err := fetch(asset.URL, io.MultiWriter(f, hash))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(tmp)
		fmt.Println("FAIL: скачивание:", firstErr(err, closeErr))
		return 1
	}
	fmt.Printf("скачано %d байт\n", n)
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		os.Remove(tmp)
		fmt.Printf("FAIL: sha256 не совпал (ожидалось %s, получено %s) — файл удалён\n", want[:12]+"…", got[:12]+"…")
		return 1
	}

	// unpack the binary and atomically swap it in
	bin := filepath.Join(filepath.Dir(exe), ".kgate-new.tmp")
	os.Remove(bin)
	if err := extractMember(tmp, "kgate", bin); err != nil {
		os.Remove(tmp)
		fmt.Println("FAIL: распаковка:", err)
		return 1
	}
	os.Remove(tmp)
	if err := os.Rename(bin, exe); err != nil {
		os.Remove(bin)
		fmt.Println("FAIL: замена бинарника:", err)
		return 1
	}
	fmt.Printf("обновлено: %s (%s)\n", rel.TagName, exe)

	// on the router: restart the service detached — S99 stop does killall kgate,
	// which would otherwise kill THIS process mid-flight. Proxy0 опускается при
	// stop и поднимется автоматически (boot_autoup) через ~25-40с.
	if _, err := os.Stat("/opt/etc/init.d/S99kgate"); err == nil {
		fmt.Println("перезапускаю S99kgate (туннель поднимется автоматически за ~30-60с)…")
		// stop+start вместо restart: у S99, установленного старыми версиями kgate,
		// restart-кейса нет — self-update обязан работать с любым установленным скриптом
		cmd := exec.Command("/bin/sh", "-c",
			"/opt/etc/init.d/S99kgate stop; sleep 1; /opt/etc/init.d/S99kgate start")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			fmt.Println("WARN: перезапуск не запущен — сделай вручную:", err)
		} else {
			fmt.Println("kgate обновлён, сервис перезапускается.")
		}
	} else {
		fmt.Println("новая версия установлена; перезапусти сервис/процесс вручную (на этом хосте S99kgate нет).")
	}
	return 0
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
