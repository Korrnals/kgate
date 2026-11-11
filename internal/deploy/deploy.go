// Package deploy pushes kgate and the VPN stack to the router over ssh.
// Every stage reports itself to the console with a colored ✓/✗ mark and
// duration (plain text when stdout is not a terminal or NO_COLOR is set).
package deploy

import (
	"net"
	"path/filepath"

	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"kgate/internal/certs"
	"kgate/internal/model"
)

// Payload объявлен в deploy_stub.go (по умолчанию: 45B заглушка) и
// deploy_real.go (-tags kgate_real_payload: реальный payload из payload.tgz).

// payloadIsPlaceholder reports the embedded 45-byte stub committed for fresh
// checkouts: deploying it would unpack nothing and wipe nothing, but the
// stack would be left broken — refuse loudly instead.
func payloadIsPlaceholder() bool { return len(Payload) < 1<<20 }

type Runner struct {
	c        *model.Config
	dry      bool
	color    bool
	ssh      *sshRunner
	failures int
}

func New(c *model.Config, dry bool) *Runner {
	return &Runner{c: c, dry: dry, color: useColor(), ssh: newSSHRunner(c)}
}

// Failures returns the number of failed steps so far.
func (r *Runner) Failures() int { return r.failures }

// ---- console UX ----

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (r *Runner) mark(ok bool) string {
	if !r.color {
		if ok {
			return "[OK]"
		}
		return "[FAIL]"
	}
	if ok {
		return "\033[32m✓\033[0m"
	}
	return "\033[31m✗\033[0m"
}

// step runs a named script, printing a colored ✓/✗ line with duration; on
// failure the script output is indented under the mark and failures counter
// grows.
func (r *Runner) step(name, script string) string {
	if r.dry {
		fmt.Printf("  %s %s (dry-run, скрипт пропущен)\n", r.mark(true), name)
		return ""
	}
	t0 := time.Now()
	out, err := r.ssh.run(script)
	d := time.Since(t0).Round(100 * time.Millisecond)
	if err != nil {
		r.failures++
		fmt.Printf("  %s %s (%v)\n", r.mark(false), name, d)
	} else {
		fmt.Printf("  %s %s (%v)\n", r.mark(true), name, d)
	}
	// вывод скрипта виден и на успехе (с отступом): version-evidence,
	// S99 status — зелёная галочка должна быть объяснима из консоли
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line != "" {
			fmt.Println("      " + line)
		}
	}
	return out
}

// upload transfers data with the same step reporting; fatal failures abort.
func (r *Runner) upload(data []byte, remoteCmd, name string) {
	if r.dry {
		fmt.Printf("  %s %s (dry-run, %d байт не передаются)\n", r.mark(true), name, len(data))
		return
	}
	t0 := time.Now()
	err := r.ssh.upload(data, remoteCmd)
	d := time.Since(t0).Round(100 * time.Millisecond)
	if err != nil {
		r.failures++
		fmt.Printf("  %s %s (%v): %v\n", r.mark(false), name, d, err)
		return
	}
	fmt.Printf("  %s %s — %d байт (%v)\n", r.mark(true), name, len(data), d)
}

// fatal prints a red abort line and exits — used for pre-flight blockers
// where continuing would leave the router half-configured.
func (r *Runner) fatal(msg string) {
	fmt.Printf("  %s %s\n", r.mark(false), msg)
	os.Exit(1)
}

// DestroyPlan renders what Destroy will do — printed for confirmation.
func DestroyPlan(c *model.Config) string {
	pins := c.ServerIP
	if pins == "" {
		pins = "—"
	}
	return fmt.Sprintf(`Действия на роутере %s:
  - остановить S99kgate (Proxy0 опустится — дом пойдёт напрямую)
  - opkg remove kgate, если стек ставился пакетом (снимет и sing-box)
  - удалить файлы: /opt/sbin/{kgate,sing-box}, /opt/etc/{kgate,sing-box},
    init-скрипт, ndm-commands.sh, логи
  - ndm: снять route-pin'ы (%s, 77.88.8.8) и name-server 77.88.8.8
  - ndm: ПОЛНОСТЬЮ удалить интерфейс Proxy0 и политики-сценарии
    (v2: VPN, NO-VPN; legacy v1: VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN)
  - проверить, что следов kgate в running-config не осталось
Останется: sshd и Entware; клиентские файлы на ноутбуке
(~/.kgate, ~/.local/bin/kgate).`, c.Host, pins)
}

// serverIPOrFatal validates ServerIP before it is interpolated into root-shell
// scripts (ndmc and destroy verbs, wave-1 B3): a non-IP string (hostname,
// shell metachars) would be interpreted by the remote sh as root. Fatal —
// конфигурация-ошибка, до ssh.
func (r *Runner) serverIPOrFatal() string {
	if r.c.ServerIP != "" && net.ParseIP(r.c.ServerIP) == nil { // пустой = легаси-деградация (как раньше), битый = отказ до ssh
		r.fatal(fmt.Sprintf("конфиг: server_ip %q — не валидный IP (net.ParseIP); деплой/destroy отменён до ssh", r.c.ServerIP))
	}
	return r.c.ServerIP
}

// ---- deploy stages ----

func (r *Runner) Preflight() {
	fmt.Println("→ preflight")
	r.step("Entware на месте, uptime", `test -d /opt/etc/init.d || { echo "Entware NOT mounted"; exit 1; }; cat /proc/uptime | awk "{print \"uptime: \" \$1 \"s\"}"`)
}

func (r *Runner) Files() {
	if payloadIsPlaceholder() && !r.dry {
		fmt.Println("→ deploy: files")
		r.fatal("встроенный payload — заглушка; релизный бинарь не несёт стек. Собери локально: make payload, затем повтори kgate deploy")
	}
	fmt.Println("→ deploy: files")
	r.upload(Payload, `cat > /tmp/payload.tgz`, "передача payload на роутер")
	// режим подписки: локальный merged-конфиг едет на роутер ВМЕСТО шаблона
	// ТОЛЬКО при активной подписке (состояние subscribe.json существует) и
	// валидном JSON. Протухшая копия после subscribe remove больше не
	// воскресает подписку (wave-1 review MAJOR-6/MINOR-1); fallback на файл
	// из TMPDIR убран — при чужом TMPDIR он подкладывал мусор в конфиг.
	h, _ := os.UserHomeDir()
	subConfig := filepath.Join(h, "subscribe-config.json")
	_, subStatErr := os.Stat(filepath.Join(h, "subscribe.json"))
	if subStatErr == nil {
		if b, err := os.ReadFile(subConfig); err == nil && len(b) > 2 && json.Valid(b) {
			r.upload(b, `mkdir -p /opt/etc/sing-box && cat > /opt/etc/sing-box/config.json`, "конфиг из подписки (замена шаблона)")
		}
	}
	r.step("распаковка и раскладка (бинари, S99, ndm, конфиг, rulesets)", `set -e
mkdir -p /tmp/px && cd /tmp/px && rm -rf * && tar -xzf /tmp/payload.tgz
mv -f kgate-arm64 /opt/sbin/kgate
mv -f sing-box /opt/sbin/sing-box
mv -f ndm-commands.sh /opt/etc/ndm-commands.sh
mv -f S99kgate /opt/etc/init.d/S99kgate
mkdir -p /opt/etc/sing-box/rulesets
# sing-box конфиг: НЕ перетираем существующий (им может управлять kgate subscribe
# или руки оператора); на чистом роутере кладём шаблон из payload
if [ -s /opt/etc/sing-box/config.json ]; then echo "config.json: сохранён (существующий/подписочный)"; else cp -f root/opt/etc/sing-box/config.json /opt/etc/sing-box/config.json; fi
cp -f root/opt/etc/sing-box/rulesets/*.srs /opt/etc/sing-box/rulesets/ 2>/dev/null
cp -f root/opt/etc/ssh/authorized_keys /opt/etc/ssh/authorized_keys.new
grep -q "^sshd:" /opt/etc/passwd || cat root/opt/etc/passwd >> /opt/etc/passwd
# ssh-ключи: НИКОГДА не затирать существующие — релизный payload несёт
# санитизированную заглушку, и безусловный cp запер бы оператора снаружи
# (v1.4.1 E2E: поймано живьём); заглушка кладётся только на чистый роутер
[ -s /opt/etc/ssh/authorized_keys ] || mv -f /opt/etc/ssh/authorized_keys.new /opt/etc/ssh/authorized_keys
rm -f /opt/etc/ssh/authorized_keys.new
chmod +x /opt/sbin/kgate /opt/sbin/sing-box /opt/etc/init.d/S99kgate
rm -rf /tmp/px /tmp/payload.tgz
mkdir -p /opt/etc/kgate /opt/etc/ssh /opt/var/log /opt/var/run
# version-evidence БЕЗ съеденного exit-кода (wave-1 B1): head в пайпе маскировал
# бы падение самого бинаря
v=$(/opt/sbin/kgate version) || { echo "kgate version FAILED"; exit 1; }
echo "$v" | head -1`)
	r.step("opkg-зависимости (iptables, openssh-server)", `opkg update >/dev/null 2>&1; for p in iptables openssh-server; do opkg list-installed | grep -q "^$p " || opkg install $p; done; opkg list-installed | grep -E "^(iptables|openssh-server) " | head -2`)
}

func (r *Runner) Migrate() {
	fmt.Println("→ deploy: migrate (legacy под замок)")
	// retire a previous routerctl install (if any); the kgate daemon takes over the stack
	r.step("retire S99routerctl, глушение S99sing-box/S24xray, чистка rc.unslung", `set -e
# set -e (wave-2 F2): retire мутирует init-скрипты — тихий частичный провал
# оставляет легаси живым. Условия — через if/fi (false-условие при set -e
# скрипт не убивает), killall без процесса — явный || true.
if [ -f /opt/etc/init.d/S99routerctl ]; then /opt/etc/init.d/S99routerctl stop 2>/dev/null; mv /opt/etc/init.d/S99routerctl /opt/etc/init.d/S99routerctl.disabled; fi
rm -f /opt/var/run/routerctl*.pid /opt/var/run/routerctl.pid
if [ -f /opt/etc/init.d/S99sing-box ]; then mv /opt/etc/init.d/S99sing-box /opt/etc/init.d/S99sing-box.disabled; fi
grep -vE "(rc-redirect|boot-autoup|\{kgate\})" /opt/etc/init.d/rc.unslung > /tmp/rcu && cat /tmp/rcu > /opt/etc/init.d/rc.unslung && rm /tmp/rcu
for P in $(ps w | grep "[r]c-redirect-watchdog" | awk "{print \$1}"); do kill $P 2>/dev/null; done   # bracket-trick: не матчим собственный sh (wave-1 C7)
if [ -f /opt/etc/init.d/S24xray ]; then mv /opt/etc/init.d/S24xray /opt/etc/init.d/S24xray.disabled; fi
killall xray 2>/dev/null || true
echo "legacy disabled"`)
}

func (r *Runner) ConfigAndCerts(cfg *model.Config) {
	fmt.Println("→ deploy: config + mTLS certs")
	yml, _ := yamlMarshal(cfg)
	r.upload(yml, `mkdir -p /opt/etc/kgate && cat > /opt/etc/kgate/kgate.yaml`, "рендер kgate.yaml на роутер")
	if r.dry {
		fmt.Printf("  %s mTLS-сертификаты (dry-run: генерация и чтение пропущены)\n", r.mark(true))
		return
	}
	// каталог сертов = каталог api.ca из конфига (уже развёрнут expandHomes;
	// имена файлов фиксированы генерацией certs.Ensure)
	certDir := filepath.Dir(cfg.API.CA)
	created, err := certs.Ensure(certDir, cfg.Host)
	if err != nil {
		r.fatal("генерация mTLS-сертификатов: " + err.Error())
	}
	fmt.Printf("  %s mTLS-сертификаты: %s\n", r.mark(true), map[bool]string{true: "сгенерированы новые (ECDSA P-256)", false: "переиспользованы существующие"}[created])
	home := certDir
	for _, pair := range [][2]string{
		{home + "/ca.crt", "/opt/etc/kgate/ca.crt"},
		{home + "/server.crt", "/opt/etc/kgate/server.crt"},
		{home + "/server.key", "/opt/etc/kgate/server.key"},
	} {
		b, err := os.ReadFile(pair[0])
		if err != nil {
			r.fatal("чтение " + pair[0] + ": " + err.Error())
		}
		r.upload(b, `cat > `+pair[1], "загрузка "+pair[1])
	}
	r.step("chmod 600 server.key", `chmod 600 /opt/etc/kgate/server.key`)
}

func (r *Runner) NDM() {
	serverIP := r.serverIPOrFatal()
	fmt.Println("→ deploy: ndm (Proxy0, пины, DNS, политики policy-v2)")
	r.step("ndm-commands.sh идемпотентным прогоном", `{ test -f /opt/etc/ndm-commands.sh || { echo "ndm-commands.sh missing — run kgate files first"; exit 1; }; KGATE_SERVER_IP="`+serverIP+`" sh /opt/etc/ndm-commands.sh 2>&1; }`)
	// belt and suspenders (policy-v2, поле-наблюдение 09.11): веб «Приоритеты
	// доступов» при каждом save возвращает застоявшийся статический
	// `ip route 0.0.0.0/0 Proxy0` — а дефолтная политика с ним смотрит не
	// только на ISP. Явный un-route ПОСЛЕ ndm-commands.sh (там он тоже есть)
	// — IaC-гарантия честного дефолта = ISP.
	// set -e (wave-2 F2); grep -c при нуле совпадений выходит 1 — || true в
	// $(…) не даёт set -e убить шаг
	r.step("un-route stale 0.0.0.0/0 Proxy0 (честный дефолт = ISP)", `set -e
ndmc -c "no ip route 0.0.0.0/0 Proxy0"; n=$(ndmc -c "show ip route" | grep -c "0.0.0.0/0.*Proxy0" || true); [ "$n" = "0" ] && echo "default policy: ISP only (ok)" || echo "WARNING: 0.0.0.0/0 Proxy0 всё ещё в таблице ($n) — проверь веб «Приоритеты доступов»"`)
	// system configuration save ПОСЛЕ подъёма Proxy0: веб-переключатель читает
	// конфиг-вью (show.sc.interface up), и для объекта, хоть раз тронутого
	// вебом/RCI, up-узел в нём материализуется ТОЛЬКО явным save — без него
	// тумблер в дашборде рисует OFF при рабочем туннеле (см. investigate:
	// kgate-session-reports/tumbler-verdict.md). Save также фиксирует intent
	// "up" во flash — после ребута ОС уважает его.
	r.step("system configuration save (веб-модель тумблера + intent up)", `set -e
# set -e + явный ассерт (wave-2 F2): провал save стопает шаг ДО записи intent —
# иначе intent=up пишется при НЕсохранённом флеше и переживает ребут ложью
ndmc -c "system configuration save" || { echo "ndmc save FAILED — intent НЕ записывается"; exit 1; }
echo saved
mkdir -p /opt/etc/kgate
# ГРОМКОЕ предупреждение при перевороте явно выключенного владельцем туннеля (wave-1 B4):
if [ -f /opt/etc/kgate/intent ] && [ "$(cat /opt/etc/kgate/intent 2>/dev/null)" = "down" ]; then
  echo "WARNING: существовал intent=down (туннель явно выключен владельцем) — deploy ПЕРЕВОРАЧИВАЕТ его в up"
  echo "WARNING: если это не ожидаемо — после deploy выполни: kgate toggle off"
fi
echo up > /opt/etc/kgate/intent`)
}

func (r *Runner) Services() {
	fmt.Println("→ deploy: services")
	// stop+start, не restart: у S99, развёрнутого старыми версиями kgate,
	// restart-кейса нет — --only services обязан работать с любой генерацией скрипта
	// kgate-1.4.4: принудительно свежий sing-box — живой старый процесс
	// (переживший killall) больше НЕ усыновляется свежим демоном: перед
	// стартом демона глушим движки и чистим их pidfiles, иначе конфиги,
	// заменённые files-стадией, не вступают в силу
	r.step("S99kgate stop + свежий движок + start + статус", `set -e
# set -e (wave-2 F2); stop/killall «нет процесса» легитимен — || true,
# финальный status остаётся честным гейтом шага
# deploy-маркер: супервизор демона 3 минуты НЕ делает web-switch adoption
# (окно рестарта движка выглядит как «внешнее выключение» — поле 2026-11-11)
date +%s > /opt/etc/kgate/deploy.epoch
/opt/etc/init.d/S99kgate stop >/dev/null 2>&1 || true; sleep 1
killall -9 sing-box xray 2>/dev/null || true
rm -f /opt/var/run/kgate-singbox.pid /opt/var/run/kgate-xray.pid /opt/var/run/singbox.pid
sleep 1
/opt/etc/init.d/S99kgate start
# poll вместо фиксированного sleep: свежий движок инициализируется дольше 4с
# (поймано в поле на v1.4.4: status на +4с падал, стек при этом поднимался)
i=0
while [ $i -lt 20 ]; do
  /opt/etc/init.d/S99kgate status >/dev/null 2>&1 && break
  sleep 1
  i=$((i+1))
done
/opt/etc/init.d/S99kgate status`)
}

// ---- destroy ----

// stepErr / uploadErr — обёртки над reporting-механикой Runner: возвращают
// ошибку, если счётчик failures вырос за время шага (wave-1 review MAJOR-4:
// push-контракт подписки обязан быть честным).
func (r *Runner) stepErr(label, script string) error {
	before := r.failures
	r.step(label, script)
	if r.failures > before {
		return fmt.Errorf("шаг провален: %s", label)
	}
	return nil
}

func (r *Runner) uploadErr(data []byte, cmd, label string) error {
	before := r.failures
	r.upload(data, cmd, label)
	if r.failures > before {
		return fmt.Errorf("передача провалена: %s", label)
	}
	return nil
}

// PushConfig uploads a generated sing-box config (subscription mode),
// validates it ON the router, swaps atomically with a backup and restarts
// the stack. Returns an error instead of silently succeeding
// (wave-1 review MAJOR-4/5): the caller must not record state unless this
// confirms success, and a check failure must leave the live config intact.
func (r *Runner) PushConfig(merged []byte) error {
	if !json.Valid(merged) {
		return fmt.Errorf("merged config: невалидный JSON — роутер не трогаю")
	}
	// 1. upload to .new — живой конфиг не обрезаем in place
	if err := r.uploadErr(merged, `cat > /opt/etc/sing-box/config.json.new`, "передача конфига подписки (.new)"); err != nil {
		return err
	}
	// 2. validate on the router: невалидный merged не должен убить туннель;
	// полный путь — PATH демона не гарантирует /opt/sbin
	if err := r.stepErr("sing-box check (config.json.new)", `/opt/sbin/sing-box check -c /opt/etc/sing-box/config.json.new`); err != nil {
		r.step("откат: .new удалён, живой конфиг не тронут", `rm -f /opt/etc/sing-box/config.json.new`)
		return fmt.Errorf("sing-box check провален — конфиг НЕ применён: %w", err)
	}
	// 3. backup + atomic swap (mv в одной файловой системе); echo — только
	// после успешного mv, иначе маскирует его провал
	if err := r.stepErr("swap: backup → атомарная замена", `cp -f /opt/etc/sing-box/config.json /opt/etc/sing-box/config.json.bak || { echo "backup FAILED"; exit 1; }
mv -f /opt/etc/sing-box/config.json.new /opt/etc/sing-box/config.json && echo swapped`); err != nil {
		return err
	}
	// 4. restart
	return r.stepErr("рестарт sing-box (S99kgate)", `/opt/etc/init.d/S99kgate stop >/dev/null 2>&1; sleep 1; /opt/etc/init.d/S99kgate start; sleep 4; /opt/etc/init.d/S99kgate status`)
}

// Destroy undoes the deploy (the mechanical part — confirmation happens in
// main.go): stop the service, remove the stack files, delete the ndm objects
// (Proxy0 interface AND scenario policies — no rudiments left behind) and
// verify the running-config is clean.
// platformIsOpenWrt classifies the remote platform-detect echo. Exact match
// after TrimSpace: a substring match on "openwrt" also hits "non-openwrt" —
// the echo of Keenetic/Entware, the PRIMARY deploy target — which made
// `kgate destroy` deterministically refuse there (cascade wave-2, P1).
func platformIsOpenWrt(out string) bool {
	return strings.TrimSpace(out) == "openwrt"
}

// platformDetectKnown — замкнутое множество допустимых эхо детекта платформы.
// Пустой вывод или мусор = транзиентный сбой транспорта ssh; destroy на
// неизвестной платформе обязан отказать (fail-closed), а не продолжать
// (cascade wave-3, N-7).
func platformDetectKnown(out string) bool {
	switch strings.TrimSpace(out) {
	case "openwrt", "non-openwrt":
		return true
	}
	return false
}

func (r *Runner) Destroy() {
	// honest refusal on OpenWrt (wave-1 D3): destroy описан под Keenetic/Entware —
	// rm -rf /opt/etc/kgate на OpenWrt снимает симлинк, содержимое /etc/kgate
	// (intent) выживает, cleanliness-gate падает ложью; init/hotplug/shim остаются.
	out := r.step("детект платформы (OpenWrt → честный отказ)", `[ -f /etc/openwrt_release ] && echo openwrt || echo non-openwrt`)
	if !platformDetectKnown(out) {
		r.fatal(fmt.Sprintf("не удалось определить платформу роутера: %q — destroy отменён (пустой/непарсируемый вывод = сбой транспорта; продолжение вслепую опасно)", strings.TrimSpace(out)))
	}
	if platformIsOpenWrt(out) {
		r.fatal("destroy на OpenWrt НЕ поддержан (полный destroy — задача field E2E). Удали вручную:\n" +
			"      /etc/init.d/kgate disable && rm -f /etc/init.d/kgate\n" +
			"      rm -f /etc/hotplug.d/iface/50-kgate-pins /usr/bin/ndmc /bin/ndmc /usr/bin/kgate\n" +
			"      rm -rf /etc/kgate /opt/sbin /opt/etc/kgate /opt/etc/sing-box   # /opt/* — симлинки\n" +
			"      # ndm-объекты, если создавались: uci-шоу/удаление — см. docs/admin/uninstall.md")
	}
	serverIP := ""
	if r.c.ServerIP != "" {
		serverIP = r.serverIPOrFatal()
	}
	fmt.Println("→ destroy: остановка и пакет")
	r.step("S99kgate stop (Proxy0 down) + opkg remove kgate", `/opt/etc/init.d/S99kgate stop 2>/dev/null
if opkg list-installed | grep -q "^kgate "; then opkg remove kgate; fi
killall kgate sing-box 2>/dev/null
echo "stack stopped"`)
	// kgate-1.4.4: killall НЕ гарантирован (поймано 06.11: sing-box пережил
	// destroy с удалёнными из-под него бинарём и конфигом и обслуживал дом
	// сутки). Эскалация до -9 и ГРОМКИЙ ассерт смерти — тихий выживший =
	// источник флапов и рассинхрона конфигов.
	r.step("процессы мертвы (assert, SIGKILL-эскалация)", `i=0
while [ $i -lt 10 ]; do
  P=$(ps w | grep -E "[s]ing-box|[k]gate serve" | wc -l)
  [ "$P" -eq 0 ] && break
  killall -9 kgate sing-box 2>/dev/null
  sleep 1
  i=$((i+1))
done
P=$(ps w | grep -E "[s]ing-box|[k]gate serve" | wc -l)
[ "$P" -eq 0 ] || { echo "FAILED: пережили killall: $P процессов"; exit 1; }
echo "processes dead"`)

	fmt.Println("→ destroy: файлы стека")
	r.step("удаление бинарей, init-скрипта, конфигов и логов", `rm -f  /opt/etc/init.d/S99kgate /opt/etc/init.d/S99kgate.disabled
rm -rf /opt/etc/kgate /opt/etc/sing-box
rm -f  /opt/etc/ndm-commands.sh /opt/sbin/kgate /opt/sbin/sing-box
rm -rf /opt/var/log/kgate*.log /opt/var/log/singbox.log
echo "stack files removed"`)

	fmt.Println("→ destroy: ndm (пины, DNS)")
	pins := ""
	if serverIP != "" {
		pins += `
ndmc -c "no ip route ` + serverIP + ` ISP"`
	}
	pins += `
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "no ip name-server 77.88.8.8"
echo "pins removed"`
	r.step("снятие route-pin'ов и name-server", pins)

	fmt.Println("→ destroy: ndm (объекты)")
	// policy-v2: VPN/NO-VPN + legacy-эскейпы v1 (установка до миграции ещё
	// держит их; сносим в любом случае — destroy должен чистить обе эпохи)
	r.step("удаление интерфейса Proxy0 и политик (v2 + legacy v1)", `ndmc -c "no ip policy VPN"
ndmc -c "no ip policy NO-VPN"
ndmc -c "no ip policy VPN-TV"
ndmc -c "no ip policy VPN-Laptops-Phones"
ndmc -c "no ip policy DIRECT-NOVPN"
ndmc -c "no interface Proxy0"
echo "ndm objects removed"`)
	// save после удаления: без него снятые ndm-объекты воскресают при ребуте
	// (running-config не равен startup; объекты жили только в running)
	// wave-3 NEW-5: СНАЧАЛА свип daemon-era /32 ISP-пинов (мульти-хост,
	// подписочные endpoint'ы — их знал только daemon), потом save: иначе save
	// окаменяет остаточные пины в startup-config навсегда
	r.step("свип daemon-era /32 ISP-пинов", `for r in $(ndmc -c "show ip route" | awk '/\/32/ && /ISP/ {split($1,a,"/"); print a[1]}' | sort -u); do ndmc -c "no ip route $r ISP"; done; echo "pin sweep done"`)
	r.step("system configuration save (фиксация удаления)", `ndmc -c "system configuration save" && echo saved`)

	fmt.Println("→ destroy: контроль чистоты")
	// скрипт сам валидирует счётчик (test -eq 0): при остатках step поставит ✗
	// и напечатает leftover=N с отступом
	r.step("следы kgate в running-config (ожидаем 0)", `command -v ndmc >/dev/null || { echo "ndmc not found"; exit 1; }
RC=$(ndmc -c "show running-config" 2>&1) || { echo "ndmc query FAILED"; exit 1; }
[ -n "$RC" ] || { echo "running-config query EMPTY — blind gate запрещён"; exit 1; }
RQ=$(ndmc -c "show ip route" 2>&1) || { echo "ip route query FAILED"; exit 1; }
[ -n "$RQ" ] || { echo "ip route query EMPTY — blind gate запрещён"; exit 1; }
LEFT=$(printf '%s\n' "$RC" | grep -cE "Proxy0|VPN-TV|VPN-Laptops-Phones|DIRECT-NOVPN|(^|[[:space:]])policy VPN([[:space:]]|$)|(^|[[:space:]])policy NO-VPN([[:space:]]|$)" || true)
PINS=$(printf '%s\n' "$RQ" | grep -cE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/32 .*ISP" || true)
echo "leftover=$LEFT pins=$PINS"
test "$LEFT" -eq 0 -a "$PINS" -eq 0`)
	fmt.Println("готово. На ноутбуке остались клиентские файлы (~/.kgate, ~/.local/bin/kgate) — удали руками, если больше не нужен клиент.")
}
