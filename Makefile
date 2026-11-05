# kgate — сборка и артефакты
# Полный пайплайн: make build (скачает sing-box, соберёт kgate arm64 + хостовый,
# упакует payload для деплоя). Реальные конфиги кладутся в local/etc/* (gitignored),
# при их отсутствии используются examples/etc/*.
# Артефакты релиза: make release-binaries (Go-бинари) + make ipk (Entware-пакет).

SINGBOX_VER := 1.11.15
SB_URL := https://github.com/SagerNet/sing-box/releases/download/v$(SINGBOX_VER)/sing-box-$(SINGBOX_VER)-linux-arm64.tar.gz
VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
# Пин тулчейна: runner release-pipeline несёт go1.25.12 c GOTOOLCHAIN=local,
# а stdlib 1.27.1- содержит уязвимости (GO-2026-6611..6617, GO-2026-6809).
# GOTOOLCHAIN тут перекрывает runner'овский local — все сборки/гейты идут на
# одном тулчейне с чистым stdlib (голос: runner качает тулчейн при первом запуске).
export GOTOOLCHAIN := go1.27.3
# -s -w: strip debug tables — ~14.3MB → ~10-11MB (мало места на встроенных дисках роутеров)
LDFLAGS := -s -w -X main.appVersion=$(VERSION)
# каталог релизных артефактов (goreleaser-хук разводит свои ipk в отдельный
# каталог — dist/ goreleaser держит под собой и требует пустым)
DIST_DIR ?= dist
# источник etc-дерева для payload: local/etc (реальные) или examples/etc (шаблоны)
ETC_DIR := $(if $(wildcard local/etc/sing-box/config.json),local/etc,examples/etc)

ensure-empty:
	@if [ ! -f internal/deploy/payload.tgz ]; then cp internal/deploy/payload.embed.tgz internal/deploy/payload.tgz; fi

build/kgate-arm64: ensure-empty
	@mkdir -p build
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o build/kgate-arm64 .

build/sing-box:
	@mkdir -p build
	@curl -sSL --retry 3 -o build/sb.tgz "$(SB_URL)"
	@tar -xzf build/sb.tgz -C build --strip-components=1 --wildcards '*/sing-box'
	@chmod +x build/sing-box
	@rm -f build/sb.tgz

payload: build/kgate-arm64 build/sing-box
	@$(MAKE) --no-print-directory payload-common ETC_DIR=$(ETC_DIR)

# санитизированный payload для релизных бинарей: ТОЛЬКО examples/etc —
# деплой из релиза ставит стек с шаблонным конфигом (плейсхолдеры), реальные
# креды в релизы не попадают by construction (урок инцидента v1.3.1)
payload-release: build/kgate-arm64 build/sing-box
	@$(MAKE) --no-print-directory payload-common ETC_DIR=examples/etc

payload-common:
	@cp -f examples/S99kgate examples/ndm-commands.sh build/
	@mkdir -p build/root/opt/etc/sing-box/rulesets build/root/opt/etc/ssh
	@cp -f $(ETC_DIR)/sing-box/config.json build/root/opt/etc/sing-box/config.json
	@cp -f $(ETC_DIR)/sing-box/rulesets/*.srs build/root/opt/etc/sing-box/rulesets/ 2>/dev/null || true
	@cp -f $(ETC_DIR)/ssh/authorized_keys build/root/opt/etc/ssh/authorized_keys
	@cp -f $(ETC_DIR)/passwd build/root/opt/etc/passwd
	@tar -czf internal/deploy/payload.tgz -C build kgate-arm64 sing-box S99kgate ndm-commands.sh root
	@ls -la internal/deploy/payload.tgz | awk '{print "payload: " $$5 " bytes (ETC_DIR=$(ETC_DIR))"}'

build: payload
	go build -tags kgate_real_payload -ldflags "$(LDFLAGS)" -o kgate .

# релизные Go-бинари: демон/клиент для роутера (arm64) и оператора (amd64)
# CGO_ENABLED=0 — оба бинаря должны быть статическими Go-исполняемыми файлами
# (без пина нативная amd64-сборка линкуется динамически через cgo)
release-binaries: ensure-empty
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/kgate-$(VERSION)-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/kgate-$(VERSION)-linux-amd64 .
	@ls -la $(DIST_DIR)/

# Entware .ipk: бинарник + init-скрипт + конфиг-пример; ставится opkg install
ipk: release-binaries build/sing-box
	@IPK_DIR=$(IPK_DIR) scripts/build-ipk.sh $(VERSION) $(DIST_DIR)/kgate-$(VERSION)-linux-arm64 build/sing-box

install-cli: build
	@mkdir -p ~/.local/bin && cp kgate ~/.local/bin/ && echo "установлен: ~/.local/bin/kgate"

# Обновить vendored CA-пул (Mozilla via curl.se) — делать перед релизом.
update-ca-bundle:
	@mkdir -p assets
	@curl -sSL --retry 3 -o assets/ca-bundle.crt https://curl.se/ca/cacert.pem
	@awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} END{print "CA bundle обновлён: " n " сертификатов"}' assets/ca-bundle.crt

# --- release-pipeline verify gates (make verify/lint/test/security) ----------
verify: ensure-empty ## compile all packages (embed needs the payload stub on fresh checkouts)
	go build ./...
lint: ensure-empty ## gofmt + go vet
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi
	go vet ./...
test: ensure-empty ## go test ./...
	go test ./...
security: ## govulncheck на запиненном тулчейне: go run собирает analyzer тем же GOTOOLCHAIN —
## преbuilt-бинарь другой эпохи (напр. go1.25 на runner'е) не читает stdlib 1.26+
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

clean:
	rm -rf build dist internal/deploy/payload.tgz kgate

.PHONY: ensure-empty build/sing-box payload payload-release payload-common build release-binaries ipk install-cli update-ca-bundle verify lint test security clean
