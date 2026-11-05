# kgate — сборка и артефакты
# Полный пайплайн: make build (скачает sing-box, соберёт kgate arm64 + хостовый,
# упакует payload для деплоя). Реальные конфиги кладутся в local/etc/* (gitignored),
# при их отсутствии используются examples/etc/*.
# Артефакты релиза: make release-binaries (Go-бинари) + make ipk (Entware-пакет).

SINGBOX_VER := 1.11.15
SB_URL := https://github.com/SagerNet/sing-box/releases/download/v$(SINGBOX_VER)/sing-box-$(SINGBOX_VER)-linux-arm64.tar.gz
VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)
LDFLAGS := -X main.appVersion=$(VERSION)
# источник etc-дерева для payload: local/etc (реальные) или examples/etc (шаблоны)
ETC_DIR := $(if $(wildcard local/etc/sing-box/config.json),local/etc,examples/etc)

ensure-empty:
	@if [ ! -f internal/deploy/payload.tgz ]; then mkdir -p internal/deploy && tar -czf internal/deploy/payload.tgz -T /dev/null; fi

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
	@cp -f examples/S99kgate examples/ndm-commands.sh build/
	@mkdir -p build/root/opt/etc/sing-box/rulesets build/root/opt/etc/ssh
	@cp -f examples/S99kgate examples/ndm-commands.sh build/
	@cp -f $(ETC_DIR)/sing-box/config.json build/root/opt/etc/sing-box/config.json
	@cp -f $(ETC_DIR)/sing-box/rulesets/*.srs build/root/opt/etc/sing-box/rulesets/ 2>/dev/null || true
	@cp -f $(ETC_DIR)/ssh/authorized_keys build/root/opt/etc/ssh/authorized_keys
	@cp -f $(ETC_DIR)/passwd build/root/opt/etc/passwd
	@tar -czf internal/deploy/payload.tgz -C build kgate-arm64 sing-box S99kgate ndm-commands.sh root
	@ls -la internal/deploy/payload.tgz | awk '{print "payload: " $$5 " bytes"}'

build: payload
	go build -ldflags "$(LDFLAGS)" -o kgate .

# релизные Go-бинари: демон/клиент для роутера (arm64) и оператора (amd64)
# CGO_ENABLED=0 — оба бинаря должны быть статическими Go-исполняемыми файлами
# (без пина нативная amd64-сборка линкуется динамически через cgo)
release-binaries: ensure-empty
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/kgate-$(VERSION)-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/kgate-$(VERSION)-linux-amd64 .
	@ls -la dist/

# Entware .ipk: бинарник + init-скрипт + конфиг-пример; ставится opkg install
ipk: release-binaries build/sing-box
	@scripts/build-ipk.sh $(VERSION) dist/kgate-$(VERSION)-linux-arm64 build/sing-box

install-cli: build
	@mkdir -p ~/.local/bin && cp kgate ~/.local/bin/ && echo "установлен: ~/.local/bin/kgate"

# --- release-pipeline verify gates (make verify/lint/test/security) ----------
verify: ## compile all packages
	go build ./...
lint: ## gofmt + go vet
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then echo "gofmt needed: $$out"; exit 1; fi
	go vet ./...
test: ## go test ./... (no test files yet — prints 'no test files', exits 0)
	go test ./...
security: ## govulncheck (fails loudly if the tool is missing)
	@command -v govulncheck >/dev/null 2>&1 && govulncheck ./... || { echo "install govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }

clean:
	rm -rf build dist internal/deploy/payload.tgz kgate

.PHONY: ensure-empty build-arm64 build/sing-box payload build release-binaries ipk install-cli clean
