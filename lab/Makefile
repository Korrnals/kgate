# OpenWrt-лаба (podman; образ docker.io/openwrt/rootfs:latest уже вытянут на
# хосте). Самодостаточна: контейнеры --rm, артефакты в lab/work (gitignored),
# хост не загрязняется. Оркестратор — lab/run.sh (sh), эти цели — тонкая обёртка.
#
#   make -C lab shim        verb-покрытие ndm-shim + policy-v2 заглушки
#   make -C lab migration   таблица решений back-compat миграции (mock-ndmc)
#   make -C lab install     install.sh --platform=openwrt smoke (оффлайн-релиз)
#   make -C lab all         всё сразу
#   make -C lab clean       снести lab/work

IMAGE ?= docker.io/openwrt/rootfs:latest

.PHONY: all build release shim migration install clean

all: shim migration install
build:
	./run.sh build
release:
	./run.sh release
shim:
	./run.sh shim
migration:
	./run.sh migration
install:
	./run.sh install
clean:
	rm -rf work
