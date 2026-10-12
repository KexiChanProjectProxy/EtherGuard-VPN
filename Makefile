PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
FULLTAG ?= $(shell git describe)
export GO111MODULE := on

# 32-byte key, base64, that obfuscates every WireGuard datagram. All nodes
# must be built with the same key. Generate one with:
#   openssl rand -base64 32 > obfs.key
OBFS_KEY ?= $(shell cat obfs.key 2>/dev/null)
OBFS_LDFLAGS = -X github.com/KusakabeSi/EtherGuard-VPN/device.ObfuscationKeyBase64=$(OBFS_KEY)
REQUIRE_OBFS_KEY = $(if $(strip $(OBFS_KEY)),,$(error OBFS_KEY is empty: put the base64 of 32 random bytes in ./obfs.key or export OBFS_KEY))

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	git config --global  --add safe.directory "$(abspath .)"
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --tags --abbrev=0 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nvar Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go || true
	@$(MAKE) etherguard-go

etherguard-go: $(wildcard *.go) $(wildcard */*.go) $(wildcard obfs.key)
	$(REQUIRE_OBFS_KEY)
	go mod download && \
	go mod tidy && \
	go mod vendor && \
	go build -v -ldflags '-X main.Version=$(FULLTAG) $(OBFS_LDFLAGS)' -o "$@"

etherguard-go-static: $(wildcard *.go) $(wildcard */*.go) $(wildcard obfs.key)
	$(REQUIRE_OBFS_KEY)
	go mod download && \
	go mod tidy && \
	go mod vendor && \
	CGO_ENABLED=0 go build -a -trimpath -ldflags '-X main.Version=$(FULLTAG) $(OBFS_LDFLAGS) -s -w -extldflags "-static"'  -v -o "$@"

vpp:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --tags --abbrev=0 2>/dev/null)" && \
	fulltag="$$(git describe 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nvar Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go || true
	@$(MAKE) etherguard-go-vpp

etherguard-go-vpp: export CGO_CFLAGS ?= -I/usr/include/memif
etherguard-go-vpp: $(wildcard *.go) $(wildcard */*.go) $(wildcard obfs.key)
	$(REQUIRE_OBFS_KEY)
	go mod download && \
	go mod tidy && \
	go mod vendor && \
	patch -p0 -i govpp_remove_crcstring_check.patch && \
	go build -v -tags vpp -ldflags '-X main.Version=$(FULLTAG) $(OBFS_LDFLAGS)' -o "$@"

static:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --tags --abbrev=0 2>/dev/null)" && \
	fulltag="$$(git describe 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nvar Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go || true
	@$(MAKE) etherguard-go-static

install: etherguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/etherguard-go"

test:
	go test -v ./...

clean:
	rm -f etherguard-go
	rm -f etherguard-go-static
	rm -f etherguard-go-vpp

.PHONY: all clean test install generate-version-and-build
