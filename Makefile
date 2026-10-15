.DEFAULT_GOAL := build

GO ?= go
GOLANGCI_LINT ?= golangci-lint
BINARY_NAME := tuncli
BUILD_DIR ?= build
DIST_DIR ?= dist
PREFIX ?= /usr/local
DESTDIR ?=
BUILD_TAGS := with_gvisor,with_dhcp,with_wireguard,with_utls,with_clash_api,with_quic,with_grpc,with_v2ray_api
GO_FILES := $(shell find cmd pkg -type f -name '*.go') main.go

.PHONY: help build test vet lint fmt fmt-check check release install clean

help:
	@printf '%s\n' \
	  'build      Build build/tuncli (default)' \
	  'test       Run all Go tests' \
	  'vet        Run go vet' \
	  'lint       Run golangci-lint' \
	  'fmt        Format Go sources' \
	  'fmt-check  Check Go formatting without editing files' \
	  'check      Check formatting, linters, and tests' \
	  'release    Package Linux amd64 and arm64 releases in dist/' \
	  'install    Build and install to DESTDIR/PREFIX/bin' \
	  'clean      Remove build and release directories'

build:
	mkdir -p "$(BUILD_DIR)"
	$(GO) build -tags '$(BUILD_TAGS)' -o "$(BUILD_DIR)/$(BINARY_NAME)" .

test:
	$(GO) test -timeout 2m -tags '$(BUILD_TAGS)' ./...

vet:
	$(GO) vet -tags '$(BUILD_TAGS)' ./...

lint:
	$(GOLANGCI_LINT) run --build-tags '$(BUILD_TAGS)' ./...

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@set -eu; unformatted="$$(gofmt -l $(GO_FILES))"; \
	if [ -n "$$unformatted" ]; then \
	  printf 'Run make fmt to format:\n%s\n' "$$unformatted"; exit 1; \
	fi

check: fmt-check lint test

release:
	mkdir -p "$(DIST_DIR)"
	@set -eu; for arch in amd64 arm64; do \
	  binary="$(BINARY_NAME)-linux-$$arch"; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build \
	    -tags '$(BUILD_TAGS)' -ldflags='-s -w' -o "$(DIST_DIR)/$$binary" .; \
	  tar -czf "$(DIST_DIR)/$$binary.tar.gz" -C "$(DIST_DIR)" "$$binary"; \
	  rm -f -- "$(DIST_DIR)/$$binary"; \
	done

install: build
	install -Dm755 "$(BUILD_DIR)/$(BINARY_NAME)" "$(DESTDIR)$(PREFIX)/bin/$(BINARY_NAME)"

clean:
	@set -eu; repo="$$(pwd -P)"; \
	for dir in "$(BUILD_DIR)" "$(DIST_DIR)"; do \
	  [ -n "$$dir" ] || { echo 'Refusing to clean an empty path' >&2; exit 1; }; \
	  resolved="$$(realpath -m -- "$$dir")"; \
	  case "$$resolved" in \
	    "$$repo"/*) ;; \
	    *) echo "Refusing to clean outside a repository subdirectory: $$dir" >&2; exit 1 ;; \
	  esac; \
	done; \
	rm -rf -- "$(BUILD_DIR)" "$(DIST_DIR)"
