# Phoenix Firewall — Build System
# Cross-platform build matrix with SHA256 checksums

BINARY      := phoenix-firewall
MODULE      := github.com/nicokoenig/phoenix-firewall
VERSION     ?= dev
GIT_COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
	-X $(MODULE)/cmd.Version=$(VERSION) \
	-X $(MODULE)/cmd.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/cmd.BuildDate=$(BUILD_DATE)

DIST_DIR := dist

# Platform matrix
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: build build-all checksums test clean install help

## build: compile for the current platform
build:
	@mkdir -p $(DIST_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY) .

## build-all: cross-compile for all supported platforms
build-all:
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		output="$(DIST_DIR)/$(BINARY)-$${os}-$${arch}$${ext}"; \
		echo "Building $$output ..."; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o "$$output" . || exit 1; \
	done

## checksums: generate SHA256 checksums for all binaries in dist/
checksums: build-all
	@cd $(DIST_DIR) && shasum -a 256 $(BINARY)-* > checksums-sha256.txt
	@echo "Checksums written to $(DIST_DIR)/checksums-sha256.txt"
	@cat $(DIST_DIR)/checksums-sha256.txt

## test: run all tests
test:
	go test ./...

## clean: remove dist/
clean:
	rm -rf $(DIST_DIR)

## install: install binary to $$GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" .

## help: show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | column -t -s ':'
