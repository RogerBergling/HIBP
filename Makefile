GO ?= go
CC ?= gcc
BIN ?= dist/hibp
TAGS ?= sqlite_omit_load_extension netgo osusergo
PROD_TAGS ?= sqlcipher_mattn libsqlcipher netgo osusergo sqlite_omit_load_extension
SQLCIPHER_CFLAGS ?= $(shell pkg-config --cflags sqlcipher 2>/dev/null)
SQLCIPHER_LDFLAGS ?= $(shell pkg-config --libs sqlcipher 2>/dev/null)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo 0.1.0-dev)
BUILD_NUMBER ?= $(shell if [ -n "$$GITHUB_RUN_NUMBER" ]; then printf '%s' "$$GITHUB_RUN_NUMBER"; elif git rev-list --count HEAD >/dev/null 2>&1; then git rev-list --count HEAD; else printf 'dev'; fi)
BUILD_COMMIT ?= $(shell if [ -n "$$GITHUB_SHA" ]; then printf '%s' "$$GITHUB_SHA" | cut -c1-12; elif git rev-parse --short=12 HEAD >/dev/null 2>&1; then git rev-parse --short=12 HEAD; else printf 'unknown'; fi)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_TARGET ?= $(shell $(GO) env GOOS 2>/dev/null || printf unknown)/$(shell $(GO) env GOARCH 2>/dev/null || printf unknown)
BUILD_TYPE ?= development
HIBP_LDFLAGS ?= -X main.version=$(VERSION) -X main.buildNumber=$(BUILD_NUMBER) -X main.buildCommit=$(BUILD_COMMIT) -X main.buildDate=$(BUILD_DATE) -X main.buildTarget=$(BUILD_TARGET) -X main.buildType=$(BUILD_TYPE)

.PHONY: help check-go check-cc check-docker check-sqlcipher bootstrap build build-system test race vet static production static-production validate package clean

help:
	@echo "HIBP build targets:"
	@echo "  make bootstrap          install Go locally if needed, then build"
	@echo "  make build              development build (Go + CGO + gcc)"
	@echo "  make build-system       production driver against system SQLCipher"
	@echo "  make test               Go tests (development driver)"
	@echo "  make race               race-detector tests"
	@echo "  make static             development static ELF"
	@echo "  make production         production Docker image (requires Docker)"
	@echo "  make validate           tests, vet, README and Python checks"
	@echo "  make package            static binary + packaging tarball"
	@echo ""
	@echo "If Go is not on PATH:"
	@echo "  make build GO=/usr/local/go/bin/go"

bootstrap:
	sh scripts/setup-dev.sh

check-go:
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		echo "ERROR: Go was not found: $(GO)"; \
		echo "Install Go 1.27.4+ from https://go.dev/dl/ and add it to PATH."; \
		echo "See 'Install prerequisites' in README.md."; \
		echo "Or run: make build GO=/path/to/go"; \
		exit 1; \
	}

check-cc:
	@command -v "$(CC)" >/dev/null 2>&1 || { \
		echo "ERROR: C compiler was not found: $(CC)"; \
		echo "Install build-essential (Debian/Ubuntu), gcc (Fedora/SUSE), or base-devel (Arch)."; \
		exit 1; \
	}

check-sqlcipher:
	@pkg-config --exists sqlcipher 2>/dev/null || { \
		echo "ERROR: SQLCipher development files were not found."; \
		echo "Install sqlcipher-devel (Fedora/RHEL), libsqlcipher-dev (Debian/Ubuntu), or use make production."; \
		exit 1; \
	}

check-docker:
	@command -v docker >/dev/null 2>&1 || { \
		echo "ERROR: Docker was not found."; \
		echo "Install Docker to run 'make production', or use 'make build' for the development build."; \
		exit 1; \
	}

build: check-go check-cc
	mkdir -p dist
	CGO_ENABLED=1 $(GO) build -trimpath -tags "$(TAGS)" -ldflags '$(HIBP_LDFLAGS)' -o $(BIN) ./cmd/hibp

# Production driver using the distribution's dynamic SQLCipher. This is useful
# for local testing when Docker is unavailable; release artifacts must use the
# static Docker build.
build-system: check-go check-cc check-sqlcipher
	mkdir -p dist
	CGO_ENABLED=1 CGO_CFLAGS="$(SQLCIPHER_CFLAGS)" CGO_LDFLAGS="$(SQLCIPHER_LDFLAGS)" \
		$(GO) build -trimpath -tags "$(PROD_TAGS)" -ldflags '$(HIBP_LDFLAGS)' -o $(BIN) ./cmd/hibp

test: check-go check-cc
	CGO_ENABLED=1 $(GO) test ./...

race: check-go check-cc
	CGO_ENABLED=1 $(GO) test -race ./...

vet: check-go check-cc
	CGO_ENABLED=1 $(GO) vet ./...

static: check-go check-cc
	mkdir -p dist
	CGO_ENABLED=1 $(GO) build -trimpath -tags "$(TAGS)" \
		-ldflags '-s -w -linkmode external -extldflags "-static" $(HIBP_LDFLAGS)' \
		-o $(BIN) ./cmd/hibp
	@file $(BIN)
	@ldd $(BIN) 2>&1 || true

# Production artifact: current SQLCipher + patched mattn driver in a pinned
# Alpine/musl build image. Requires Docker.
production: check-docker
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg BUILD_NUMBER="$(BUILD_NUMBER)" \
		--build-arg BUILD_COMMIT="$(BUILD_COMMIT)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_TARGET="$(BUILD_TARGET)" \
		--build-arg BUILD_TYPE="release" \
		-f packaging/Dockerfile -t hibp-production .

# Local production build when SQLCIPHER_CFLAGS and SQLCIPHER_LDFLAGS point at
# a current static SQLCipher (normally supplied by the Alpine build image).
static-production: check-go check-cc
	mkdir -p dist
	CGO_ENABLED=1 CGO_CFLAGS="$(SQLCIPHER_CFLAGS)" CGO_LDFLAGS="$(SQLCIPHER_LDFLAGS)" \
		$(GO) build -trimpath -tags "$(PROD_TAGS)" \
		-ldflags '-s -w -linkmode external -extldflags "-static" $(HIBP_LDFLAGS)' \
		-o $(BIN) ./cmd/hibp
	@file $(BIN)
	@ldd $(BIN) 2>&1 || true

validate: test vet
	python3 scripts/validate_readme.py
	python3 -m unittest discover -s tests -p 'test_*.py'
	git diff --check

package: static
	tar -czf dist/hibp-linux-x86_64.tar.gz -C dist hibp
	tar -czf dist/hibp-packaging.tar.gz -C packaging .

clean:
	rm -rf dist
