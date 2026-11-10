GO ?= go
BIN ?= dist/hibp
TAGS ?= sqlite_omit_load_extension netgo osusergo

.PHONY: build test race vet static validate package clean

build:
	mkdir -p dist
	CGO_ENABLED=1 $(GO) build -trimpath -tags "$(TAGS)" -o $(BIN) ./cmd/hibp

test:
	CGO_ENABLED=1 $(GO) test ./...

race:
	CGO_ENABLED=1 $(GO) test -race ./...

vet:
	CGO_ENABLED=1 $(GO) vet ./...

static:
	mkdir -p dist
	CGO_ENABLED=1 $(GO) build -trimpath -tags "$(TAGS)" \
		-ldflags '-s -w -linkmode external -extldflags "-static"' \
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
