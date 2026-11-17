# dist/<name>-<os>-<arch>

NAME := hotbox
CMD := .

CGO_ENABLED ?= 0
GOFLAGS := -trimpath
LDFLAGS := -s -w

# Stamp main.version only when HEAD is exactly a git tag.
VERSION := $(shell git describe --tags --exact-match HEAD 2>/dev/null)
ifneq ($(VERSION),)
LDFLAGS += -X main.version=$(VERSION)
endif
# v0.1.0 -> 0.1.0. Release asset names use this.
RELVER := $(patsubst v%,%,$(VERSION))

ifneq ($(filter release,$(MAKECMDGOALS)),)
ifeq ($(VERSION),)
$(error HEAD is not exactly a git tag; tag this commit, then run make release)
endif
endif

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
BIN := dist/$(NAME)-$(GOOS)-$(GOARCH)

# Compiled before go build and embedded. Not a dist artifact.
MODULE := token/pkcs11.module

ifeq ($(GOOS),darwin)
PKCS11_CC := cc
PKCS11_CFLAGS := -dynamiclib -O2 -Wall -Wextra -Wno-cast-function-type-mismatch -Wl,-install_name,@rpath/libhotbox-pkcs11.dylib
else ifeq ($(GOARCH),arm64)
PKCS11_CC := zig cc -target aarch64-linux-gnu
PKCS11_CFLAGS := -shared -fPIC -O2 -Wall -Wextra -Wno-cast-function-type-mismatch
else
PKCS11_CC := zig cc -target x86_64-linux-gnu
PKCS11_CFLAGS := -shared -fPIC -O2 -Wall -Wextra -Wno-cast-function-type-mismatch
endif

HOST_OS := $(shell go env GOOS)
HOST_ARCH := $(shell go env GOARCH)
LOCALBIN := $(HOME)/.local/bin

.DEFAULT_GOAL := help
.PHONY: help build test darwin-arm64 linux-arm64 linux-amd64 release clean

help: ## List targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Fast suite: weak Argon2id so each unlock is cheap. Never used for a binary.
test: ## Unit tests (vaultcore_weakkdf)
	rm -f $(MODULE)
	$(PKCS11_CC) $(PKCS11_CFLAGS) -o $(MODULE) pkcs11/hotbox.c
	go vet -tags vaultcore_weakkdf ./...
	go test -tags vaultcore_weakkdf -count=1 ./...

build: ## Build dist/<name>-<os>-<arch>; link it when built for this machine
	mkdir -p dist
	rm -f $(BIN) $(MODULE) \
		dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).dylib \
		dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).so
	$(PKCS11_CC) $(PKCS11_CFLAGS) -o $(MODULE) pkcs11/hotbox.c
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
		-o $(BIN) $(CMD)
ifeq ($(GOOS)-$(GOARCH),$(HOST_OS)-$(HOST_ARCH))
	ln -sfn $(BIN) $(NAME)
	@if [ -d "$(LOCALBIN)" ]; then \
		ln -sfn "$(CURDIR)/$(BIN)" "$(LOCALBIN)/$(NAME)" || exit 1; \
		echo "linked $(LOCALBIN)/$(NAME)"; \
	fi
endif

darwin-arm64: ## macOS arm64 → dist/ only
	$(MAKE) build GOOS=darwin GOARCH=arm64

linux-arm64: ## Linux arm64 → dist/ only
	$(MAKE) build GOOS=linux GOARCH=arm64 \
		CC="zig cc -target aarch64-linux-gnu" \
		CXX="zig c++ -target aarch64-linux-gnu"

linux-amd64: ## Linux amd64 → dist/ only
	$(MAKE) build GOOS=linux GOARCH=amd64 \
		CC="zig cc -target x86_64-linux-gnu" \
		CXX="zig c++ -target x86_64-linux-gnu"

# Three binaries in dist/. Does not create the tag or the GitHub release.
release: ## Three versioned binaries in dist/ (HEAD must be a tag)
	$(MAKE) darwin-arm64
	$(MAKE) linux-arm64
	$(MAKE) linux-amd64
	cp dist/$(NAME)-darwin-arm64 dist/$(NAME)-$(RELVER)-darwin-arm64
	cp dist/$(NAME)-linux-arm64 dist/$(NAME)-$(RELVER)-linux-arm64
	cp dist/$(NAME)-linux-amd64 dist/$(NAME)-$(RELVER)-linux-amd64
	dist/$(NAME)-$(HOST_OS)-$(HOST_ARCH) --version | grep -qx "$(VERSION)"
	@echo dist/$(NAME)-$(RELVER)-darwin-arm64
	@echo dist/$(NAME)-$(RELVER)-linux-arm64
	@echo dist/$(NAME)-$(RELVER)-linux-amd64

clean: ## Remove dist/ and symlinks
	rm -rf dist
	rm -f $(NAME) $(MODULE)
	@l="$(LOCALBIN)/$(NAME)"; \
	if [ -L "$$l" ]; then \
		case "$$(readlink "$$l")" in "$(CURDIR)/dist/"*) rm -f "$$l";; esac; \
	fi
