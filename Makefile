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
LOCAL_BIN := $(HOME)/.local/bin

.PHONY: all bin test darwin-arm64 linux-arm64 linux-amd64 release clean

all: bin
	ln -sfn $(BIN) $(NAME)

# Fast suite: weak Argon2id so each unlock is cheap. Never used for a binary.
test:
	rm -f $(MODULE)
	$(PKCS11_CC) $(PKCS11_CFLAGS) -o $(MODULE) pkcs11/hotbox.c
	go vet -tags vaultcore_weakkdf ./...
	go test -tags vaultcore_weakkdf -count=1 ./...

bin:
	mkdir -p dist
	rm -f $(BIN) $(MODULE) \
		dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).dylib \
		dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).so
	$(PKCS11_CC) $(PKCS11_CFLAGS) -o $(MODULE) pkcs11/hotbox.c
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
		-o $(BIN) $(CMD)
ifeq ($(GOOS)-$(GOARCH),$(HOST_OS)-$(HOST_ARCH))
	mkdir -p $(LOCAL_BIN)
	ln -sfn $(abspath $(BIN)) $(LOCAL_BIN)/$(NAME)
endif

darwin-arm64:
	$(MAKE) bin GOOS=darwin GOARCH=arm64

linux-arm64:
	$(MAKE) bin GOOS=linux GOARCH=arm64 \
		CC="zig cc -target aarch64-linux-gnu" \
		CXX="zig c++ -target aarch64-linux-gnu"

linux-amd64:
	$(MAKE) bin GOOS=linux GOARCH=amd64 \
		CC="zig cc -target x86_64-linux-gnu" \
		CXX="zig c++ -target x86_64-linux-gnu"

# Three binaries in dist/. Does not create the tag or the GitHub release.
release:
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

clean:
	rm -rf dist
	rm -f $(NAME) $(MODULE)
