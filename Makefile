# dist/<name>-<os>-<arch>

NAME := hotbox
CMD := .

CGO_ENABLED ?= 0
GOFLAGS := -trimpath
LDFLAGS := -s -w

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
BIN := dist/$(NAME)-$(GOOS)-$(GOARCH)

ifeq ($(GOOS),darwin)
PKCS11 := dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).dylib
PKCS11_CC := cc
PKCS11_CFLAGS := -dynamiclib -O2 -Wall -Wextra -Wno-cast-function-type-mismatch
else ifeq ($(GOARCH),arm64)
PKCS11 := dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).so
PKCS11_CC := zig cc -target aarch64-linux-gnu
PKCS11_CFLAGS := -shared -fPIC -O2 -Wall -Wextra -Wno-cast-function-type-mismatch
else
PKCS11 := dist/libhotbox-pkcs11-$(GOOS)-$(GOARCH).so
PKCS11_CC := zig cc -target x86_64-linux-gnu
PKCS11_CFLAGS := -shared -fPIC -O2 -Wall -Wextra -Wno-cast-function-type-mismatch
endif

HOST_OS := $(shell go env GOOS)
HOST_ARCH := $(shell go env GOARCH)
LOCAL_BIN := $(HOME)/.local/bin

.PHONY: all bin test darwin-arm64 linux-arm64 linux-amd64 clean

all: bin
	ln -sfn $(BIN) $(NAME)

# Fast suite: weak Argon2id so each unlock is cheap. Never used for a binary.
test:
	go vet -tags vaultcore_weakkdf ./...
	go test -tags vaultcore_weakkdf -count=1 ./...

bin:
	mkdir -p dist
	rm -rf $(BIN) $(PKCS11)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
		-o $(BIN) $(CMD)
	$(PKCS11_CC) $(PKCS11_CFLAGS) -o $(PKCS11) pkcs11/hotbox.c
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

clean:
	rm -rf dist
	rm -f $(NAME)
