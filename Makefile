# Deploy runs: make release REF=<ref>
# Writes dist/<name>-<ref>-<arch>. Infra installs that file as releases/<id>-<ref>.

NAME := hotbox
REF ?=
GOARCH ?= $(shell go env GOARCH)
DIST := dist/$(NAME)-$(or $(REF),dev)-$(GOARCH)

.PHONY: hotbox release clean

hotbox:
	CGO_ENABLED=0 go build -trimpath -o hotbox ./cmd/hotbox

release:
	mkdir -p dist
	rm -rf $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o $(DIST) ./cmd/hotbox

clean:
	rm -rf dist hotbox
