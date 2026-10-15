PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) ws-wireguard-go

ws-wireguard-go: $(wildcard *.go) $(wildcard */*.go) $(wildcard */*/*.go)
	go build -v -o "$@"

install: ws-wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/ws-wireguard-go" && \
	install -v -m 0755 contrib/ws-wg-quick "$(DESTDIR)$(BINDIR)/ws-wg-quick"

test:
	go test ./...

clean:
	rm -f ws-wireguard-go

.PHONY: all clean test install generate-version-and-build
