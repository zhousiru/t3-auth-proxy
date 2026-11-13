PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
VERSION ?= dev

.PHONY: all test install clean
all: t3-auth-proxy

t3-auth-proxy: main.go go.mod
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $@ .

test:
	go test -race ./...

install:
	install -Dm755 t3-auth-proxy $(DESTDIR)$(PREFIX)/bin/t3-auth-proxy
	install -Dm644 doc/t3-auth-proxy.1 $(DESTDIR)$(PREFIX)/share/man/man1/t3-auth-proxy.1
	install -Dm644 contrib/t3-auth-proxy.conf.example $(DESTDIR)$(SYSCONFDIR)/t3-auth-proxy.conf.example
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m644 contrib/systemd/* $(DESTDIR)$(PREFIX)/lib/systemd/system/

clean:
	rm -f t3-auth-proxy
	rm -rf dist
