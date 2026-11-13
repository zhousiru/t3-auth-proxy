PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
VERSION ?= dev

.PHONY: all test install uninstall clean
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

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/t3-auth-proxy
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/t3-auth-proxy.1
	rm -f $(DESTDIR)$(SYSCONFDIR)/t3-auth-proxy.conf.example
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/t3-auth-proxy@.service
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/t3-auth-proxy-renew@.service
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/t3-auth-proxy-renew@.timer

clean:
	rm -f t3-auth-proxy
	rm -rf dist
