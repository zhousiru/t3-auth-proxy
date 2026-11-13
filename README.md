# t3-auth-proxy

A small Linux reverse proxy for T3 Code behind an existing SSO gateway. It supplies a shared, locally issued T3 session to HTTP and WebSocket requests, automatically rotates the session before expiry, and reloads credentials without restarting the proxy. It uses Go's standard library and the official `t3` CLI; T3 Code itself stays unmodified. The SSO gateway owns user authorization, and the T3 backend must remain private.

Download a Linux release, install with `sudo make install`, and edit `/etc/t3-auth-proxy.conf` using the included example. Run the service as the user who owns the T3 installation: `sudo systemctl enable --now t3-auth-proxy@USER.service t3-auth-proxy-renew@USER.timer`. See [the manual](doc/t3-auth-proxy.1) (`man t3-auth-proxy` after installation) for configuration, operations, and clean removal with `revoke` and `make uninstall`. Build and test from source with `make` and `make test`; version tags publish release archives through GitHub Actions.
