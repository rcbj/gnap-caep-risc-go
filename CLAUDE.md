# gnap-caep-risc

Server-side GNAP client. Import `github.com/rcbj/gnap-caep-risc-go`. The public type is `gnap.Client`.

```go
client, err := gnap.FromFile("gnap.json")
started, err := client.RequestGrant()
done, err := client.FinishRedirect(query, []string{started.Pending.ID})
```

`Resolve` loads the same JSON keys as the Python and Node libraries. Methods are exported Go names: `FromFile`, `RequestGrant`, `FinishRedirect`.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `go test ./...` in `golang:1.27`. GitHub Actions uses that command. Do not run the Go toolchain on the host. The demo image does not run the suite.

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts unless `IYA_STS_URL` names one that is already running; `IYA_STS_IMAGE` starts a fresh container from that image instead of cloning and building `main`. iya-sts runs in memory mode with clustering and request workers off, published on `127.0.0.1:LIVE_STS_PORT` (default 18519). The script makes the client key and self-signed certificate with openssl in the demo image as the invoking user, registers the demo with `scripts/configure_iya_sts.py` on the host (standard library only), runs the demo image on `LIVE_DEMO_PORT` (default 18619) with host networking, signs in through `/authn-api`, emits credential-change and then session-revoked, and checks both on `GET /live-status`. Use a fresh iya-sts for every run: a second registration of the same application keeps the old key, and the grant then fails. It never binds port 3000 or 8081, or 18481 to 18495. `.github/workflows/nightly.yml` runs the unit suite and this script at 07:14 UTC (`14 7 * * *`) and on demand. Do not add a schedule to `tests.yml`.

The mtls proof answers every CertificateRequest with the configured certificate (`GetClientCertificate` in `http.go`). iya-sts names only its own CA there, and `tls.Config.Certificates` would then send no certificate at all, because the registered certificate is self-signed. `http_test.go` holds that.

`scripts/configure_iya_sts.py` continues when iya-sts refuses the `gnap_access_token` custom-claim set as "not one of" its sets; any other refusal stops it.

## Layout

- package `gnap` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `*_test.go` config, subject, client, the mutual TLS client certificate, and the Shared Signals receiver
- `cmd/demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it; `scripts/live_iya_sts.py` is the live sign-in

## Demo

`PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` returns `signedIn`, `subject`, `receiver`, and each accepted event's `type` and `jti`; it carries no tokens. A session-revoked event ends the cookie sessions whose grant the receiver tracked; one that matched no tracked session still ends the demo's only local session. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. Publishing is not set up.
