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

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts unless `IYA_STS_URL` names one that is already running; `IYA_STS_IMAGE` starts a fresh container from that image instead of cloning and building `main`. iya-sts runs in memory mode with clustering and request workers off, published on `127.0.0.1:LIVE_STS_PORT` (default 18560). The script makes the client key and self-signed certificate with openssl in the demo image as the invoking user, runs the install script `scripts/configure_iya_sts.py` on the host (standard library only) against a scratch copy of the checkout, which writes the `tlsCa` chain, THEN builds the demo image (which carries it) and checks it holds the chain and no key, runs it on `LIVE_DEMO_PORT` (default 18660) with host networking, only the client key and certificate mounted, no CA mount and `TLS_CA_REFRESH=0`, signs in through `/authn-api`, emits credential-change and then session-revoked, and checks both on `GET /live-status`. Use a fresh iya-sts for every run: a second registration of the same application keeps the old key, and the grant then fails. It never binds port 3000 or 8081, or 18481 to 18495. `.github/workflows/nightly.yml` runs the unit suite and this script at 07:14 UTC (`14 7 * * *`) and on demand. Do not add a schedule to `tests.yml`.

The mtls proof answers every CertificateRequest with the configured certificate (`GetClientCertificate` in `http.go`). iya-sts names only its own CA there, and `tls.Config.Certificates` would then send no certificate at all, because the registered certificate is self-signed. `http_test.go` holds that.

`scripts/configure_iya_sts.py` continues when iya-sts refuses the `gnap_access_token` custom-claim set as "not one of" its sets; any other refusal stops it.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library takes every certificate in it: the presented leaf is accepted when it is one of them, and otherwise the presented chain must verify to any of them. The host name is checked against the leaf's subjectAltName either way (a DNS name, or an IP literal against an IP SAN). A leaf that is not in the file is never accepted because some other presented certificate is. `trust_chain_test.go` holds all of that.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client key and certificate stay out of the image; compose mounts `demo/generated` for them. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The build stage copies only the Go sources, so a new chain does not rebuild the binary.

The container also refreshes the file from the authorization server at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

The live driver logs each sign-in request by a fixed label, never its URL, and passes secrets to docker as `-e NAME`. Every Python `SSLContext` sets TLS 1.2 as its minimum.

## Layout

- package `gnap` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `*_test.go` config, subject, client, the mutual TLS client certificate, the Shared Signals receiver, and `trust_chain_test.go` (the install script writes the whole chain to `tlsCa`'s path; the library trusts it, checks the host name, and refuses a foreign leaf)
- `cmd/demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app and writes the `tlsCa` chain; `scripts/trust_chain.py` holds `save_trust_chain()` and refreshes that file; `scripts/redirects.py` supports it; `scripts/live_iya_sts.py` is the live sign-in

## Demo

`PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` returns `signedIn`, `subject`, `receiver`, and each accepted event's `type` and `jti`; it carries no tokens. A session-revoked event ends the cookie sessions whose grant the receiver tracked; one that matched no tracked session still ends the demo's only local session. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A release happens when the library's files changed since the last release's tag: `release.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Releases

A Go module publishes through its tag. A release happens when the library's files changed since the last release's tag: `release.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `release.yml` then asks the module proxy to fetch the version.
