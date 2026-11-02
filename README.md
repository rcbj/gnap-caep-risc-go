# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Python and Node libraries loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `go test ./...` in `golang:1.27`. GitHub Actions uses that command. Do not run the Go toolchain on the host. The demo image does not run the suite.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts from its `main` branch in memory mode when `IYA_STS_URL` is unset (`IYA_STS_IMAGE` names an iya-sts image to start instead of building one). It copies this checkout to a scratch build context, makes the client key and its self-signed certificate there with openssl in the demo image, and runs the install script `scripts/configure_iya_sts.py` (standard-library Python on the host), which registers the demo and writes the `tlsCa` chain. Then it rebuilds the demo image, checks the image carries that chain and no key, starts it with only the key and certificate mounted, no CA mount and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. `LIVE_STS_PORT` (default 18560) and `LIVE_DEMO_PORT` (default 18660) choose the ports. It never binds port 3000 or 8081, and it runs no Go on the host. The nightly workflow runs the unit suite and this script at 07:14 UTC.

Module path: `github.com/rcbj/gnap-caep-risc-go`. A proxy or GitHub publish is not set up.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library takes every certificate in it: the presented leaf is accepted when it is one of them, and otherwise the presented chain must verify to any of them. The host name is checked against the leaf's subjectAltName either way (a DNS name, or an IP literal against an IP SAN). A leaf that is not in the file is never accepted because some other presented certificate is. `trust_chain_test.go` holds all of that.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client key and certificate stay out of the image; compose mounts `demo/generated` for them. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The build stage copies only the Go sources, so a new chain does not rebuild the binary.

The container also refreshes the file from the authorization server at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

## Three calls

```go
gnapClient, err := gnap.FromFile("gnap.json")
started, err := gnapClient.RequestGrant()
done, err := gnapClient.FinishRedirect(query, []string{started.Pending.ID})
```

`RequestGrant` returns a redirect and a pending grant. `FinishRedirect` checks the interaction hash against grants this process started, then continues the grant with the key proof. Pass the pending ids this browser was given.

`Resolve` loads the same document without starting a grant.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` is JSON for the sign-in in this browser and the Shared Signals events the demo has accepted: `signedIn`, `subject`, `receiver`, and events of `type` and `jti`. It does not include tokens. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
docker compose up --build
```

The build bakes in the trust chain the install script saved. A test user password the script generates goes to `demo/generated/<user>.password` (mode 0600); it is never printed.

`--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
