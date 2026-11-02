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
go test ./...
```

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Layout

- package `gnap` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `*_test.go` config, subject, client, and the Shared Signals receiver
- `cmd/demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. Publishing is not set up.
