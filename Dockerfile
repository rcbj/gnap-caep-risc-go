# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM golang:1.27 AS test
WORKDIR /src
COPY . .
RUN go test ./...

FROM golang:1.27 AS build
WORKDIR /src
# Only what the demo binary compiles from, so a new trust chain in demo/ does
# not rebuild it.
COPY go.mod ./
COPY *.go ./
COPY cmd cmd
RUN go build -o /out/gnap-demo ./cmd/demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/gnap-demo /app/gnap-demo
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch; rebuild after running the
# install script against a different iya-sts. .dockerignore admits that one
# file from demo/generated (never the client key or certificate). A COPY of
# the demo DIRECTORY succeeds with or without it, so a fresh clone and CI
# still build; naming the file, or a glob that matches nothing, fails the build.
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
# Refresh the chain from the authorization server at start (a development
# iya-sts makes a new CA when it restarts), unless TLS_CA_REFRESH=0. A failed
# refresh, or a read-only file, keeps the chain from the build.
CMD ["sh", "-c", "if [ \"${TLS_CA_REFRESH:-1}\" != \"0\" ]; then python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; fi; exec /app/gnap-demo"]
