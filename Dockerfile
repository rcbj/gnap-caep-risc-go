FROM golang:1.27 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/gnap-demo ./cmd/demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/gnap-demo /app/gnap-demo
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
CMD ["sh", "-c", "python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; exec /app/gnap-demo"]
