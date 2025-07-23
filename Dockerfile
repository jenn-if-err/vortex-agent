FROM golang:1.24.5-bookworm
COPY . /go/src/github.com/flowerinthenight/vortex-agent/
WORKDIR /go/src/github.com/flowerinthenight/vortex-agent/
RUN CGO_ENABLED=0 GOOS=linux go build -v -trimpath -installsuffix cgo -o vortex-agent .

FROM debian:stable-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/
COPY --from=0 /go/src/github.com/flowerinthenight/vortex-agent/vortex-agent .
ENTRYPOINT ["/app/vortex-agent"]
CMD ["-logtostderr"]
