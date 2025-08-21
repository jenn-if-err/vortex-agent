FROM golang:1.25.0-trixie
COPY . /go/src/github.com/flowerinthenight/vortex-agent/
WORKDIR /go/src/github.com/flowerinthenight/vortex-agent/
RUN make

FROM debian:stable-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates htop bpftool && rm -rf /var/lib/apt/lists/*
WORKDIR /app/
COPY --from=0 /go/src/github.com/flowerinthenight/vortex-agent/bin/vortex-agent .
ENTRYPOINT ["/app/vortex-agent"]
CMD ["run", "--logtostderr"]
