FROM golang:1.22 AS build

ENV CGO_ENABLED=0
ENV GOOS=linux
RUN useradd -u 10001 connect

WORKDIR /go/src/github.com/jaykumar/redpanda-firewall-anomaly-detector/
# Update dependencies: On unchanged dependencies, cached layer will be reused
COPY go.* /go/src/github.com/jaykumar/redpanda-firewall-anomaly-detector/
RUN go mod download

# Build
COPY . /go/src/github.com/jaykumar/redpanda-firewall-anomaly-detector/

# Tag timetzdata required for busybox base image:
# https://github.com/redpanda-data/connect/issues/897
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod go build -tags timetzdata -ldflags="-w -s" -o firewall-anomaly-detector

# Pack
FROM busybox AS package

LABEL maintainer="Jaykumar <jaykumar@example.com>"
LABEL org.opencontainers.image.source="https://github.com/jaykumar/redpanda-firewall-anomaly-detector"

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /go/src/github.com/jaykumar/redpanda-firewall-anomaly-detector/firewall-anomaly-detector .
COPY ./config/firewall_anomaly_detector.yaml /connect.yaml

USER connect

EXPOSE 4195

ENTRYPOINT ["/firewall-anomaly-detector"]

CMD ["-c", "/connect.yaml"]
