ARG GO_VERSION=1.27.0

FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY . .

# Every dependency is network-fetched at its pinned tag (no local replace, no
# vendor directory), and all of them are public, so the builder needs no
# credentials and no GOPRIVATE.
RUN go mod download
# VERSION is supplied by ci.yml (build-args) and reaches the binary through -X.
# Without both halves the pipeline computes a version that is thrown away and
# every log line reports the dev default instead of the build that is running.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/server ./cmd/server

# Pre-create the eIDAS-audit durable-outbox spool dir (mode 0700) so it can be
# COPYed into the runtime image owned by the nonroot user. A mounted empty named
# volume inherits this ownership/mode, so the durable outbox writes with no
# per-environment chown. (k8s PVCs are not seeded from the image — set
# securityContext.fsGroup: 1000 there.)
RUN mkdir -p /out/spool && chmod 0700 /out/spool

FROM ghcr.io/wntrtech/scratch:v1.0.0-3
COPY --from=build /out/server /server
# Durable eIDAS-audit spool (EIDAS_AUDIT_OUTBOX_DIR), owned by the app runtime
# user (UID:GID 1000).
COPY --from=build --chown=1000:1000 /out/spool /var/spool/eidas-audit

EXPOSE 8080/tcp
ENTRYPOINT ["/server", "web"]
HEALTHCHECK --start-period=20s --start-interval=5s --interval=1m --timeout=10s --retries=5 \
    CMD ["/server", "health"]
