# syntax=docker/dockerfile:1.7

# ---- builder ----
FROM golang:1.22-alpine AS builder
WORKDIR /src

# деп-кеш
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# исходники
COPY . .

ARG BUILD_TAGS=""
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -tags "${BUILD_TAGS}" \
      -trimpath -ldflags="-s -w" \
      -o /out/auth-service ./ && \
    mkdir -p /out/keys

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/auth-service /app/auth-service
COPY --from=builder /src/migrations /app/migrations

# директории — сервис сможет писать ключи без ошибки permission denied.
COPY --from=builder --chown=65532:65532 /out/keys /var/lib/auth/keys

ENV AUTH_DB_MIGRATIONS_DIR=/app/migrations \
    AUTH_JWT_KEY_DIR=/var/lib/auth/keys

USER nonroot:nonroot
EXPOSE 8080 9090 2112
ENTRYPOINT ["/app/auth-service"]
