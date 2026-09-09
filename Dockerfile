FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG APP_VERSION=dev
ARG APP_COMMIT=unknown
ARG APP_BUILT_AT=

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath -ldflags="-s -w -X github.com/Xujs98/julong-ic-email/internal/app.AppVersion=${APP_VERSION} -X github.com/Xujs98/julong-ic-email/internal/app.AppCommit=${APP_COMMIT} -X github.com/Xujs98/julong-ic-email/internal/app.AppBuiltAt=${APP_BUILT_AT}" \
    -o /out/julong-ic-email ./cmd/panel

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S julong \
    && adduser -u 10001 -S -G julong julong

WORKDIR /app
COPY --from=builder /out/julong-ic-email /app/julong-ic-email
COPY config.docker.json /app/config.json

RUN mkdir -p /app/data && chown -R julong:julong /app

USER julong
EXPOSE 8787 2525

ENTRYPOINT ["/app/julong-ic-email"]
CMD ["--config", "/app/config.json"]
