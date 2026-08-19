FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
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
