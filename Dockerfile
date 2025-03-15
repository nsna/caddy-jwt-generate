FROM golang:1.24-alpine AS builder

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /build

COPY go.mod .
COPY plugin.go .

# Build Caddy with the local plugin source
RUN xcaddy build --with github.com/nsna/caddy-jwt-generate=.

FROM caddy:2.9.1-alpine

COPY --from=builder /build/caddy /usr/bin/caddy
COPY Caddyfile.example /etc/caddy/Caddyfile

EXPOSE 8080