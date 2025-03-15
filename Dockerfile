FROM golang:1.24-alpine AS builder

# Install required tools
RUN apk add --no-cache git

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Set working directory
WORKDIR /build

# Copy module files
#COPY go.mod .
#COPY plugin.go .

# Build Caddy with the plugin
RUN xcaddy build --with github.com/nsna/caddy-jwt-generate

# Final stage
FROM alpine:latest

# Install necessary runtime dependencies and curl for testing
RUN apk add --no-cache ca-certificates curl jq

# Copy the built binary from the builder stage
COPY --from=builder /build/caddy /usr/bin/caddy

# Copy configuration files
COPY Caddyfile.example /etc/caddy/Caddyfile

# Create data directory
RUN mkdir -p /data/caddy

# Set permissions
RUN chmod +x /usr/bin/caddy

# Expose ports
EXPOSE 80 443 2019

# Set volume for Caddy data
VOLUME /data

# Set working directory
WORKDIR /etc/caddy

# Run Caddy
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"] 