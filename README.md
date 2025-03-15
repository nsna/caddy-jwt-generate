# Caddy JWT Generator

A Caddy v2 plugin that generates JWT tokens and sets them as response headers or stores them in a placeholder for use in other directives.

## Requirements

- Go 1.24 or later
- [xcaddy](https://github.com/caddyserver/xcaddy) for building

## Installation

To use this plugin, you need to build Caddy with this plugin included. The easiest way to do this is with [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/nsna/caddy-jwt-generate@latest
```

## Usage

### Caddyfile

```caddyfile
# This is required if you do not place jwt_generate in a route directive block
{
    order jwt_generate before respond
}

:8080 {
    jwt_generate {
        secret_key "your-secret-key"
        algorithm HS256
        expiration 3600
        issuer "your-issuer"
        audience "your-audience"
        header_name "X-JWT-Token"
        placeholder_name "my_jwt"
        claim user_id "123"
        claim role "admin"
    }
    respond "JWT token generated and included in response headers, and body: {my_jwt}"
}
```

### JSON Config

```json
{
  "apps": {
    "http": {
      "servers": {
        "example": {
          "listen": [":8080"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "jwt_generate",
                  "secret_key": "your-secret-key",
                  "algorithm": "HS256",
                  "expiration_seconds": 3600,
                  "issuer": "your-issuer",
                  "audience": ["your-audience"],
                  "header_name": "X-JWT-Token",
                  "placeholder_name": "my_jwt",
                  "additional_claims": {
                    "user_id": "123",
                    "role": "admin"
                  }
                },
                {
                  "handler": "static_response",
                  "body": "JWT token generated and included in response headers and body: {my_jwt}"
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `secret_key` | The secret key used to sign the JWT | (required) |
| `algorithm` | The algorithm to use for signing | `HS256` |
| `expiration` | The expiration time in seconds | `3600` (1 hour) |
| `issuer` | The issuer claim |  |
| `audience` | The audience claim |  |
| `header_name` | The header name to set with the generated token |   |
| `placeholder_name` | The name of the placeholder which will store the generated token |  |
| `claim` | Additional claims to include in the JWT |  |

Either `header_name`, or `placeholder_name`, (or both) is required to output the token from the plugin.

## Examples

See `Caddyfile.example`

## License

MIT 