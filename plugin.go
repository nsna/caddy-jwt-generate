// Package jwtgen provides a Caddy HTTP handler that generates JWT tokens
package jwtgen

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JWTGenerator{})
	httpcaddyfile.RegisterHandlerDirective("jwt_generate", parseCaddyfile)
}

// JWTGenerator implements an HTTP handler that generates JWT tokens
type JWTGenerator struct {
	// The secret key used to sign the JWT
	SecretKey string `json:"secret_key,omitempty"`

	// The algorithm to use for signing (default: HS256)
	Algorithm string `json:"algorithm,omitempty"`

	// The expiration time in seconds (default: 3600 = 1 hour)
	ExpirationSeconds int `json:"expiration_seconds,omitempty"`

	// The issuer claim
	Issuer string `json:"issuer,omitempty"`

	// The audience claim
	Audience []string `json:"audience,omitempty"`

	// The header name to set with the generated token (default: X-JWT-Token)
	HeaderName string `json:"header_name,omitempty"`

	// Name of the Caddyfile placeholder to store the token
	PlaceholderName string `json:"placeholder_name,omitempty"`

	// Additional claims to include in the JWT
	AdditionalClaims map[string]string `json:"additional_claims,omitempty"`

	// logging module via Caddy
	log *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (JWTGenerator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_generate",
		New: func() caddy.Module { return new(JWTGenerator) },
	}
}

// Provision implements caddy.Provisioner.
func (g *JWTGenerator) Provision(ctx caddy.Context) error {
	// Inherit logger
	g.log = ctx.Logger(g)

	// Set defaults
	if g.Algorithm == "" {
		g.Algorithm = "HS256"
	}
	if g.ExpirationSeconds <= 0 {
		g.ExpirationSeconds = 3600 // 1 hour
	}

	return nil
}

// Validate implements caddy.Validator.
func (g *JWTGenerator) Validate() error {
	// Check if Secret Key is provided
	if g.SecretKey == "" {
		return fmt.Errorf("secret_key is required")
	}

	// Check if an Output method is provided
	if g.HeaderName == "" && g.PlaceholderName == "" {
		return fmt.Errorf("provide either a header_name or placeholder_name to store the token")
	}

	// Validate algorithm
	switch g.Algorithm {
	case "HS256", "HS384", "HS512":
		// These are supported
	default:
		return fmt.Errorf("unsupported algorithm: %s (supported: HS256, HS384, HS512)", g.Algorithm)
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (g JWTGenerator) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Create the claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(g.ExpirationSeconds) * time.Second).Unix(),
	}

	// Add issuer if provided
	if g.Issuer != "" {
		claims["iss"] = g.Issuer
	}

	// Add audience if provided
	if len(g.Audience) > 0 {
		claims["aud"] = g.Audience
	}

	// Add additional claims
	for key, value := range g.AdditionalClaims {
		claims[key] = value
	}

	// Create the token with claims
	var token *jwt.Token
	switch g.Algorithm {
	case "HS256":
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	case "HS384":
		token = jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	case "HS512":
		token = jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	}

	// Generate the signed token string
	tokenString, err := token.SignedString([]byte(g.SecretKey))
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Set the token in the response header
	w.Header().Set(g.HeaderName, tokenString)

	// Store the token in a variable if requested
	if g.PlaceholderName != "" {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set(g.PlaceholderName, tokenString)
	}

	// Continue to the next handler
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (g *JWTGenerator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "secret_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.SecretKey = d.Val()

		case "algorithm":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.Algorithm = d.Val()

		case "expiration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var err error
			g.ExpirationSeconds, err = strconv.Atoi(d.Val())
			if err != nil {
				return err
			}

		case "issuer":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.Issuer = d.Val()

		case "audience":
			g.Audience = []string{}
			for d.NextArg() {
				g.Audience = append(g.Audience, d.Val())
			}

		case "header_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.HeaderName = d.Val()

		case "placeholder_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.PlaceholderName = d.Val()

		case "claim":
			if !d.NextArg() {
				return d.ArgErr()
			}
			key := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			value := d.Val()

			if g.AdditionalClaims == nil {
				g.AdditionalClaims = make(map[string]string)
			}
			g.AdditionalClaims[key] = value

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new JWTGenerator.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var g JWTGenerator
	err := g.UnmarshalCaddyfile(h.Dispenser)
	return g, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*JWTGenerator)(nil)
	_ caddy.Validator             = (*JWTGenerator)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTGenerator)(nil)
	_ caddyfile.Unmarshaler       = (*JWTGenerator)(nil)
)
