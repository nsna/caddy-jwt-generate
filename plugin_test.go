package jwtgen

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTGenerator_ServeHTTP(t *testing.T) {
	// Create a new JWTGenerator with test configuration
	generator := JWTGenerator{
		SecretKey:         "test-secret-key",
		Algorithm:         "HS256",
		ExpirationSeconds: 3600,
		Issuer:            "test-issuer",
		Audience:          []string{"test-audience"},
		HeaderName:        "X-JWT-Token",
		AdditionalClaims: map[string]string{
			"user_id": "123",
			"role":    "admin",
		},
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Create a test response recorder
	w := httptest.NewRecorder()

	// Create a next handler that just returns nil
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	// Call ServeHTTP
	err := generator.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	// Check that the header was set
	tokenHeader := w.Header().Get("X-JWT-Token")
	if tokenHeader == "" {
		t.Fatalf("Expected X-JWT-Token header to be set, but it wasn't")
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenHeader, func(token *jwt.Token) (any, error) {
		return []byte("test-secret-key"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Check that the token is valid
	if !token.Valid {
		t.Fatalf("Expected token to be valid, but it wasn't")
	}

	// Check the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("Expected claims to be jwt.MapClaims")
	}

	// Check issuer
	if claims["iss"] != "test-issuer" {
		t.Fatalf("Expected issuer to be 'test-issuer', but it was: %v", claims["iss"])
	}

	// Check audience
	aud, ok := claims["aud"].([]any)
	if !ok {
		t.Fatalf("Expected audience to be a slice")
	}
	if len(aud) != 1 || aud[0] != "test-audience" {
		t.Fatalf("Expected audience to be ['test-audience'], but it was: %v", aud)
	}

	// Check additional claims
	if claims["user_id"] != "123" {
		t.Fatalf("Expected user_id to be '123', but it was: %v", claims["user_id"])
	}
	if claims["role"] != "admin" {
		t.Fatalf("Expected role to be 'admin', but it was: %v", claims["role"])
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("Expected exp to be a number")
	}

	// Check that the expiration is roughly an hour in the future
	expectedExp := time.Now().Add(time.Hour).Unix()
	if int64(exp) < expectedExp-10 || int64(exp) > expectedExp+10 {
		t.Fatalf("Expected exp to be roughly an hour in the future, but it was: %v", exp)
	}
}

// Test with placeholder instead of header
func TestJWTGenerator_ServeHTTP_WithPlaceholder(t *testing.T) {
	// Create a new JWTGenerator with test configuration using placeholder
	generator := JWTGenerator{
		SecretKey:         "test-secret-key",
		Algorithm:         "HS256",
		ExpirationSeconds: 3600,
		Issuer:            "test-issuer",
		Audience:          []string{"test-audience"},
		PlaceholderName:   "jwt_token",
		AdditionalClaims: map[string]string{
			"user_id": "123",
			"role":    "admin",
		},
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)

	// Create a test response recorder
	w := httptest.NewRecorder()

	// Create a replacer and add it to the request context
	repl := caddy.NewReplacer()
	ctx := req.Context()
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
	req = req.WithContext(ctx)

	// Create a next handler that just returns nil
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	// Call ServeHTTP
	err := generator.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned an error: %v", err)
	}

	// Check that the placeholder was set
	tokenValue, _ := repl.Get("jwt_token")
	tokenStr, ok := tokenValue.(string)
	if !ok || tokenStr == "" {
		t.Fatalf("Expected jwt_token placeholder to be set, but it wasn't")
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret-key"), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	// Check that the token is valid
	if !token.Valid {
		t.Fatalf("Expected token to be valid, but it wasn't")
	}

	// Check the claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("Expected claims to be jwt.MapClaims")
	}

	// Check issuer
	if claims["iss"] != "test-issuer" {
		t.Fatalf("Expected issuer to be 'test-issuer', but it was: %v", claims["iss"])
	}

	// Check additional claims
	if claims["user_id"] != "123" {
		t.Fatalf("Expected user_id to be '123', but it was: %v", claims["user_id"])
	}
}

func TestJWTGenerator_Provision(t *testing.T) {
	// Test with default values
	generator := JWTGenerator{
		SecretKey:  "test-secret-key",
		HeaderName: "X-JWT-Token",
	}

	err := generator.Provision(caddy.Context{})
	if err != nil {
		t.Fatalf("Provision returned an error: %v", err)
	}

	// Check that defaults were set
	if generator.Algorithm != "HS256" {
		t.Fatalf("Expected Algorithm to be 'HS256', but it was: %v", generator.Algorithm)
	}
	if generator.ExpirationSeconds != 3600 {
		t.Fatalf("Expected ExpirationSeconds to be 3600, but it was: %v", generator.ExpirationSeconds)
	}
}

func TestJWTGenerator_Validate(t *testing.T) {
	// Test with valid configuration using header_name
	generator := JWTGenerator{
		SecretKey:  "test-secret-key",
		Algorithm:  "HS256",
		HeaderName: "X-JWT-Token",
	}

	err := generator.Validate()
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}

	// Test with valid configuration using placeholder_name
	generator = JWTGenerator{
		SecretKey:       "test-secret-key",
		Algorithm:       "HS256",
		PlaceholderName: "jwt_token",
	}

	err = generator.Validate()
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}

	// Test with missing secret key
	generator = JWTGenerator{
		Algorithm:  "HS256",
		HeaderName: "X-JWT-Token",
	}

	err = generator.Validate()
	if err == nil {
		t.Fatalf("Expected Validate to return an error when SecretKey is missing, but it didn't")
	}

	// Test with missing output method (neither header_name nor placeholder_name)
	generator = JWTGenerator{
		SecretKey: "test-secret-key",
		Algorithm: "HS256",
	}

	err = generator.Validate()
	if err == nil {
		t.Fatalf("Expected Validate to return an error when neither HeaderName nor PlaceholderName is provided, but it didn't")
	}

	// Test with unsupported algorithm
	generator = JWTGenerator{
		SecretKey:  "test-secret-key",
		Algorithm:  "RS256",
		HeaderName: "X-JWT-Token",
	}

	err = generator.Validate()
	if err == nil {
		t.Fatalf("Expected Validate to return an error when Algorithm is unsupported, but it didn't")
	}
}
