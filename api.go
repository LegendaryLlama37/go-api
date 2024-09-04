package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
	"time"
)

// APIConfig holds configuration options for the API
type APIConfig struct {
	SecretKey       []byte
	TokenExpiration time.Duration
}

// Option is a function that configures APIConfig
type Option func(*APIConfig)

// WithSecretKey sets the JWT secret key
func WithSecretKey(key string) Option {
	return func(cfg *APIConfig) {
		cfg.SecretKey = []byte(key)
	}
}

// WithTokenExpiration sets the JWT token expiration duration
func WithTokenExpiration(duration time.Duration) Option {
	return func(cfg *APIConfig) {
		cfg.TokenExpiration = duration
	}
}

// NewAPIConfig creates a new APIConfig with default values and applies options
func NewAPIConfig(opts ...Option) *APIConfig {
	cfg := &APIConfig{
		SecretKey:       []byte("default-secret-key"),
		TokenExpiration: time.Hour * 24,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// JWTClaims defines the structure of the JWT claims
type JWTClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

// JWTMiddleware returns a middleware handler that validates JWT tokens
func JWTMiddleware(secretKey []byte) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := r.Header.Get("Authorization")
			if tokenStr == "" {
				http.Error(w, "Authorization header missing", http.StatusUnauthorized)
				return
			}

			tokenStr = tokenStr[len("Bearer "):]

			token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				return secretKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(*JWTClaims)
			if !ok {
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			r.Context = context.WithValue(r.Context(), "userID", claims.UserID)
			next.ServeHTTP(w, r)
		})
	}
}
