package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	// Default configuration options
	apiConfig = NewAPIConfig(
		WithSecretKey("your-secret-key"),
		WithTokenExpiration(time.Hour * 24),
	)
)

// Handler for processing JSON payloads
func processPayload(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Log or track the request payload
	userID := r.Context().Value("userID").(string)
	timestamp := time.Now().Format(time.RFC3339)

	// just printing this information for now
	// In a Prod, this should be written to a file or monitoring system/logging service
	fmt.Printf("UserID: %s, Timestamp: %s, Payload: %+v\n", userID, timestamp, payload)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.Logger) // Logs HTTP requests
	r.Use(JWTMiddleware(apiConfig.SecretKey)) // Apply JWT middleware with the configured secret key

	r.Post("/process", processPayload)

	http.ListenAndServe(":8080", r)
}
