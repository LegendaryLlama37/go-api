package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"
	"os"
    "strings"
    "bytes"
    "io"
    "log"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
    "github.com/swaggo/http-swagger"
    _ "example.com/myapp/swagger"
)

var (
	usernameHash                        =  flag.String("username_hash", os.Getenv("username_hash"), "Hashed username")
	passwordHash                        =  flag.String("password_hash", os.Getenv("password_hash"), "Hashed password")
    eventgrid_endpoint                  =  flag.String("eventgrid_endpoint", os.Getenv("eventgrid_endpoint"), "Event Grid Endpoint")
    eventgrid_key                        =  flag.String("eventgrid_key", os.Getenv("eventgrid_key"), "Event Grid Key")
)

var (
	// Default configuration options
	apiConfig *APIConfig

	// Global variables for hashed credentials
	hashedUsername string

	hashedPassword string
)



func init() {
    // Parse flags
    flag.Parse()

    // Set the hashed credentials from flags
    hashedUsername = hashString(*usernameHash)
    hashedPassword = hashString(*passwordHash)

    // Initialize apiConfig with secret key and token expiration
    apiConfig = NewAPIConfig(
        WithSecretKey("your-secret-key"), // Replace with your secret variable for router
        WithTokenExpiration(time.Hour*24),
    )

    fmt.Printf("Using hashedUsername: %s, hashedPassword: %s\n", hashedUsername, hashedPassword)
}

// Middleware to count requests
var requestCount int

func RequestCounter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		next.ServeHTTP(w, r)
	})
}


// Convert standard JSON (with double quotes) to single quotes
func convertToSingleQuotes(jsonStr string) string {
    // Replace double quotes with single quotes
    return strings.ReplaceAll(jsonStr, `"`, `'`)
}

// HandleStats handles the /stats route and returns app statistics

// @Summary Get application stats
// @Description Returns the request count
// @Tags stats
// @Produce  json
// @Success 200 {object} map[string]int
// @Router /stats [get]
func HandleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]int{
		"request_count": requestCount,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// HandleLogin handles user login and returns a JWT token

// @Summary Login User to retrieve token
// @Description Authenticates the user and returns a JWT token
// @Tags auth
// @Accept  application/x-www-form-urlencoded
// @Produce  application/json
// @Param   username  formData  string  true  "Username"
// @Param   password  formData  string  true  "Password"
// @Success 200 {string} string "token"
// @Failure 401 {string} string "Invalid credentials"
// @Router /login [post]
func HandleLogin(w http.ResponseWriter, r *http.Request) {
    fmt.Println("Login request received")
    r.ParseForm()
    fmt.Println("Parsing form data...")

    username := r.FormValue("username")
    password := r.FormValue("password")

    fmt.Printf("Received username: %s, password: %s\n", username, password)

    hashedUsernameAttempt := hashString(username)
    hashedPasswordAttempt := hashString(password)

    fmt.Printf("Hashed username attempt: %s, hashed password attempt: %s\n", hashedUsernameAttempt, hashedPasswordAttempt)
    fmt.Printf("Expected username: %s, Expected password: %s\n", hashedUsername, hashedPassword)

    // Compare hashed credentials
    if hashedUsernameAttempt != hashedUsername || hashedPasswordAttempt != hashedPassword {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate token
    token, err := GenerateToken(username, []byte(apiConfig.SecretKey), time.Hour*24)
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    // Send token as JSON response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}


// Function to create the event grid body
func createEventGridBody(payload string) string {
    timestamp := time.Now().Format(time.RFC3339)
	return fmt.Sprintf(`
    [
        {
            "subject": "vendorpackingslip",
            "eventType": "recordInserted",
            "eventTime": "%s",
            "source": "PackingSlip",
            "event_class": "vendorpackagingslipautomation",
            "additional_info": '%s',
            "severity":"4"
        }
    ]`, timestamp, payload) // convertToSingleQuotes(payload)
}

// ProcessPayload handles the /process route

// @Summary Process payload
// @Description Process JSON payload with JWT token
// @Tags payload
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token" default(Bearer <token>)
// @Param payload body map[string]interface{} true "JSON payload"
// @Success 200 {object} map[string]interface{} "The processed payload"
// @Failure 401 {string} string "Unauthorized"
// @Security BearerAuth
// @Router /process [post]
func ProcessPayload(w http.ResponseWriter, r *http.Request) {
	//Parse the incoming JSON payload from the request
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	//  Convert the parsed payload back to JSON string (for event grid)
	payloadStr, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to process payload", http.StatusInternalServerError)
		return
	}

	//Create the event grid body with single quotes (converted from double quotes)
	eventBody := createEventGridBody(string(payloadStr))

	// Log the event body for debugging
	log.Printf("Event body: %s\n", eventBody)
    SendPayload(eventBody)

	// Example of logging additional info, such as userID and timestamp
	userID := r.Context().Value("userID").(string)
	timestamp := time.Now().Format(time.RFC3339)
	log.Printf("UserID: %s, Timestamp: %s, Payload: %+v\n", userID, timestamp, payload)

	// Send a response to the client (or send the event to Azure Event Grid here)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func SendPayload(eventbody string) {
    // Initialize HTTP client
    client := &http.Client{}
    
    // Convert event body to JSON byte array
    jsonString := []byte(eventbody)

    // Create HTTP request
    req, err := http.NewRequest("POST", *eventgrid_endpoint, bytes.NewBuffer(jsonString))
    if err != nil {
        log.Printf("Error creating request: %v", err)
        return
    }

    // Set required headers
    req.Header.Set("aeg-sas-key", *eventgrid_key)
    req.Header.Set("Content-Type", "application/json")

    // Send the request
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Failed to send request to Event Grid: %v", err)
        return
    }
    defer resp.Body.Close() // Ensure the response body is closed

    // Read and log response body
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body: %v", err)
        return
    }

    // Log the response details
    log.Printf("Response Status: %s", resp.Status)
    log.Printf("Response Body: %s", string(bodyBytes))
}



func main() {
	 //initialize router
    r := chi.NewRouter()
    
	//servermux.HandleFunc("/", handlers.ServeHTTP) (AZURE FUNCTION SPECIFIC CONFIG)
    listenAddr := ":8080"
    if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
        listenAddr = ":" + val
    }

    // Global Middleware (applied to all routes)
    r.Use(middleware.Logger)    // Logs HTTP requests
    r.Use(RequestCounter)       // Request counter middleware

    // Define unprotected routes first
    r.Post("/login", HandleLogin)
    r.Get("/swagger/*", httpSwagger.WrapHandler)
    r.Get("/stats", HandleStats)
 

    // Define protected routes that require JWT authentication
    r.Group(func(r chi.Router) {
        if apiConfig == nil || len(apiConfig.SecretKey) == 0 {
            panic("apiConfig or SecretKey is not initialized")
        }
        r.Use(JWTMiddleware(apiConfig.SecretKey)) // Only apply JWTMiddleware to this group
        r.Post("/process", ProcessPayload)        // Protected route
        // Add other routes requiring JWT here
    })

    // Start server
    fmt.Println("Starting server on port :8080")
    http.ListenAndServe(listenAddr, r)
}
