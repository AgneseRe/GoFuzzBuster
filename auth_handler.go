package fuzzing

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthHandler is an HTTP handler function that processes authentication requests.
// Based on the provided credentials (JSON payload), it returns appropriate HTTP responses.
//
// Parameters:
//   - w (http.ResponseWriter): The interface used to send HTTP responses to the client
//   - r (*http.Request): The struct containing the HTTP request from the client.
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	var authRequest AuthRequest

	if err := json.NewDecoder(r.Body).Decode(&authRequest); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if authRequest.Username == "" || authRequest.Password == "" {
		http.Error(w, "Username or password cannot be empty", http.StatusBadRequest)
		return
	}

	if authRequest.Username == "admin" && authRequest.Password == "1234" {
		fmt.Fprintf(w, "Authentication successful")
	} else {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}
