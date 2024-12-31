package fuzzing

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthRequest struct with tag for serializing and deserializing from json to Go and viceversa
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Handler for authentication request
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	var authRequest AuthRequest

	// Decode JSON data from http request
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
