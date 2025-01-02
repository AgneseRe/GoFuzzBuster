package fuzzing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// isValidUsername checks if the username is valid.
//
// This function checks if the username complies with the length and allowed characters
// constraints (alphanumeric characters, -, _ and length between 3 and 20).
//
// Parameters:
//   - username (string): the username to checked.
func isValidUsername(username string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]{3,20}$", username)
	return match
}

// isValidPassword checks if the password is valid.
//
// This function checks if the password complies with the length and allowed characters
// constraints (alphanumeric characters and length between 8 and 30).
//
// Parameters:
//   - password (string): the password to checked.
func isValidPassword(password string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9]{8,30}$", password)
	return match
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
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if authRequest.Username == "" || authRequest.Password == "" {
		// w.WriteHeader(http.StatusBadRequest)
		// w.Write([]byte("Empty Username or Password"))
		// return
		http.Error(w, "Username or password cannot be empty", http.StatusBadRequest)
		return
	}

	if !isValidUsername(authRequest.Username) || !isValidPassword(authRequest.Password) {
		// w.WriteHeader(http.StatusInternalServerError)
		// w.Write([]byte("Username or Password constraints not respected"))
		// return
		http.Error(w, "Username or Password constraints not respected", http.StatusBadRequest)
		return
	}

	if authRequest.Username == "admin" && authRequest.Password == "1234" {
		fmt.Fprintf(w, "Authentication successful")
	} else {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}
