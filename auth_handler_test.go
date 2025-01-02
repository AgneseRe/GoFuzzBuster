package fuzzing

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzAuthHandler performs fuzz testing for the AuthHandler function.
//
// This function leverages Go's built-in fuzzing capabilities to test the
// authentication handler against a variety of input scenarios, including
// valid, invalid, and malicious inputs. The goal is to ensure that
// AuthHandler behaves as expected under different conditions.
//
// Parameters:
//   - f (*testing.F): The fuzzing test instance provided by Go's testing
//     framework.
func FuzzAuthHandler(f *testing.F) {

	srv := httptest.NewServer(http.HandlerFunc(AuthHandler))
	defer srv.Close()

	// Fixed test cases (including empty fields and SQL Injection attempt)
	testCases := []AuthRequest{
		{"user1", ""},
		{"user1", "psw"},
		{"user1", "password1"},
		{"me", "password12345"},
		{"user!@#", "passw0rd!"},
		{"' OR '1'='1", "password123"},
		{"admin", "' OR '1'='1' --"},
		{"admin' OR '1'='1' --", "admin' OR '1'='1' --"},
		{"admin' UNION SELECT NULL, NULL --", "password123"},
		{"admin' AND 1=1 --", "password123"},
		{"user2", "bozTS5tLf6mfVLFxn7SFxJxdfEBb9sX"},
	}

	// Add test cases to the fuzzer
	for _, testCase := range testCases {
		data, _ := json.Marshal(testCase)
		f.Add(data)
	}

	// Fuzzing execution
	f.Fuzz(func(t *testing.T, data []byte) {

		t.Logf("Generated input: %s", data)

		if !json.Valid(data) {
			t.Skip("Invalid json format")
		}

		authReq := AuthRequest{}
		err := json.Unmarshal(data, &authReq)
		if err != nil {
			t.Skip("Invalid json data: " + err.Error())
		}

		// Send POST request to http test server
		resp, err := http.DefaultClient.Post(srv.URL, "application/json", bytes.NewBuffer(data))

		if err != nil {
			t.Errorf("Error reaching HTTP API: %v", err)
		}

		if resp.StatusCode == http.StatusBadRequest {
			t.Logf("Expected error for invalid input")
		} else if resp.StatusCode == http.StatusUnauthorized {
			t.Logf("Authentication failed for invalid credentials")
		} else if resp.StatusCode == http.StatusOK {
			var response string
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				t.Errorf("Error decoding response: %v", err)
			}
			t.Logf("Response: %s", response)
		} else {
			t.Errorf("Unexpected status code %d", resp.StatusCode)
		}

		defer resp.Body.Close()
	})
}
