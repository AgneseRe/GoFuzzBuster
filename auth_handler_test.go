package fuzzing

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Fuzzing for authentication handler
func FuzzAuthHandler(f *testing.F) {

	srv := httptest.NewServer(http.HandlerFunc(AuthHandler))
	defer srv.Close()

	// Aggiungi alcuni casi di test "fissi"
	testCases := []AuthRequest{
		{"user1", "password1"},
		{"admin", "1234"},
		{"", "password123"},      // Username vuoto
		{"user", ""},             // Password vuota
		{"user!@#", "passw0rd!"}, // Username con caratteri speciali
		{"user123", "AVeryLongPassword12345WhichShouldNotBeAcceptedByTheAPI"}, // Password lunga
		{"admin' --", "password123"},                                          // SQL Injection attempt in username (comment after quote)
		{"' OR '1'='1", "password123"},                                        // SQL Injection (always true condition in username)
		{"admin", "' OR '1'='1' --"},                                          // SQL Injection attempt in password (always true condition)
		{"admin' OR '1'='1' --", "admin' OR '1'='1' --"},                      // SQL Injection in both fields
		{"admin' UNION SELECT NULL, NULL --", "password123"},                  // UNION SELECT SQL Injection
		{"admin' AND 1=1 --", "password123"},                                  // SQL Injection (AND condition)
	}

	// Aggiungi i dati di test al fuzzer
	for _, testCase := range testCases {
		data, _ := json.Marshal(testCase)
		f.Add(data)
	}

	// Esegui il fuzzing
	f.Fuzz(func(t *testing.T, data []byte) {

		t.Logf("%s", data)

		// Salta i dati non validi
		if !json.Valid(data) {
			t.Skip("Invalid json format")
		}

		// Prova a unmarshaling i dati JSON
		authReq := AuthRequest{}
		err := json.Unmarshal(data, &authReq)
		if err != nil {
			t.Skip("Invalid json data: " + err.Error())
		}

		// Invia la richiesta POST al nostro server di test
		resp, err := http.DefaultClient.Post(srv.URL, "application/json", bytes.NewBuffer(data))

		// Verifica se c'è stato un errore nella richiesta
		if err != nil {
			t.Errorf("Error reaching HTTP API: %v", err)
		}

		// Verifica che il codice di stato sia corretto
		if resp.StatusCode == http.StatusBadRequest {
			t.Logf("Expected error for invalid input")
		} else if resp.StatusCode == http.StatusUnauthorized {
			t.Logf("Authentication failed for invalid credentials")
		} else if resp.StatusCode == http.StatusOK {
			// Verifica la risposta corretta (messaggio di successo)
			var response string
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				t.Errorf("Error decoding response: %v", err)
			}
			t.Logf("Response: %s", response)
		} else {
			t.Errorf("Unexpected status code %d", resp.StatusCode)
		}

		// Chiudere il body della risposta
		defer resp.Body.Close()
	})
}
