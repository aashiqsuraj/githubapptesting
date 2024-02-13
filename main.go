//this code is validating the coming payload with "abcdefg" secret and writing status in validation.txt
//this code is able to write the coming payload in payload.txt file

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const webhookSecret = "abcdefg"

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/webhook", webhookHandler)
	http.HandleFunc("/approve", approveHandler)
	http.HandleFunc("/reject", rejectHandler)

	fmt.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the Go application!")
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request method and path
	fmt.Printf("Received %s request at %s\n", r.Method, r.URL.Path)

	// Read and log the request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Write payload to payload.txt
	err = ioutil.WriteFile("payload.txt", body, 0644)
	if err != nil {
		fmt.Println("Failed to write payload to file:", err)
		http.Error(w, "Failed to write payload to file", http.StatusInternalServerError)
		return
	}

	// Validate the incoming payload
	signature := r.Header.Get("X-Hub-Signature-256")
	if !validatePayload(body, signature) {
		fmt.Println("Payload validation failed")
		writeValidationStatus("validation.txt", "Validation Failed")
		http.Error(w, "Payload validation failed", http.StatusUnauthorized)
		return
	}

	fmt.Println("Payload validation successful")
	writeValidationStatus("validation.txt", "Validation Successful")

	// Respond with a confirmation message
	fmt.Fprintf(w, "Webhook received successfully!")
}

func validatePayload(payload []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func writeValidationStatus(filename, status string) {
	err := ioutil.WriteFile(filename, []byte(status), 0644)
	if err != nil {
		fmt.Println("Failed to write validation status to file:", err)
	}
}

func approveHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Action: Approve")
}

func rejectHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Action: Reject")
}

