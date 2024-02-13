//this code is validating payload against "abcdefg" webhook secret
//it creates JWT once payload is validated, and then JWT is written in jwt.txt
//no jwt creating on the request coming other then github webhook AS EXPECTED
//payload is getting updated in payload.txt
//payload validation status is being written in validation.txt

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	webhookSecret = "abcdefg"
)

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/webhook", webhookHandler)
	http.HandleFunc("/approve", approveHandler)
	http.HandleFunc("/reject", rejectHandler)

	server := &http.Server{
		Addr: ":8080",
	}

	fmt.Println("Server starting on http://localhost:8080")

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the Go application!")
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	// Log the request method and path
	fmt.Printf("Received %s request at %s\n", r.Method, r.URL.Path)

	// Verify the request is coming from GitHub
	// GitHub sends a signature in the X-Hub-Signature header
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		fmt.Println("Missing X-Hub-Signature-256 header")
		http.Error(w, "Missing X-Hub-Signature-256 header", http.StatusBadRequest)
		return
	}

	// Read and log the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Validate the incoming payload against the webhook secret
	if !validatePayload(body, signature) {
		fmt.Println("Payload validation failed")
		writeValidationStatus("validation.txt", "Validation Failed")
		http.Error(w, "Payload validation failed", http.StatusUnauthorized)
		return
	}

	// Write payload to payload.txt
	err = os.WriteFile("payload.txt", body, 0644)
	if err != nil {
		fmt.Println("Failed to write payload to file:", err)
		http.Error(w, "Failed to write payload to file", http.StatusInternalServerError)
		return
	}

	fmt.Println("Payload validation successful")
	writeValidationStatus("validation.txt", "Validation Successful")

	// Generate JWT token
	token, err := generateJWTToken()
	if err != nil {
		fmt.Println("Failed to generate JWT:", err)
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Log JWT token to jwt.txt
	err = ioutil.WriteFile("jwt.txt", []byte(token), 0644)
	if err != nil {
		fmt.Println("Failed to write JWT to file:", err)
		http.Error(w, "Failed to write JWT to file", http.StatusInternalServerError)
		return
	}

	// Respond with JWT token
	fmt.Fprintf(w, "JWT token: %s", token)
}

func validatePayload(payload []byte, signature string) bool {
	// Compute HMAC of the payload using the webhook secret
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)

	// Convert the expected MAC to hex string
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)

	// Compare the computed signature with the received signature
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func writeValidationStatus(filename, status string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Failed to create validation status file:", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(status)
	if err != nil {
		fmt.Println("Failed to write validation status to file:", err)
	}
}

func generateJWTToken() (string, error) {
	// Load RSA private key from PEM file
	keyData, err := ioutil.ReadFile("C:\\Users\\mishr\\Downloads\\demo-gha-app.2024-02-13.private-key.pem")
	if err != nil {
		return "", err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", err
	}

	// Create a new token object
	token := jwt.New(jwt.SigningMethodRS256)

	// Add claims to the token
	claims := token.Claims.(jwt.MapClaims)
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expiration time (e.g., 24 hours)
	claims["iss"] = "827127"                              // Issuer claim
	claims["alg"] = "RS256"                               // Algorithm used for signing

	// Sign the token with the RSA private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func approveHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Action: Approve")
}

func rejectHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Action: Reject")
}
