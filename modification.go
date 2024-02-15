//THis code is generating installation token writing in INS_TOKEN.txt file
//fetching deployment_callback_url from incoming payload and writing in URL.txt
//Hence no need to make GET request to obtain RUN_ID anymore
//As that value is present in payload.txt under key "deployment_callback_url"
//So now we can directly make POST request to either approve or reject the deployment.
(this is being done in this program as well user would be asked to enter "approved" or "rejected").
//accordingly WF will either run or get failed
//Also removed useless Approve and reject handler this is latest code now.
*******************************
package main
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	webhookSecret    = "abcdefg"
	installationID   = 47252163 // Your installation ID
	jwtExpirationMin = 9
)

func main() {
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/webhook", webhookHandler)

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

	// Extract deployment_callback_url from payload
	var payloadData map[string]interface{}
	err = json.Unmarshal(body, &payloadData)
	if err != nil {
		fmt.Println("Failed to parse payload JSON:", err)
		http.Error(w, "Failed to parse payload JSON", http.StatusInternalServerError)
		return
	}

	deploymentCallbackURL, ok := payloadData["deployment_callback_url"].(string)
	if !ok {
		fmt.Println("deployment_callback_url not found in payload")
		http.Error(w, "deployment_callback_url not found in payload", http.StatusBadRequest)
		return
	}

	// Write deployment_callback_url to URL.txt
	err = ioutil.WriteFile("URL.txt", []byte(deploymentCallbackURL), 0644)
	if err != nil {
		fmt.Println("Failed to write deployment_callback_url to file:", err)
		http.Error(w, "Failed to write deployment_callback_url to file", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	jwtToken, err := generateJWTToken()
	if err != nil {
		fmt.Println("Failed to generate JWT:", err)
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Log JWT token to jwt.txt
	err = ioutil.WriteFile("jwt.txt", []byte(jwtToken), 0644)
	if err != nil {
		fmt.Println("Failed to write JWT to file:", err)
		http.Error(w, "Failed to write JWT to file", http.StatusInternalServerError)
		return
	}

	// Get installation token
	installationToken, err := getInstallationToken(jwtToken)
	if err != nil {
		fmt.Println("Failed to get installation token:", err)
		http.Error(w, "Failed to get installation token", http.StatusInternalServerError)
		return
	}

	// Prompt the user to enter the state value
	fmt.Println("Enter 'approved' or 'rejected' for the state:")
	var state string
	fmt.Scanln(&state)

	// Validate user input for state
	if state != "approved" && state != "rejected" {
		fmt.Println("Invalid state value. State must be 'approved' or 'rejected'.")
		http.Error(w, "Invalid state value", http.StatusBadRequest)
		return
	}

	// Send callback request
	err = sendCallbackRequest(installationToken, deploymentCallbackURL, state)
	if err != nil {
		fmt.Println("Failed to send callback request:", err)
		http.Error(w, "Failed to send callback request", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	fmt.Fprintf(w, "JWT token: %s\nDeployment callback URL obtained and written to URL.txt", jwtToken)
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
	claims["exp"] = time.Now().Add(time.Minute * jwtExpirationMin).Unix() // Token expiration time (e.g., 24 hours)
	claims["iss"] = "827127"                                              // Issuer claim
	claims["alg"] = "RS256"                                               // Algorithm used for signing

	// Sign the token with the RSA private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func getInstallationToken(jwtToken string) (string, error) {
	// Create HTTP client
	client := &http.Client{}

	// Create HTTP request to obtain installation token
	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	// Make HTTP request to obtain installation token
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Unmarshal JSON response to extract installation token
	var responseMap map[string]interface{}
	err = json.Unmarshal(body, &responseMap)
	if err != nil {
		return "", err
	}

	// Extract installation token
	installationToken, ok := responseMap["token"].(string)
	if !ok {
		return "", fmt.Errorf("installation token not found in response")
	}

	// Write installation token to file
	err = ioutil.WriteFile("INS_TOKEN.txt", []byte(installationToken), 0644)
	if err != nil {
		return "", err
	}

	return installationToken, nil
}

func sendCallbackRequest(installationToken, deploymentCallbackURL, state string) error {
	// Prepare request payload
	payload := map[string]interface{}{
		"environment_name": "Dev",
		"state":            state,
		"comment":          "All health checks passed.",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Create HTTP client
	client := &http.Client{}

	// Create HTTP request
	req, err := http.NewRequest("POST", deploymentCallbackURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	// Make HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Print request sent
	fmt.Println("Request sent successfully.")

	return nil
}
