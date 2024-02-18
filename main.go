//this code validates Payload coming from deployment webhook
//creates JWT using pem key and installation id
//obtains Access token write it in token.txt
//fetches deployment url writes it in url.txt
//get response from user at /response and accordingly runs or rejects workflow.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	secretToken      = "abcdefg"
	privateKeyPath   = "C:\\Users\\mishr\\Downloads\\demo-gha-app.2024-02-13.private-key.pem"
	installationID   = 47252163
	accessTokenURL   = "https://api.github.com/app/installations/47252163/access_tokens"
	serverPort       = ":8080"
	responseTemplate = `<html>
<head>
    <title>Response</title>
</head>
<body>
    <h1>Response Page</h1>
    <form action="/response" method="post">
        <button type="submit" name="state" value="approved">Approved</button>
        <button type="submit" name="state" value="rejected">Rejected</button>
    </form>
</body>
</html>`
)

var (
	deploymentCallbackURL string
	state                 string
)

type Payload struct {
	DeploymentCallbackURL string `json:"deployment_callback_url"`
}

func main() {
	http.HandleFunc("/webhook", webhookHandler)
	http.HandleFunc("/response", responseHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, this is the webhook server!")
	})
	fmt.Printf("Server listening on %s\n", serverPort)
	http.ListenAndServe(serverPort, nil)
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	// Validate payload
	signature := r.Header.Get("X-Hub-Signature-256")
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	isValid := validatePayload(signature, payload)
	if !isValid {
		http.Error(w, "Invalid payload", http.StatusUnauthorized)
		return
	}

	// Write payload to file and extract deployment_callback_url
	err = ioutil.WriteFile("payload.json", payload, 0644)
	if err != nil {
		http.Error(w, "Error writing payload to file", http.StatusInternalServerError)
		return
	}
	var p Payload
	err = json.Unmarshal(payload, &p)
	if err != nil {
		http.Error(w, "Error parsing payload", http.StatusInternalServerError)
		return
	}
	deploymentCallbackURL = p.DeploymentCallbackURL
	err = ioutil.WriteFile("URL.txt", []byte(deploymentCallbackURL), 0644)
	if err != nil {
		http.Error(w, "Error writing URL to file", http.StatusInternalServerError)
		return
	}

	// Create JWT
	jwtToken, err := createJWT()
	if err != nil {
		http.Error(w, "Error creating JWT", http.StatusInternalServerError)
		return
	}
	err = ioutil.WriteFile("jwt.txt", []byte(jwtToken), 0644)
	if err != nil {
		http.Error(w, "Error writing JWT to file", http.StatusInternalServerError)
		return
	}

	// Obtain Installation token
	installationToken, err := getInstallationToken(jwtToken)
	if err != nil {
		http.Error(w, "Error obtaining Installation token", http.StatusInternalServerError)
		return
	}
	err = ioutil.WriteFile("token.txt", []byte(installationToken), 0644)
	if err != nil {
		http.Error(w, "Error writing Installation token to file", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/response", http.StatusSeeOther)
}

func responseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		state = r.FormValue("state")
		if state != "approved" && state != "rejected" {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// Send POST request to GitHub API
		accessToken, err := ioutil.ReadFile("token.txt")
		if err != nil {
			http.Error(w, "Error reading Installation token", http.StatusInternalServerError)
			return
		}
		data := fmt.Sprintf(`{"environment_name":"Dev","state":"%s","comment":"All health checks passed."}`, state)
		req, err := http.NewRequest("POST", deploymentCallbackURL, bytes.NewBuffer([]byte(data)))
		if err != nil {
			http.Error(w, "Error creating POST request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+string(accessToken))
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Error sending POST request to GitHub API", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Unexpected status code from GitHub API", resp.StatusCode)
			return
		}

		fmt.Fprintf(w, "POST request sent successfully with state: %s", state)
	} else {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, responseTemplate)
	}
}

func validatePayload(signature string, payload []byte) bool {
	// Validate payload here using secret token and HMAC hex digest
	key := []byte(secretToken)
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)
	expected := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(signature), []byte(expected))
}

func createJWT() (string, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", err
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": 827127,
		"alg": "RS256",
	})

	return token.SignedString(privateKey)
}

func getInstallationToken(jwtToken string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", accessTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	token, ok := result["token"].(string)
	if !ok {
		return "", fmt.Errorf("token not found in response")
	}
	return token, nil
}
