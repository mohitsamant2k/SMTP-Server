package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Helper function to get environment variables with default fallback
func GetEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

var (
	ClientID     string
	ClientSecret string
	TenantID     string
	RedirectURI  string
	TenantName   string
	SMTPDomain   string
	AuthURL      string
	TokenURL     string
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file:", err)
		log.Println("Using environment variables or defaults instead")
	}
	ClientID = GetEnvOrDefault("AZURE_CLIENT_ID", "")
	ClientSecret = GetEnvOrDefault("AZURE_CLIENT_SECRET", "")
	TenantID = GetEnvOrDefault("AZURE_TENANT_ID", "")
	RedirectURI = GetEnvOrDefault("REDIRECT_URI", "")
	TenantName = GetEnvOrDefault("TENANT_NAME", "")
	SMTPDomain = GetEnvOrDefault("SMTP_DOMAIN", "")

	AuthURL = fmt.Sprintf("https://%s.ciamlogin.com/%s/oauth2/v2.0/authorize", TenantName, TenantID)
	TokenURL = fmt.Sprintf("https://%s.ciamlogin.com/%s/oauth2/v2.0/token", TenantName, TenantID)
}

func VerifyUser(username, password string) (bool, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", ClientID)
	data.Set("scope", "openid") // or more scopes as needed
	data.Set("username", username)
	data.Set("password", password)
	data.Set("client_secret", ClientSecret)

	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("authentication failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	// If access_token exists, login is successful
	if _, ok := result["access_token"]; ok {
		return true, nil
	}

	return false, fmt.Errorf("authentication failed: %s", string(body))
}
