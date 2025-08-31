package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/toorop/go-dkim"
	"golang.org/x/oauth2"
)

// Azure AD configuration variables
var (
	clientID     string
	clientSecret string
	tenantID     string
	redirectURI  string
	frontendURL  string
	cookieSecure bool
	tenantName   string
)

// Create the OAuth2 config with Azure AD endpoints
var oauthConfig *oauth2.Config

// init is called before main - loads environment variables and initializes OAuth config
func init() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file:", err)
		log.Println("Using environment variables or defaults instead")
	}

	// Get configuration from environment variables with defaults
	clientID = getEnvOrFatal("AZURE_CLIENT_ID")
	clientSecret = getEnvOrFatal("AZURE_CLIENT_SECRET")
	tenantID = getEnvOrFatal("AZURE_TENANT_ID")
	redirectURI = getEnvOrDefault("REDIRECT_URI", "")
	frontendURL = getEnvOrDefault("FRONTEND_URL", "")
	cookieSecure = strings.ToLower(getEnvOrDefault("COOKIE_SECURE", "false")) == "true"
	tenantName = getEnvOrDefault("TENANT_NAME", "")

	log.Println("OAuth configuration loaded from environment")

	// Initialize OAuth config
	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"openid", "profile", "email", "User.Read"},
		Endpoint: oauth2.Endpoint{
			// This is the Azure AD authority URL where users will be redirected for authentication
			AuthURL:  fmt.Sprintf("https://%s.ciamlogin.com/%s/oauth2/v2.0/authorize", tenantName, tenantID),
			TokenURL: fmt.Sprintf("https://%s.ciamlogin.com/%s/oauth2/v2.0/token", tenantName, tenantID),
		},
	}
}

// Helper function to get environment variables with default fallback
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Helper function to get required environment variables
func getEnvOrFatal(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}

// Simple in-memory session store (replace with Redis or DB for production)
var sessions = make(map[string]SessionData)

// SessionData stores user info
type SessionData struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	ExpiresAt   time.Time `json:"-"`
	AccessToken string    `json:"-"` // Don't expose to client
}

// MicrosoftGraphUser represents the user information from Microsoft Graph API
type MicrosoftGraphUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"` // This is typically the email
	Mail              string `json:"mail"`              // Sometimes the email is here
}

// parseJWT parses a JWT token and returns the claims
// Note: In a production environment, you should validate the token signature
func parseJWT(tokenString string) (map[string]interface{}, error) {
	// JWT tokens are three base64-encoded segments joined by dots
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// We need the middle part (payload)
	payloadBase64 := parts[1]

	// Add padding if needed
	if l := len(payloadBase64) % 4; l > 0 {
		payloadBase64 += strings.Repeat("=", 4-l)
	}

	// Decode the base64 string
	payload, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %v", err)
	}

	// Parse JSON
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, fmt.Errorf("error parsing claims: %v", err)
	}

	return claims, nil
}

// getUserInfoFromGraph gets user info from Microsoft Graph API
func getUserInfoFromGraph(accessToken string) (*MicrosoftGraphUser, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("graph API error: %s - %s", resp.Status, string(body))
	}

	var user MicrosoftGraphUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func generateRandomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// enableCORS adds CORS headers to allow requests from the frontend
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", frontendURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Starts the OAuth flow - redirects to Azure AD login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate cryptographically secure random state
	state := generateRandomState()

	// Save state in a cookie - this will be verified when Azure calls back
	// to prevent CSRF attacks
	stateCookie := &http.Cookie{
		Name:     "auth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300, // 5 minutes
		SameSite: http.SameSiteNoneMode,
		Secure:   cookieSecure,
	}
	http.SetCookie(w, stateCookie)

	// Get returnTo path from query parameter and store in a cookie
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo != "" {
		returnToCookie := &http.Cookie{
			Name:     "return_to",
			Value:    returnTo,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   300, // 5 minutes
			SameSite: http.SameSiteNoneMode,
			Secure:   cookieSecure,
		}
		http.SetCookie(w, returnToCookie)
	}

	// Build the Azure AD authorization URL
	// This is where we redirect the user to Azure AD - the authority URL
	azureURL := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	// Log the redirect for debugging (remove in production)
	log.Printf("Redirecting to Azure AD: %s", azureURL)

	// Redirect user's browser to Azure AD login
	http.Redirect(w, r, azureURL, http.StatusTemporaryRedirect)
}

// Handles the OAuth callback from Azure AD
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("auth_state")
	if err != nil {
		http.Error(w, "State cookie not found", http.StatusBadRequest)
		return
	}

	queryState := r.URL.Query().Get("state")
	if stateCookie.Value != queryState {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("Error exchanging code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Extract user info from ID token or Microsoft Graph API
	var email, name string

	// First attempt: Get info from ID token (if available)
	if idToken, ok := token.Extra("id_token").(string); ok {
		log.Printf("ID token found, attempting to parse")
		claims, err := parseJWT(idToken)
		if err == nil {
			// Extract email from ID token claims
			if emailClaim, ok := claims["email"].(string); ok {
				email = emailClaim
			} else if upnClaim, ok := claims["upn"].(string); ok {
				email = upnClaim
			}

			// Extract name from ID token claims
			if nameClaim, ok := claims["name"].(string); ok {
				name = nameClaim
			}

			log.Printf("Extracted from ID token - Email: %s, Name: %s", email, name)
		} else {
			log.Printf("Error parsing ID token: %v", err)
		}
	}

	// Second attempt: Get info from Microsoft Graph API if needed
	if email == "" || name == "" {
		log.Printf("Calling Microsoft Graph API to get user info")
		user, err := getUserInfoFromGraph(token.AccessToken)
		if err == nil {
			if email == "" {
				if user.Mail != "" {
					email = user.Mail
				} else {
					email = user.UserPrincipalName
				}
			}

			if name == "" && user.DisplayName != "" {
				name = user.DisplayName
			}

			log.Printf("Extracted from Graph API - Email: %s, Name: %s", email, name)
		} else {
			log.Printf("Error calling Microsoft Graph API: %v", err)
		}
	}

	// Fallback to defaults if we couldn't get the info
	if email == "" {
		http.Error(w, "token exchange but email is empty", http.StatusInternalServerError)
		return
	}

	if name == "" {
		http.Error(w, "token exchange but name is empty", http.StatusInternalServerError)
		return
	}

	// Create a session
	sessionID := generateRandomState()
	sessions[sessionID] = SessionData{
		ID:          sessionID,
		Email:       email,
		Name:        name,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		AccessToken: token.AccessToken,
	}

	// Set session cookie
	sessionCookie := &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400, // 24 hours
		SameSite: http.SameSiteNoneMode,
		Secure:   cookieSecure,
	}
	http.SetCookie(w, sessionCookie)

	// Redirect back to frontend
	returnPath := "/"
	if cookie, err := r.Cookie("return_to"); err == nil {
		returnPath = cookie.Value
	}
	log.Printf("Redirecting to Home %s", frontendURL+returnPath)
	http.Redirect(w, r, frontendURL+returnPath, http.StatusTemporaryRedirect)
}

// Returns user info if authenticated
func handleMe(w http.ResponseWriter, r *http.Request) {
	// Check for session cookie

	log.Printf("Handle me request %s", r.URL.Path)
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get session data
	sessionData, exists := sessions[cookie.Value]
	if !exists || time.Now().After(sessionData.ExpiresAt) {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionData)
}

// Logs the user out by clearing the session cookie
func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session from memory
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteNoneMode,
		Secure:   cookieSecure,
	})

	w.WriteHeader(http.StatusNoContent)
}

// StoreMail stores received mail (implement as needed)
func StoreMail(from, to, data string) {
	log.Printf("Storing mail: From=%s To=%s Data=%s", from, to, data)
	// TODO: Save to database, file, etc.
}

// SMTP Backend implements go-smtp Backend interface
// Handles receiving emails

type SMTPBackend struct{}

func (bkd *SMTPBackend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	return &SMTPSession{}, nil
}

func (bkd *SMTPBackend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	return &SMTPSession{}, nil
}

type SMTPSession struct {
	from string
	to   string
	data string
}

func (s *SMTPSession) Mail(from string, opts smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *SMTPSession) Rcpt(to string) error {
	s.to = to
	return nil
}

func (s *SMTPSession) Data(r io.Reader) error {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return err
	}
	s.data = ""
	bodyBytes, err := io.ReadAll(msg.Body)
	if err == nil {
		s.data = string(bodyBytes)
	}
	StoreMail(s.from, s.to, s.data)
	return nil
}

func (s *SMTPSession) Reset()        {}
func (s *SMTPSession) Logout() error { return nil }

// SendEmail sends an email using SMTP
func SendEmail(smtpAddr, from, to, subject, body string) error {
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body)
	return smtp.SendMail(smtpAddr, nil, from, []string{to}, msg)
}

// SendEmailWithDNS sends an email by resolving recipient MX records and optionally signing with DKIM
func SendEmailWithDNS(from, to, subject, body, dkimDomain, dkimSelector, dkimPrivateKey string) error {
	// Resolve MX records for recipient domain
	domainParts := strings.SplitN(to, "@", 2)
	if len(domainParts) != 2 {
		return fmt.Errorf("invalid recipient email: %s", to)
	}
	recipientDomain := domainParts[1]
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(recipientDomain), dns.TypeMX)
	resp, _, err := c.Exchange(&m, "8.8.8.8:53") // Use Google DNS
	if err != nil {
		return fmt.Errorf("DNS MX lookup failed: %v", err)
	}
	if len(resp.Answer) == 0 {
		return fmt.Errorf("no MX records found for domain: %s", recipientDomain)
	}
	// Pick highest priority MX
	mx := ""
	priority := uint16(65535)
	for _, ans := range resp.Answer {
		if mxrec, ok := ans.(*dns.MX); ok {
			if mxrec.Preference < priority {
				priority = mxrec.Preference
				mx = mxrec.Mx
			}
		}
	}
	if mx == "" {
		return fmt.Errorf("no valid MX record found")
	}
	mx = strings.TrimSuffix(mx, ".")

	// Build email message
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body

	// DKIM signing (optional)
	if dkimDomain != "" && dkimSelector != "" && dkimPrivateKey != "" {
		options := dkim.NewSigOptions()
		options.PrivateKey = []byte(dkimPrivateKey)
		options.Domain = dkimDomain
		options.Selector = dkimSelector
		options.Headers = []string{"from", "to", "subject"}
		options.AddSignatureTimestamp = true
		options.BodyLength = 0
		options.SignatureExpireIn = 3600
		options.HeadersCanon = dkim.Relaxed
		options.BodyCanon = dkim.Relaxed
		options.Debug = false
		dkimHeader, err := dkim.Sign(&options, []byte(msg))
		if err != nil {
			return fmt.Errorf("DKIM signing failed: %v", err)
		}
		msg = string(dkimHeader) + msg
	}

	// Connect to recipient MX server
	addr := mx + ":25"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to MX server: %v", err)
	}
	cSmtp, err := smtp.NewClient(conn, mx)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer cSmtp.Close()
	if err := cSmtp.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}
	if err := cSmtp.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %v", err)
	}
	w, err := cSmtp.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}
	w.Close()
	cSmtp.Quit()
	return nil
}

func main() {
	// Register API routes
	http.HandleFunc("/api/auth/login", enableCORS(handleLogin))
	http.HandleFunc("/api/auth/callback", enableCORS(handleCallback))
	http.HandleFunc("/api/auth/me", enableCORS(handleMe))
	http.HandleFunc("/api/auth/logout", enableCORS(handleLogout))

	// Start SMTP server on port 25 for receiving mail
	go func() {
		be := &SMTPBackend{}
		s := smtp.NewServer(be)
		s.Addr = ":25"
		s.Domain = "mohitsamant.space"
		s.AllowInsecureAuth = true // For demo only
		log.Printf("SMTP server listening on port 25 for receiving mail...")
		if err := s.ListenAndServe(); err != nil {
			log.Fatalf("SMTP server error: %v", err)
		}
	}()

	// Start server
	port := 8080
	log.Printf("Backend server starting on port %d...", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
