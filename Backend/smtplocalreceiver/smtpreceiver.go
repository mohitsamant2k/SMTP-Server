package smtplocalreceiver

import (
	"smtp-server-backend/storage"
	"strings"
	"time"
	"log"

	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/emersion/go-message"
	"smtp-server-backend/utils"
)

type SMTPBackend struct {
	storage storage.Storage
}

var password = utils.GetEnvOrDefault("MAILSENDER_KEY", "") // Replace with secure password retrieval in production
var username = utils.GetEnvOrDefault("MAILSENDER_USERNAME", "") // Replace with secure username retrieval in production

// NewSMTPBackend creates a new SMTP backend with the given storage
func NewSMTPBackend(storage storage.Storage) *SMTPBackend {
	return &SMTPBackend{
		storage: storage,
	}
}

type SMTPSession struct {
	remoteAddr net.Addr
	from       string
	to         []string
	backend    *SMTPBackend
	data       bytes.Buffer
	auth       bool
}

// AuthMechanisms returns a slice of available auth mechanisms; only PLAIN is
// supported in this example.
func (s *SMTPSession) AuthMechanisms() []string {
	log.Printf("Local AuthMechanisms called")
	return []string{sasl.Plain}
}

// Auth is the handler for supported authenticators.
func (s *SMTPSession) Auth(mech string) (sasl.Server, error) {
	log.Printf("Local Auth called with mechanism: %s", mech)
	return sasl.NewPlainServer(func(identity, username, password string) error {
		log.Printf("Local Auth attempt: identity=%s, username=%s", identity, username)
		if ok, err := utils.VerifyUser(username,password); err != nil {
			log.Printf("Local Auth failed for user: %s, error: %v", username, err)
			return err
		} else if !ok {
			log.Printf("Local Auth failed for user: %s, invalid credentials", username)
			return fmt.Errorf("invalid credentials")
		}
		s.auth = true
		s.from = username
		log.Printf("Local Auth successful for user: %s", username)
		return nil
	}), nil
}

func (b *SMTPBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	log.Printf("Local New SMTP connection from %s", c.Conn().RemoteAddr())
	return &SMTPSession{
		remoteAddr: c.Conn().RemoteAddr(),
		backend:    b,
	}, nil
}

func (s *SMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	if !s.auth {
		log.Printf("Local MAIL called without authentication")
		return smtp.ErrAuthRequired
	}
	log.Printf("Local MAIL FROM: %s", from)
	log.Printf("Local MailOptions: %+v", opts)
	if s.from != from {
		return fmt.Errorf("MAIL FROM address does not match authenticated user")
	}
	return nil
}

func (s *SMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !s.auth {
		log.Printf("Local RCPT called without authentication")
		return smtp.ErrAuthRequired
	}
	log.Printf("Local RCPT TO: %s", to)
	log.Printf("Local RcptOptions: %+v", opts)
	s.to = append(s.to, to)
	return nil
}

func (s *SMTPSession) Data(r io.Reader) error {
	if !s.auth {
		log.Printf("Local Data called without authentication")
		return smtp.ErrAuthRequired
	}
	s.data.Reset()
	if _, err := io.Copy(&s.data, r); err != nil {
		return err
	}

	log.Printf("Local Received email: %d bytes", s.data.Len())

	// Get the data
	data := s.data.Bytes()
	fmt.Printf("Local Email data:\n%s\n", string(data))

	// Parse the message for both DKIM verification and content processing
	m, err := message.Read(bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to parse email message: %v", err)
		return err
	}

	var b bytes.Buffer
	if err := m.WriteTo(&b); err != nil {
		return fmt.Errorf("m.WriteTo: %w", err)
	}
	// Store the email using the storage backend
	// to is first sender for now
	if id, err := s.backend.storage.MailCreate("Sent", b.Bytes(), s.from, s.to[0]); err != nil {
		log.Printf("Local Failed to store email: %v", err)
		return err
	} else {
		log.Printf("Local Stored email with ID %d", id)
	}
	err = smtp.SendMail("mail.smtp2go.com:2525",
		sasl.NewPlainClient("", username, password),
		s.from, s.to, strings.NewReader(string(data)))
	if err != nil {
		log.Printf("Local Failed to send email via MailerSend: %v", err)
		return err
	}
	log.Printf("Local Sent email via MailerSend from %s to %v", s.from, s.to)

	return nil
}

func (s *SMTPSession) Reset() {
	s.from = ""
	s.to = nil
	s.data.Reset()
}

func (s *SMTPSession) Logout() error {
	log.Printf("Logging out SMTP session from %s", s.remoteAddr)
	return nil
}

func RunSMTPReceiver(storage storage.Storage, domain string) {
	// Implementation for running the SMTP receiver
	// This will involve setting up the SMTP server and handling incoming emails
	backend := NewSMTPBackend(storage)
	s := smtp.NewServer(backend)
	s.Addr = ":1025" // Listen on port 1025
	s.Domain = domain
	s.ReadTimeout = 10 * time.Second
	s.WriteTimeout = 10 * time.Second
	s.MaxMessageBytes = 25 * 1024 * 1024 // 25MB
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true // For testing only, remove in production

	log.Printf("Starting local SMTP server on port 1025...")
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("local SMTP server error: %v", err)
	}
}
