package smtpserverreceiver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
	"github.com/wttw/spf"
)

type SMTPSession struct {
	remoteAddr net.Addr
	from       string
	to         []string
	backend    *SMTPBackend
	data       bytes.Buffer
}

func (b *SMTPBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	log.Printf("New SMTP connection from %s", c.Conn().RemoteAddr())
	return &SMTPSession{
		remoteAddr: c.Conn().RemoteAddr(),
		backend:    b,
	}, nil
}

func (s *SMTPSession) AuthPlain(username, password string) error {
	// We don't use authentication for incoming mail in this example
	log.Printf("AUTH PLAIN: %s", username)
	return smtp.ErrAuthUnsupported
}

func (s *SMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	log.Printf("MAIL FROM: %s", from)
	log.Printf("MailOptions: %+v", opts)
	s.from = from

	// Extract domain from "from" address
	addr, err := mail.ParseAddress(from)
	if err != nil {
		log.Printf("Failed to parse MAIL FROM address: %v", err)
		return err
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		log.Printf("Invalid MAIL FROM address format: %s", addr.Address)
		return fmt.Errorf("invalid MAIL FROM address format")
	}
	domain := parts[1]

	// Get remote IP address
	ipstr, _, err := net.SplitHostPort(s.remoteAddr.String())
	if err != nil {
		log.Printf("Failed to get remote IP: %v", err)
		return err
	}

	// Check SPF
	ip := net.ParseIP(ipstr)
	result, _ := spf.Check(context.Background(), ip, addr.Address, domain)
	if result == spf.Pass {
		fmt.Println("✅ SPF Passed")
		return nil
	}

	log.Printf("SPF check failed for %s: %s", addr.Address, result)

	return fmt.Errorf("❌ SPF failed: %s (%s)", result, addr.Address)
}

func (s *SMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Printf("RCPT TO: %s", to)
	log.Printf("RcptOptions: %+v", opts)
	s.to = append(s.to, to)
	return nil
}

func (s *SMTPSession) Data(r io.Reader) error {
	s.data.Reset()
	if _, err := io.Copy(&s.data, r); err != nil {
		return err
	}

	log.Printf("Received email: %d bytes", s.data.Len())

	// Get the data
	data := s.data.Bytes()
	fmt.Printf("Email data:\n%s\n", string(data))

	// Parse the message for both DKIM verification and content processing
	m, err := message.Read(bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to parse email message: %v", err)
		return err
	}

	// Perform DKIM verification
	log.Printf("Starting DKIM verification...")
	verifications, err := dkim.Verify(bytes.NewReader(data))
	if err != nil {
		log.Printf("DKIM verification error: %v", err)
		return nil
	} else {
		if len(verifications) == 0 {
			log.Println("No DKIM signatures found")
			return fmt.Errorf("❌ DKIM verification failed")
		}
		for _, v := range verifications {
			if v.Err == nil {
				log.Println("✅ Valid DKIM signature for:", v.Domain)
			} else {
				log.Println("❌ Invalid DKIM signature for:", v.Domain, v.Err)
				return fmt.Errorf("❌ DKIM verification failed")
			}
		}
	}
	
	var b bytes.Buffer
	if err := m.WriteTo(&b); err != nil {
		return fmt.Errorf("m.WriteTo: %w", err)
	}
	// Store the email using the storage backend
	// to is first sender for now
	if id, err := s.backend.storage.MailCreate("INBOX", b.Bytes(), s.from, s.to[0]); err != nil {
		log.Printf("Failed to store email: %v", err)
		return err
	} else {
		log.Printf("Stored email with ID %d", id)
	}

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
