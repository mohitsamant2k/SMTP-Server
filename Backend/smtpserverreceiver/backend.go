package smtpserverreceiver

import (
	"smtp-server-backend/storage"
)

type SMTPBackend struct {
	storage storage.Storage
}

// NewSMTPBackend creates a new SMTP backend with the given storage
func NewSMTPBackend(storage storage.Storage) *SMTPBackend {
	return &SMTPBackend{
		storage: storage,
	}
}
