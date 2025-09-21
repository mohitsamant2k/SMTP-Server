package imapserver

import (
	"fmt"
	"log"
	"smtp-server-backend/storage"
	"smtp-server-backend/utils"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

type Backend struct {
	Storage storage.Storage
}

func (b *Backend) Login(conn *imap.ConnInfo, username, password string) (backend.User, error) {
	// Authenticate the user
	log.Printf("Attempting login for user: %s", username)
	if ok, err := utils.VerifyUser(username, password); err != nil {
		log.Printf("Login failed for user: %s, error: %v", username, err)
		return nil, err
	} else if !ok {
		log.Printf("Login failed for user: %s, invalid credentials", username)
		return nil, fmt.Errorf("invalid credentials")
	}
	user := &User{
		backend:  b,
		username: username,
		conn:     conn,
	}
	return user, nil
}
