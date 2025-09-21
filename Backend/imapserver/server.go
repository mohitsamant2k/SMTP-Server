package imapserver

import (
	"log"

	"github.com/emersion/go-imap/server"
)

type IMAPServer struct {
	Server  *server.Server
	Backend *Backend
}

func NewIMAPServer(backend *Backend, addr string, insecure bool) (*IMAPServer, error) {
	s := &IMAPServer{
		Server:  server.New(backend),
		Backend: backend,
	}
	s.Server.Addr = addr
	s.Server.AllowInsecureAuth = insecure
	go func() {
		if err := s.Server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	return s, nil
}