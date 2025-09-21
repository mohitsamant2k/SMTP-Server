package imapserver

import (
	"errors"
	"fmt"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

type User struct {
	backend  *Backend
	username string
	conn     *imap.ConnInfo
}

func (u *User) Username() string {
	fmt.Println("Username called for user:", u.username)
	return u.username
}

func (u *User) ListMailboxes(subscribed bool) (mailboxes []backend.Mailbox, err error) {
	fmt.Println("ListMailboxes called for user:", u.username, "subscribed:", subscribed)
	names, err := u.backend.Storage.MailboxList(subscribed)
	if err != nil {
		return nil, err
	}

	for _, mailbox := range names {
		mailboxes = append(mailboxes, &Mailbox{
			backend: u.backend,
			user:    u,
			name:    mailbox,
		})
	}

	return
}

func (u *User) GetMailbox(name string) (mailbox backend.Mailbox, err error) {
	fmt.Println("GetMailbox called for user:", u.username, "mailbox name:", name)
	if name == "" {
		return &Mailbox{
			backend: u.backend,
			user:    u,
			name:    "",
		}, nil
	}
	ok, _ := u.backend.Storage.MailboxSelect(name)
	if !ok {
		return nil, fmt.Errorf("mailbox %q not found", name)
	}
	return &Mailbox{
		backend: u.backend,
		user:    u,
		name:    name,
	}, nil
}

func (u *User) CreateMailbox(name string) error {
	fmt.Println("CreateMailbox called for user:", u.username, "mailbox name:", name)
	return u.backend.Storage.MailboxCreate(name)
}

func (u *User) DeleteMailbox(name string) error {
	fmt.Println("DeleteMailbox called for user:", u.username, "mailbox name:", name)
	switch name {
	case "INBOX", "Outbox":
		return errors.New("Cannot delete " + name)
	default:
		return u.backend.Storage.MailboxDelete(name)
	}
}

func (u *User) RenameMailbox(existingName, newName string) error {
	fmt.Println("RenameMailbox called for user:", u.username, "existing name:", existingName, "new name:", newName)
	switch existingName {
	case "INBOX", "Outbox":
		return errors.New("Cannot rename " + existingName)
	default:
		return u.backend.Storage.MailboxRename(existingName, newName)
	}
}

func (u *User) Logout() error {
	fmt.Println("Logout called for user:", u.username)
	return nil
}
