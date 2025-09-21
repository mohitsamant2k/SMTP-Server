package storage

// Storage defines the interface for database storage operations
type Storage interface {
	MailboxSelect(mailbox string) (bool, error)
	MailNextID(mailbox string) (int, error)
	MailIDForSeq(mailbox string, id int) (int, error)
	MailUnseen(mailbox string) (int, error)
	MailboxList(onlySubscribed bool) ([]string, error)
	MailboxCreate(name string) error
	MailboxRename(old, new string) error
	MailboxDelete(name string) error

	MailCreate(mailbox string, data []byte, sender string, receiver string) (int, error)
	MailSelect(mailbox string, id int) (int, *Mail, error)
	MailSearch(mailbox string) ([]uint32, error)
	MailUpdateFlags(mailbox string, id int, seen, answered, flagged, deleted bool) error
	MailDelete(mailbox string, id int) error
	MailExpunge(mailbox string) error
	MailCount(mailbox string) (int, error)

	// Close the storage connection
	Close() error
}
