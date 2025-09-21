package storage

import (
	"database/sql"
	"fmt"
)

type TableMailboxes struct {
	db                      *sql.DB
	withTx                  func(func(*sql.Tx) error) error
	selectMailboxes         *sql.Stmt
	listMailboxes           *sql.Stmt
	createMailbox           *sql.Stmt
	renameMailbox           *sql.Stmt
	deleteMailbox           *sql.Stmt
}

const mailboxesSchema = `
	CREATE TABLE IF NOT EXISTS mailboxes (
		mailbox 	TEXT NOT NULL DEFAULT('INBOX'),
		PRIMARY 	KEY(mailbox)
	);
`

const mailboxesList = `
	SELECT mailbox FROM mailboxes
`

const mailboxesSelect = `
	SELECT mailbox FROM mailboxes WHERE mailbox = $1
`

const mailboxesCreate = `
	INSERT OR IGNORE INTO mailboxes (mailbox) VALUES($1)
`

const mailboxesRename = `
	UPDATE mailboxes SET mailbox = $1 WHERE mailbox = $2
`

const mailboxesDelete = `
	DELETE FROM mailboxes WHERE mailbox = $1
`

func NewTableMailboxes(db *sql.DB, withTx func(func(*sql.Tx) error) error) (*TableMailboxes, error) {
	t := &TableMailboxes{
		db:     db,
		withTx: withTx,
	}
	_, err := db.Exec(mailboxesSchema)
	if err != nil {
		return nil, fmt.Errorf("db.Exec: %w", err)
	}
	t.listMailboxes, err = db.Prepare(mailboxesList)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(mailboxesCreate): %w", err)
	}
	t.selectMailboxes, err = db.Prepare(mailboxesSelect)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(mailboxesSelect): %w", err)
	}
	t.createMailbox, err = db.Prepare(mailboxesCreate)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(mailboxesCreate): %w", err)
	}
	t.deleteMailbox, err = db.Prepare(mailboxesDelete)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(mailboxesDelete): %w", err)
	}
	t.renameMailbox, err = db.Prepare(mailboxesRename)
	if err != nil {
		return nil, fmt.Errorf("db.Prepare(mailboxesRename): %w", err)
	}
	return t, nil
}

// Get the list of mail box
func (t *TableMailboxes) MailboxList(onlySubscribed bool) ([]string, error) {
	// show whole mailbox subscribed feature not there for now
	stmt := t.listMailboxes
	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf("t.listMailboxes.Query: %w", err)
	}
	defer rows.Close()
	var mailboxes []string
	for rows.Next() {
		var mailbox string
		if err := rows.Scan(&mailbox); err != nil {
			return nil, fmt.Errorf("rows.Scan: %w", err)
		}
		mailboxes = append(mailboxes, mailbox)
	}
	return mailboxes, nil
}

// Check if the mailbox exists
func (t *TableMailboxes) MailboxSelect(mailbox string) (bool, error) {
	// fetches the firt row . Name are unique for the mailboxes table
	row := t.selectMailboxes.QueryRow(mailbox)
	if err := row.Err(); err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("row.Err: %w", err)
	} else if err == sql.ErrNoRows {
		return false, nil
	}
	var got string
	if err := row.Scan(&got); err != nil {
		return false, fmt.Errorf("row.Scan: %w", err)
	}
	return mailbox == got, nil
}

func (t *TableMailboxes) MailboxCreate(name string) error {
	err := t.withTx(func(tx *sql.Tx) error {
		_, err := tx.Stmt(t.createMailbox).Exec(name)
		return err
	})
	if err != nil {
		return fmt.Errorf("t.createMailbox.Exec: %w", err)
	}
	return nil
}

func (t *TableMailboxes) MailboxRename(old, new string) error {
	err := t.withTx(func(tx *sql.Tx) error {
		_, err := tx.Stmt(t.renameMailbox).Exec(old, new)
		return err
	})
	if err != nil {
		return fmt.Errorf("t.renameMailbox.Exec: %w", err)
	}
	return nil
}

func (t *TableMailboxes) MailboxDelete(name string) error {
	err := t.withTx(func(tx *sql.Tx) error {
		_, err := tx.Stmt(t.deleteMailbox).Exec(name)
		return err
	})
	if err != nil {
		return fmt.Errorf("t.deleteMailbox.Exec: %w", err)
	}
	return nil
}
