package storage

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DBRequest represents a database job request
type DBRequest struct {
	fn   func(*sql.Tx) error
	done chan error
}

type SQLiteStorage struct {
	*TableMailboxes
	*TableMails
	db        *sql.DB
	writeChan chan DBRequest
}

func NewSQLiteStorage(filename string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite", "file:"+filename+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	s := &SQLiteStorage{
		db: db,
	}
	s.TableMailboxes, err = NewTableMailboxes(db, s.WithTx)
	if err != nil {
		return nil, fmt.Errorf("NewTableMailboxes: %w", err)
	}
	s.TableMails, err = NewTableMails(db, s.WithTx)
	if err != nil {
		return nil, fmt.Errorf("NewTableMails: %w", err)
	}
	s.writeChan = make(chan DBRequest)
	s.start()
	return s, nil
}

func (s *SQLiteStorage) Close() error {
	close(s.writeChan)
	return s.db.Close()
}

// Start a single writer goroutine
func (storage *SQLiteStorage) start() {
	go func() {
		for req := range storage.writeChan {
			tx, err := storage.db.Begin()
			if err != nil {
				req.done <- err
				continue
			}

			if err := req.fn(tx); err != nil {
				_ = tx.Rollback()
				req.done <- err
			} else {
				req.done <- tx.Commit()
			}
		}
	}()
}

// WithTx sends a transaction request through the channel
func (storage *SQLiteStorage) WithTx(fn func(*sql.Tx) error) error {
	done := make(chan error)
	storage.writeChan <- DBRequest{fn: fn, done: done}
	return <-done
}
