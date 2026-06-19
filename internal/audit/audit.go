package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const Dir = ".agentguard"

type Event struct {
	ID             int64    `json:"id,omitempty"`
	Timestamp      string   `json:"timestamp"`
	WorkingDir     string   `json:"working_dir"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	Status         string   `json:"status"`
	Reason         string   `json:"reason"`
	ExitCode       int      `json:"exit_code"`
	DurationMillis int64    `json:"duration_ms"`
	SensitiveFiles []string `json:"sensitive_files,omitempty"`
	User           string   `json:"user"`
}

type Store struct {
	db        *sql.DB
	jsonl     *os.File
	jsonlPath string
}

func Open(baseDir string) (*Store, error) {
	dir := filepath.Join(baseDir, Dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "audit.db"))
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	jsonlPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, jsonl: f, jsonlPath: jsonlPath}, nil
}

func (s *Store) Close() error {
	var errs []error
	if s.jsonl != nil {
		errs = append(errs, s.jsonl.Close())
	}
	if s.db != nil {
		errs = append(errs, s.db.Close())
	}
	return errors.Join(errs...)
}

func (s *Store) Add(e Event) error {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	sensitive, err := json.Marshal(e.SensitiveFiles)
	if err != nil {
		return err
	}
	args, err := json.Marshal(e.Args)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`INSERT INTO events
		(timestamp, working_dir, command, args, status, reason, exit_code, duration_ms, sensitive_files, user)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.WorkingDir, e.Command, string(args), e.Status, e.Reason, e.ExitCode, e.DurationMillis, string(sensitive), e.User)
	if err != nil {
		return err
	}
	if id, err := res.LastInsertId(); err == nil {
		e.ID = id
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := s.jsonl.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.jsonl.Sync()
}

func (s *Store) List(limit int) ([]Event, error) {
	order := "ASC"
	if limit > 0 {
		order = "DESC"
	}
	query := `SELECT id, timestamp, working_dir, command, args, status, reason, exit_code, duration_ms, sensitive_files, user
		FROM events ORDER BY id ` + order
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(query+` LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var e Event
		var args, sensitive string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.WorkingDir, &e.Command, &args, &e.Status, &e.Reason, &e.ExitCode, &e.DurationMillis, &sensitive, &e.User); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(args), &e.Args)
		_ = json.Unmarshal([]byte(sensitive), &e.SensitiveFiles)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit > 0 {
		slices.Reverse(events)
	}
	return events, nil
}

func (s *Store) JSONLPath() string {
	return s.jsonlPath
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		working_dir TEXT NOT NULL,
		command TEXT NOT NULL,
		args TEXT NOT NULL,
		status TEXT NOT NULL,
		reason TEXT NOT NULL,
		exit_code INTEGER NOT NULL,
		duration_ms INTEGER NOT NULL,
		sensitive_files TEXT NOT NULL,
		user TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);`)
	return err
}

func NewEvent(args []string, status, reason string, exitCode int, duration time.Duration, sensitive []string) Event {
	wd, _ := os.Getwd()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	return Event{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		WorkingDir:     wd,
		Command:        strings.Join(args, " "),
		Args:           append([]string(nil), args...),
		Status:         status,
		Reason:         reason,
		ExitCode:       exitCode,
		DurationMillis: duration.Milliseconds(),
		SensitiveFiles: append([]string(nil), sensitive...),
		User:           user,
	}
}
