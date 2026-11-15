// Package store persists chase jobs and reports in SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
	_ "modernc.org/sqlite"
)

// JobStatus is the lifecycle of an async chase.
type JobStatus string

const (
	JobQueued     JobStatus = "queued"
	JobRunning    JobStatus = "running"
	JobSucceeded  JobStatus = "succeeded"
	JobFailed     JobStatus = "failed"
)

// Job is a persisted chase request.
type Job struct {
	ID        string          `json:"id"`
	Status    JobStatus       `json:"status"`
	Target    string          `json:"target"`
	Error     string          `json:"error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	Report    *types.Report   `json:"report,omitempty"`
}

// Store is a SQLite-backed job store.
type Store struct {
	db *sql.DB
}

// Open creates or opens a SQLite database under dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "auth-chaser.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  target TEXT NOT NULL,
  error TEXT,
  report_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
`)
	return err
}

// CreateJob inserts a queued job.
func (s *Store) CreateJob(id, target string) (*Job, error) {
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO jobs (id, status, target, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		id, string(JobQueued), target, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	return &Job{ID: id, Status: JobQueued, Target: target, CreatedAt: now, UpdatedAt: now}, nil
}

// UpdateJob writes status/error/report.
func (s *Store) UpdateJob(id string, status JobStatus, jobErr string, rep *types.Report) error {
	var reportJSON sql.NullString
	if rep != nil {
		b, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		reportJSON = sql.NullString{String: string(b), Valid: true}
	}
	_, err := s.db.Exec(
		`UPDATE jobs SET status=?, error=?, report_json=?, updated_at=? WHERE id=?`,
		string(status), jobErr, reportJSON, time.Now().UTC().Format(time.RFC3339Nano), id,
	)
	return err
}

// GetJob loads one job.
func (s *Store) GetJob(id string) (*Job, error) {
	row := s.db.QueryRow(`SELECT id, status, target, error, report_json, created_at, updated_at FROM jobs WHERE id=?`, id)
	var j Job
	var status, created, updated string
	var errMsg sql.NullString
	var reportJSON sql.NullString
	if err := row.Scan(&j.ID, &status, &j.Target, &errMsg, &reportJSON, &created, &updated); err != nil {
		return nil, err
	}
	j.Status = JobStatus(status)
	j.Error = errMsg.String
	j.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	j.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if reportJSON.Valid && reportJSON.String != "" {
		var rep types.Report
		if err := json.Unmarshal([]byte(reportJSON.String), &rep); err == nil {
			j.Report = &rep
		}
	}
	return &j, nil
}

// ListJobs returns newest jobs first.
func (s *Store) ListJobs(limit int) ([]*Job, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT id, status, target, error, report_json, created_at, updated_at FROM jobs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Job, 0)
	for rows.Next() {
		var j Job
		var status, created, updated string
		var errMsg, reportJSON sql.NullString
		if err := rows.Scan(&j.ID, &status, &j.Target, &errMsg, &reportJSON, &created, &updated); err != nil {
			return nil, err
		}
		j.Status = JobStatus(status)
		j.Error = errMsg.String
		j.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		j.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		if reportJSON.Valid && reportJSON.String != "" {
			var rep types.Report
			if err := json.Unmarshal([]byte(reportJSON.String), &rep); err == nil {
				j.Report = &rep
			}
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// Close closes the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// EnsureOpen is a helper for tests.
func EnsureOpen(dir string) (*Store, error) {
	s, err := Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return s, nil
}
