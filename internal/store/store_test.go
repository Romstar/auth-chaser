package store

import (
	"path/filepath"
	"testing"

	"github.com/Romstar/auth-chaser/pkg/types"
)

func TestJobLifecycle(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	job, err := s.CreateJob("job-1", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != JobQueued {
		t.Fatalf("status %s", job.Status)
	}
	rep := &types.Report{Target: "https://example.com", PassCount: 1}
	if err := s.UpdateJob("job-1", JobSucceeded, "", rep); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetJob("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != JobSucceeded || got.Report == nil || got.Report.PassCount != 1 {
		t.Fatalf("unexpected job %#v", got)
	}
	list, err := s.ListJobs(10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
}
