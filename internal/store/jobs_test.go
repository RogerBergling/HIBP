package store

import (
	"path/filepath"
	"testing"
)

func TestJobLifecycleAndTargetCounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.hibp"), []byte("correct horse battery staple"), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	first, err := s.CreateHost(Host{Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: "/tmp/key"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateHost(Host{Name: "web02", Address: "10.0.0.12", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: "/tmp/key"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateJob(Job{
		Kind: "facts", Status: JobQueued, Actor: "test", Title: "Collect facts", Payload: `{}`,
	}, []JobTarget{
		{HostID: first.ID, HostName: first.Name, Status: JobTargetPending},
		{HostID: second.ID, HostName: second.Name, Status: JobTargetPending},
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Total != 2 || job.ID == "" {
		t.Fatalf("unexpected job: %+v", job)
	}
	active, err := s.ActiveJobHostIDs()
	if err != nil {
		t.Fatal(err)
	}
	if !active[first.ID] || !active[second.ID] {
		t.Fatalf("expected both hosts active: %+v", active)
	}
	claimed, err := s.ClaimNextJob()
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Status != JobRunning || len(claimed.Targets) != 2 {
		t.Fatalf("unexpected claimed job: %+v", claimed)
	}
	if err := s.StartJobTarget(job.ID, first.ID, "collecting"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishJobTarget(JobTarget{JobID: job.ID, HostID: first.ID, Status: JobTargetSucceeded, Stage: "done", Detail: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishJobTarget(JobTarget{JobID: job.ID, HostID: second.ID, Status: JobTargetFailed, Stage: "failed", Error: "boom"}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Completed != 2 || updated.Failed != 1 || updated.Skipped != 0 {
		t.Fatalf("unexpected counters: %+v", updated)
	}
	if err := s.FinishJob(job.ID, JobFailed, "one failure"); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ListJobs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || len(jobs[0].Targets) != 2 {
		t.Fatalf("unexpected list result: %+v", jobs)
	}
	if err := s.RetryJob(job.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	retried, err := s.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status != JobQueued || retried.Completed != 1 || retried.Targets[1].Status != JobTargetPending {
		t.Fatalf("unexpected retry state: %+v", retried)
	}
}

func TestInterruptAndResumeJobs(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "jobs.hibp"), []byte("correct horse battery staple"), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	host, err := s.CreateHost(Host{Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: "/tmp/key"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateJob(Job{Kind: "facts", Status: JobQueued, Actor: "test", Title: "Facts"}, []JobTarget{{HostID: host.ID, HostName: host.Name}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNextJob(); err != nil {
		t.Fatal(err)
	}
	if err := s.StartJobTarget(job.ID, host.ID, "collecting"); err != nil {
		t.Fatal(err)
	}
	if err := s.InterruptJob(job.ID, "restart"); err != nil {
		t.Fatal(err)
	}
	interrupted, err := s.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.Status != JobInterrupted || interrupted.Targets[0].Status != JobTargetInterrupted {
		t.Fatalf("unexpected interrupted state: %+v", interrupted)
	}
	if err := s.RetryJob(job.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	retried, err := s.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status != JobQueued || retried.Targets[0].Status != JobTargetPending {
		t.Fatalf("unexpected retried state: %+v", retried)
	}
}
