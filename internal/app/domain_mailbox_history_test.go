package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDomainMailboxHistoryPersistsAfterDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("owner-1", "", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := store.AddDomainMailboxesForOwner("owner-1", domain.ID, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	generated := mailboxes[0].Email
	if err := store.DeleteMailbox(mailboxes[0].ID); err != nil {
		t.Fatal(err)
	}
	if history := store.Snapshot().DomainMailboxHistory; len(history) != 1 || history[0].Email != generated {
		t.Fatalf("history after delete = %#v, want %q", history, generated)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if history := reloaded.Snapshot().DomainMailboxHistory; len(history) != 1 || history[0].Email != generated {
		t.Fatalf("reloaded history = %#v, want %q", history, generated)
	}
}

func TestDomainMailboxGenerationSkipsHistoricalAddress(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("", "", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.addDomainMailboxesForOwner("", domain.ID, "", "", 1, func() (string, error) {
		return "reused", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteMailbox(first[0].ID); err != nil {
		t.Fatal(err)
	}

	locals := []string{"reused", "fresh"}
	calls := 0
	created, err := store.addDomainMailboxesForOwner("", domain.ID, "", "", 1, func() (string, error) {
		local := locals[calls]
		calls++
		return local, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(created) != 1 || created[0].Email != "mail-fresh@example.test" {
		t.Fatalf("calls=%d created=%#v", calls, created)
	}
	if history := store.Snapshot().DomainMailboxHistory; len(history) != 2 {
		t.Fatalf("history = %#v, want 2 entries", history)
	}
}

func TestDomainMailboxHistoryMigratesExistingMailboxes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	legacy := State{
		NextID:  3,
		Domains: []Domain{{ID: "dom-1", Name: "Example.Test", Enabled: true}},
		Mailboxes: []Mailbox{{
			ID:        "mbx-2",
			Provider:  MailboxProviderDomain,
			DomainID:  "dom-1",
			Email:     "Mail-Legacy@Example.Test",
			CreatedAt: createdAt,
		}},
		SystemSettings: defaultSystemSettings(),
	}
	legacy.SystemSettings.UpdatedAt = createdAt
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	history := store.Snapshot().DomainMailboxHistory
	if len(history) != 1 || history[0].Email != "mail-legacy@example.test" || history[0].DomainName != "example.test" || !history[0].GeneratedAt.Equal(createdAt) {
		t.Fatalf("migrated history = %#v", history)
	}
	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if history = reloaded.Snapshot().DomainMailboxHistory; len(history) != 1 {
		t.Fatalf("history duplicated after reload = %#v", history)
	}
}

func TestConcurrentDomainMailboxGenerationRemainsUnique(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("", "", "example.test")
	if err != nil {
		t.Fatal(err)
	}

	const workers = 8
	const perWorker = 10
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, createErr := store.AddDomainMailboxesForOwner("", domain.ID, "", "", perWorker)
			errs <- createErr
		}()
	}
	wg.Wait()
	close(errs)
	for createErr := range errs {
		if createErr != nil {
			t.Fatal(createErr)
		}
	}

	snapshot := store.Snapshot()
	want := workers * perWorker
	if len(snapshot.Mailboxes) != want || len(snapshot.DomainMailboxHistory) != want {
		t.Fatalf("mailboxes=%d history=%d want=%d", len(snapshot.Mailboxes), len(snapshot.DomainMailboxHistory), want)
	}
	seen := make(map[string]struct{}, want)
	for _, mailbox := range snapshot.Mailboxes {
		if _, exists := seen[mailbox.Email]; exists {
			t.Fatalf("duplicate mailbox generated: %s", mailbox.Email)
		}
		seen[mailbox.Email] = struct{}{}
	}
}
