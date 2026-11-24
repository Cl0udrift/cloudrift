// Package trustapprovals keeps the outside AWS accounts a person has approved as trusted, each with a note and the
// date. The list sits beside the scans and is added to the configured approved accounts at the next scan.
package trustapprovals

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Approval struct {
	AccountID  string    `json:"account_id"`
	Note       string    `json:"note"`
	ApprovedAt time.Time `json:"approved_at"`
}

const fileName = "trust-approvals.json"

var (
	mu        sync.Mutex
	accountRe = regexp.MustCompile(`^[0-9]{12}$`)
)

func Load(dir string) ([]Approval, error) {
	mu.Lock()
	defer mu.Unlock()
	return load(dir)
}

func load(dir string) ([]Approval, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Approval
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("read %s: %w", fileName, err)
	}
	return out, nil
}

func save(dir string, list []Approval) error {
	sort.Slice(list, func(i, j int) bool { return list[i].AccountID < list[j].AccountID })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, fileName+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, fileName))
}

// Add approves an account, or updates its note. A note is required: an approval nobody can explain later is the
// problem this list exists to avoid.
func Add(dir, accountID, note string, now time.Time) (Approval, error) {
	accountID, note = strings.TrimSpace(accountID), strings.TrimSpace(note)
	if !accountRe.MatchString(accountID) {
		return Approval{}, fmt.Errorf("account_id must be a 12-digit AWS account ID")
	}
	if note == "" {
		return Approval{}, fmt.Errorf("a note is required: say who the account belongs to and why it is trusted")
	}
	if len(note) > 500 {
		return Approval{}, fmt.Errorf("note must be 500 characters or fewer")
	}
	mu.Lock()
	defer mu.Unlock()
	list, err := load(dir)
	if err != nil {
		return Approval{}, err
	}
	a := Approval{AccountID: accountID, Note: note, ApprovedAt: now.UTC()}
	replaced := false
	for i := range list {
		if list[i].AccountID == accountID {
			list[i], replaced = a, true
		}
	}
	if !replaced {
		list = append(list, a)
	}
	return a, save(dir, list)
}

func Remove(dir, accountID string) error {
	mu.Lock()
	defer mu.Unlock()
	list, err := load(dir)
	if err != nil {
		return err
	}
	kept := list[:0]
	for _, a := range list {
		if a.AccountID != accountID {
			kept = append(kept, a)
		}
	}
	return save(dir, kept)
}

// AccountIDs lists the approved accounts. A file that cannot be read yields none: an unreadable approval list must
// never silently approve anything.
func AccountIDs(dir string) []string {
	list, err := Load(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.AccountID)
	}
	return out
}
