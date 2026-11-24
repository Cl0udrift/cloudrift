// Package business holds what Cloudrift cannot learn from AWS: who owns an account, how fast a finding must be
// fixed, and what a loss is worth to this organization. They are the customer's own assumptions, kept beside the
// scans, and every figure built from them is labelled as theirs.
package business

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Range is a low and a high figure. A loss is a range, never a point.
type Range struct {
	Low  float64 `json:"low"`
	High float64 `json:"high"`
}

type FixDays struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// Loss holds the values used to put risk into money. Nothing is filled in by default: until the customer enters
// them, no dollar figure is shown anywhere.
type Loss struct {
	Currency string `json:"currency"`
	// StoreCost is what it costs if one data store (a bucket, database or secret) is breached.
	StoreCost Range `json:"store_cost"`
	// HostnameCost is what it costs if one of your hostnames is taken over.
	HostnameCost Range `json:"hostname_cost"`
	// LikelihoodCritical and LikelihoodHigh are the chance, per year, that a finding of that severity is used. 0 to 1.
	LikelihoodCritical Range `json:"likelihood_critical"`
	LikelihoodHigh     Range `json:"likelihood_high"`
}

type Settings struct {
	// Owners maps an AWS account ID to the team or person who answers for it.
	Owners  map[string]string `json:"owners"`
	FixDays FixDays           `json:"fix_days"`
	Loss    Loss              `json:"loss"`
}

// Configured is true when the values needed to estimate a loss have been entered.
func (l Loss) Configured() bool {
	return l.StoreCost.High > 0 && (l.LikelihoodCritical.High > 0 || l.LikelihoodHigh.High > 0)
}

const fileName = "business-settings.json"

var accountRe = regexp.MustCompile(`^[0-9]{12}$`)

// Defaults are deadlines most teams already work to. They are settings, not claims.
func Defaults() Settings {
	return Settings{Owners: map[string]string{}, FixDays: FixDays{Critical: 7, High: 30, Medium: 90}, Loss: Loss{Currency: "USD"}}
}

func Validate(s Settings) error {
	for acct, owner := range s.Owners {
		if !accountRe.MatchString(acct) {
			return fmt.Errorf("owner account %q must be a 12-digit AWS account ID", acct)
		}
		if len(owner) > 120 {
			return fmt.Errorf("owner for %s is too long", acct)
		}
	}
	for name, d := range map[string]int{"critical": s.FixDays.Critical, "high": s.FixDays.High, "medium": s.FixDays.Medium} {
		if d < 0 || d > 3650 {
			return fmt.Errorf("fix_days.%s must be between 0 and 3650", name)
		}
	}
	for name, r := range map[string]Range{"store_cost": s.Loss.StoreCost, "hostname_cost": s.Loss.HostnameCost} {
		if r.Low < 0 || r.High < r.Low {
			return fmt.Errorf("loss.%s needs 0 <= low <= high", name)
		}
	}
	for name, r := range map[string]Range{"likelihood_critical": s.Loss.LikelihoodCritical, "likelihood_high": s.Loss.LikelihoodHigh} {
		if r.Low < 0 || r.High < r.Low || r.High > 1 {
			return fmt.Errorf("loss.%s needs 0 <= low <= high <= 1", name)
		}
	}
	if len(s.Loss.Currency) > 4 {
		return fmt.Errorf("loss.currency must be a short code or symbol")
	}
	return nil
}

var mu sync.Mutex

func Load(dir string) (Settings, error) {
	mu.Lock()
	defer mu.Unlock()
	return load(dir)
}

func load(dir string) (Settings, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileName))
	if errors.Is(err, os.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Defaults(), err
	}
	s := Defaults()
	if err := json.Unmarshal(raw, &s); err != nil {
		return Defaults(), fmt.Errorf("read %s: %w", fileName, err)
	}
	if s.Owners == nil {
		s.Owners = map[string]string{}
	}
	return s, nil
}

func Save(dir string, s Settings) (Settings, error) {
	s.Currency()
	if err := Validate(s); err != nil {
		return Settings{}, err
	}
	mu.Lock()
	defer mu.Unlock()
	owners := map[string]string{}
	for k, v := range s.Owners {
		if v = strings.TrimSpace(v); v != "" {
			owners[strings.TrimSpace(k)] = v
		}
	}
	s.Owners = owners
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return Settings{}, err
	}
	tmp := filepath.Join(dir, fileName+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return Settings{}, err
	}
	return s, os.Rename(tmp, filepath.Join(dir, fileName))
}

// Currency fills an empty currency with the default so a saved file always names one.
func (s *Settings) Currency() {
	if strings.TrimSpace(s.Loss.Currency) == "" {
		s.Loss.Currency = "USD"
	}
}

// Cache reads the settings file again only when it changes, so a list of thousands of findings does not read it
// thousands of times.
type Cache struct {
	dir  string
	mu   sync.Mutex
	mod  time.Time
	size int64
	cur  Settings
}

func NewCache(dir string) *Cache { return &Cache{dir: dir, cur: Defaults()} }

func (c *Cache) Get() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(filepath.Join(c.dir, fileName))
	if err != nil {
		c.cur, c.mod, c.size = Defaults(), time.Time{}, 0
		return c.cur
	}
	if !st.ModTime().Equal(c.mod) || st.Size() != c.size {
		if s, err := Load(c.dir); err == nil {
			c.cur, c.mod, c.size = s, st.ModTime(), st.Size()
		}
	}
	return c.cur
}

// Owner is the owner set for an account, or "".
func (c *Cache) Owner(accountID string) string { return c.Get().Owners[accountID] }
