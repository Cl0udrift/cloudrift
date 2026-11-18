package ciem

import (
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// reachListCap is how many callers an escalation finding lists; the total is always stated.
const reachListCap = 15

// reacher answers "who can reach this role" for the escalation findings: the users and roles whose stored policies let
// them call sts:AssumeRole on it, with the credential weakness of each user. It is the same evaluation the Access Explorer
// shows. Direct callers only: someone who could assume one of those callers is not listed.
type reacher struct {
	assets []models.AssetNode
	rels   []models.Relationship
	byARN  map[string]models.AssetNode
	now    time.Time
	cache  map[string]reachInfo
	// deadline, when set, stops new reach computations: each one evaluates every user and role in the scan, so on a large
	// account they must not run past the escalation budget. skipped counts the ones that were not computed.
	deadline time.Time
	skipped  int
}

type reachCaller struct {
	ARN        string `json:"arn"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Weak       bool   `json:"weak_credential"`
	Weakness   string `json:"weakness,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	weakStatus string
}

type reachInfo struct {
	Callers   []reachCaller `json:"callers"`
	Total     int           `json:"total"`
	Weak      int           `json:"weak"`
	Evaluated int           `json:"evaluated"`
	Unknown   int           `json:"unknown"`
	Note      string        `json:"note"`
	// Skipped says the callers were not computed because the time budget ended; Total is then not a count.
	Skipped bool `json:"skipped,omitempty"`
	// weakValidated and weakPending say how sure the weakest route is: assumed under every evaluated control, or only
	// by the policies because organization controls were not collected.
	weakValidated, weakPending bool
}

func newReacher(assets []models.AssetNode, rels []models.Relationship, now time.Time) *reacher {
	return &reacher{assets: assets, rels: rels, byARN: indexAssets(assets), now: now, cache: map[string]reachInfo{}}
}

func (r *reacher) reach(role models.AssetNode) reachInfo {
	if info, ok := r.cache[role.ARN]; ok {
		return info
	}
	if !r.deadline.IsZero() && time.Now().After(r.deadline) {
		r.skipped++
		info := reachInfo{Skipped: true, Callers: []reachCaller{}, Note: "Who can assume this role was not computed: the time budget for the escalation work ended first."}
		r.cache[role.ARN] = info
		return info
	}
	list, evaluated, unknown := blastradius.WhoCan(scoringScan, "sts:AssumeRole", role, r.assets, r.rels, r.now)
	info := reachInfo{Evaluated: evaluated, Unknown: unknown, Total: len(list), Callers: []reachCaller{},
		Note: "Users and roles in this scan whose stored policies let them assume the role. Callers in accounts that were not scanned and federated principals are not listed, and nobody who could only assume one of these callers is."}
	for _, c := range list {
		rc := reachCaller{ARN: c.ARN, Name: c.Name, Kind: c.Kind, Status: c.Status, AccountID: c.AccountID, Reason: c.Reason}
		if u, ok := r.byARN[c.ARN]; ok && u.AssetType == models.AssetIAMUser {
			if cred := CredentialSummaryFor(u, r.now); cred != nil {
				var why []string
				if cred.Console && !cred.MFA {
					why = append(why, "console access, no MFA")
				}
				why = append(why, keyProblems(cred.Findings)...)
				if len(why) > 0 {
					rc.Weak, rc.Weakness = true, strings.Join(why, "; ")
					info.Weak++
					if c.Status == blastradius.StatusPendingControls {
						info.weakPending = true
					} else {
						info.weakValidated = true
					}
				}
			}
		}
		info.Callers = append(info.Callers, rc)
	}
	sort.SliceStable(info.Callers, func(i, j int) bool {
		a, b := info.Callers[i], info.Callers[j]
		if a.Weak != b.Weak {
			return a.Weak
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.Name < b.Name
	})
	if len(info.Callers) > reachListCap {
		info.Callers = info.Callers[:reachListCap]
	}
	r.cache[role.ARN] = info
	return info
}

// raiseForWeakCaller moves a finding up one severity when a user with a weak credential can reach the role: that is the
// combination to fix first. A route that exists only by the policies (organization controls not collected) raises it to High at most.
func raiseForWeakCaller(sev models.Severity, info reachInfo) models.Severity {
	switch {
	case info.weakValidated:
		switch sev {
		case models.SeverityLow:
			return models.SeverityMedium
		case models.SeverityMedium:
			return models.SeverityHigh
		case models.SeverityHigh:
			return models.SeverityCritical
		}
	case info.weakPending:
		switch sev {
		case models.SeverityLow:
			return models.SeverityMedium
		case models.SeverityMedium:
			return models.SeverityHigh
		}
	}
	return sev
}
