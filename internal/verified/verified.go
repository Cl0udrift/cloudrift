// Package verified holds counts that describe the test suites, so the Coverage page prints what the tests
// contain instead of a number typed into a string. counts.json is written by the tests themselves (run with
// UPDATE_VERIFIED_COUNTS=1) and each test fails when the file is out of date.
package verified

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed counts.json
var raw []byte

type Counts struct {
	// GoldenCases is the number of hand-written evaluator cases tied to AWS documentation.
	GoldenCases int `json:"golden_cases"`
}

var (
	once   sync.Once
	loaded Counts
)

func Load() Counts {
	once.Do(func() { _ = json.Unmarshal(raw, &loaded) })
	return loaded
}
