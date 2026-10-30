package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

const datasetDataOrigin = "synthetic-mendeley-3pddspdv4v-cc-by-4.0"

// datasetRecord is one profile of the Mendeley "AWS IAM Policy Configuration Profiles" dataset
// (DOI 10.17632/3pddspdv4v, CC BY 4.0). The data is synthetic and carries injected-flaw labels.
type datasetRecord struct {
	ProfileID       string          `json:"profile_id"`
	EntityName      string          `json:"entity_name"`
	EntityType      string          `json:"entity_type"`
	PolicyName      string          `json:"policy_name"`
	Context         map[string]any  `json:"context"`
	PolicyDocument  json.RawMessage `json:"policy_document"`
	Label           int             `json:"label"`
	Vulnerabilities []string        `json:"vulnerabilities"`
}

// datasetLabel is the ground truth kept beside the scan for accuracy checks.
type datasetLabel struct {
	RoleARN         string   `json:"role_arn"`
	ProfileID       string   `json:"profile_id"`
	Misconfigured   bool     `json:"misconfigured"`
	Vulnerabilities []string `json:"vulnerabilities"`
}

// datasetScan converts role profiles into IAM role assets. Users are skipped: the scan model is role based.
func datasetScan(scanID string, records []datasetRecord) (assets []models.AssetNode, labels []datasetLabel, skippedUsers int) {
	for _, r := range records {
		account, _ := r.Context["AccountId"].(string)
		if r.EntityType != "role" || account == "" || r.EntityName == "" {
			if r.EntityType == "user" {
				skippedUsers++
			}
			continue
		}
		arn := "arn:aws:iam::" + account + ":role/" + r.EntityName
		assets = append(assets, models.AssetNode{
			ARN: arn, AssetType: models.AssetIAMRole, Name: r.EntityName, AccountID: account, ScanID: scanID,
			Properties: map[string]any{
				"path": "/", "resolution_status": "collected",
				"inline_policy_documents":       []string{string(r.PolicyDocument)},
				"policy_retrieval_status":       models.PolicyRetrievalOK,
				"permissions_boundary_status":   "confirmed_absent",
				"permissions_boundary_evidence": "dataset: no permissions boundary is described",
				"session_policy_status":         "confirmed_absent",
				"session_policy_evidence":       "dataset: no session policy is described",
				"scp_status":                    "confirmed_absent",
				"scp_evidence":                  "dataset: no service control policy is described",
				"rcp_status":                    "confirmed_absent",
				"rcp_evidence":                  "dataset: no resource control policy is described",
				"data_origin":                   datasetDataOrigin,
			},
		})
		labels = append(labels, datasetLabel{RoleARN: arn, ProfileID: r.ProfileID, Misconfigured: r.Label == 1, Vulnerabilities: r.Vulnerabilities})
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ARN < assets[j].ARN })
	sort.Slice(labels, func(i, j int) bool { return labels[i].RoleARN < labels[j].RoleARN })
	return assets, labels, skippedUsers
}

func loadDataset(path string) ([]datasetRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []datasetRecord
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, fmt.Errorf("parse dataset: %w", err)
	}
	return records, nil
}

func importDataset(input, outputDir, scanID string, now time.Time) (string, int, int, error) {
	if !scans.IsSafeScanID(scanID) {
		return "", 0, 0, fmt.Errorf("invalid --scan-id %q", scanID)
	}
	records, err := loadDataset(input)
	if err != nil {
		return "", 0, 0, err
	}
	assets, labels, skipped := datasetScan(scanID, records)
	accounts := map[string]struct{}{}
	for _, a := range assets {
		accounts[a.AccountID] = struct{}{}
	}
	ids := make([]string, 0, len(accounts))
	for id := range accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	path := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(filepath.Join(path, "assets"), 0o755); err != nil {
		return "", 0, 0, err
	}
	meta := models.ScanSnapshot{
		ScanID: scanID, Timestamp: now.UTC(), AccountIDs: ids, ToolVersion: version,
		Synthetic: true, DataOrigin: datasetDataOrigin,
	}
	for name, v := range map[string]any{
		"scan-metadata.json":  meta,
		"findings.json":       []any{},
		"relationships.json":  []any{},
		"assets/iam.json":     assets,
		"dataset-labels.json": labels,
	} {
		if err := writeJSONFile(filepath.Join(path, name), v); err != nil {
			return "", 0, 0, err
		}
	}
	return path, len(assets), skipped, nil
}

func newDemoImportCmd() *cobra.Command {
	var input, outputDir, scanID string
	cmd := &cobra.Command{
		Use:   "import-iam-dataset",
		Short: "Build a labeled synthetic scan from the Mendeley AWS IAM policy profiles dataset (CC BY 4.0)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			path, roles, skipped, err := importDataset(input, outputDir, scanID, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d role assets to %s (%d user profiles skipped: the scan model is role based)\n", roles, path, skipped)
			return nil
		},
	}
	cmd.Flags().StringVar(&input, "input", "", "Path to the dataset's iam_dataset.json")
	cmd.Flags().StringVar(&outputDir, "output-dir", "output", "Output directory")
	cmd.Flags().StringVar(&scanID, "scan-id", "iam-dataset", "Scan directory name")
	return cmd
}
