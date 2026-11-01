package collectors

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// IAMCredentialReportAPI is the account credential report: one CSV that lists console
// access, MFA and access keys for every user. Separate so role-only clients keep working.
type IAMCredentialReportAPI interface {
	GenerateCredentialReport(ctx context.Context, params *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

var credentialReportPoll = time.Second

// fetchCredentialReport generates the report and waits for it. AWS reports are cached for
// four hours, so a recent one is returned at once.
func fetchCredentialReport(ctx context.Context, api IAMCredentialReportAPI) ([]byte, error) {
	for attempt := 0; attempt < 15; attempt++ {
		out, err := api.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, err
		}
		if out.State == iamtypes.ReportStateTypeComplete {
			report, err := api.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			if err != nil {
				return nil, err
			}
			return report.Content, nil
		}
		select {
		case <-time.After(credentialReportPoll):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("credential report was not ready after 15 attempts")
}

// annotateCredentials copies console, MFA and access key facts from the report onto the
// matching user nodes. A user missing from the report keeps no credential properties,
// which the dashboard shows as not collected instead of as no credentials.
func annotateCredentials(users []models.AssetNode, content []byte) error {
	rows, err := csv.NewReader(strings.NewReader(string(content))).ReadAll()
	if err != nil {
		return err
	}
	if len(rows) < 1 {
		return errors.New("credential report is empty")
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	need := []string{"arn", "password_enabled", "mfa_active", "access_key_1_active", "access_key_2_active"}
	for _, n := range need {
		if _, ok := col[n]; !ok {
			return errors.New("credential report is missing column " + n)
		}
	}
	byARN := map[string]map[string]string{}
	for _, row := range rows[1:] {
		rec := map[string]string{}
		for name, i := range col {
			if i < len(row) {
				rec[name] = row[i]
			}
		}
		byARN[rec["arn"]] = rec
	}
	for i := range users {
		if users[i].AssetType != models.AssetIAMUser {
			continue
		}
		rec, ok := byARN[users[i].ARN]
		if !ok {
			continue
		}
		props := users[i].Properties
		props["credential_report"] = "collected"
		props["console_enabled"] = rec["password_enabled"] == "true"
		props["password_last_used"] = reportTime(rec["password_last_used"])
		props["mfa_active"] = rec["mfa_active"] == "true"
		var keys []map[string]any
		for _, slot := range []string{"access_key_1", "access_key_2"} {
			if rec[slot+"_active"] == "not_supported" || rec[slot+"_active"] == "" {
				continue
			}
			keys = append(keys, map[string]any{
				"slot":         slot,
				"active":       rec[slot+"_active"] == "true",
				"last_rotated": reportTime(rec[slot+"_last_rotated"]),
				"last_used":    reportTime(rec[slot+"_last_used_date"]),
				"last_service": rec[slot+"_last_used_service"],
			})
		}
		props["access_keys"] = keys
	}
	return nil
}

// reportTime keeps the report's RFC3339 value and turns its N/A and no_information into "".
func reportTime(v string) string {
	if _, err := time.Parse(time.RFC3339, v); err != nil {
		return ""
	}
	return v
}
