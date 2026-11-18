package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/spf13/cobra"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func newVerifyCommand(cfgPath *string) *cobra.Command {
	verify := &cobra.Command{Use: "verify", Short: "Check Cloudrift's own answers against an independent source"}
	var scanID, outputDir string
	var maxProbes int
	var asJSON bool
	authz := &cobra.Command{
		Use:   "authz",
		Short: "Compare local authorization decisions with iam:SimulatePrincipalPolicy",
		Long: `Takes users and roles from a stored scan, asks Cloudrift's evaluator whether each may perform identity-only IAM actions,
and asks the IAM policy simulator the same question. The simulator reads identity policies and permissions boundaries only, so
probes for callers with organization controls (SCP/RCP) in the scan are reported as not comparable, not as disagreements.
Read-only: the only AWS call is iam:SimulatePrincipalPolicy. Exits non-zero on a false allow or a bad deny.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				return err
			}
			if outputDir == "" {
				outputDir = cfg.Output.OutputDir
			}
			id, err := scans.ResolveScanDirectoryName(outputDir, scanID)
			if err != nil {
				return fmt.Errorf("scan %q: %w", scanID, err)
			}
			assets, err := scans.LoadAssets(outputDir, id)
			if err != nil {
				return err
			}
			rels, err := scans.LoadRelationships(outputDir, id)
			if err != nil {
				return err
			}
			if err := ensureValidSession(cmd.Context(), cfg.AWS.ManagementProfile, cmd); err != nil {
				return err
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(cmd.Context(), awsconfig.WithSharedConfigProfile(cfg.AWS.ManagementProfile), awsconfig.WithDefaultRegion("us-east-1"))
			if err != nil {
				return err
			}
			failed, err := runVerifyAuthz(cmd.Context(), iam.NewFromConfig(awsCfg), id, assets, rels, maxProbes, asJSON, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if failed {
				return fmt.Errorf("the evaluator and the simulator disagree in a way that is not safe: see above")
			}
			return nil
		},
	}
	authz.Flags().StringVar(&scanID, "scan-id", "latest", "Scan ID or \"latest\"")
	authz.Flags().StringVar(&outputDir, "output-dir", "", "Output directory (default: from config)")
	authz.Flags().IntVar(&maxProbes, "max-probes", 200, "At most this many simulator calls")
	authz.Flags().BoolVar(&asJSON, "json", false, "Print the report as JSON")
	verify.AddCommand(authz)
	return verify
}

// verifyReport is what `verify authz` prints. Agreement, disagreement, conservative and not-comparable are kept
// apart so a reviewer can see what was and was not checked.
type verifyReport struct {
	ScanID   string `json:"scan_id"`
	Compared int    `json:"compared"`
	Agree    int    `json:"agree"`
	// LocalAllowed, LocalDenied and LocalUnknown say what Cloudrift answered across the compared probes, so an
	// agreement made only of "no" answers is visible as such.
	LocalAllowed  int                      `json:"local_allowed"`
	LocalDenied   int                      `json:"local_denied"`
	LocalUnknown  int                      `json:"local_unknown"`
	FalseAllows   []string                 `json:"false_allows"`
	BadDenies     []string                 `json:"bad_denies"`
	Conservative  []string                 `json:"conservative"`
	NotComparable []blastradius.SimSkipped `json:"not_comparable"`
	Errors        []string                 `json:"errors"`
	Result        string                   `json:"result"`
	Note          string                   `json:"note"`
}

func runVerifyAuthz(ctx context.Context, api collectors.SimulatorAPI, scanID string, assets []models.AssetNode, rels []models.Relationship, maxProbes int, asJSON bool, out io.Writer) (bool, error) {
	probes, skipped := blastradius.SimulatorProbes(scanID, assets, rels, maxProbes)
	var agreement []collectors.AgreementProbe
	for _, p := range probes {
		agreement = append(agreement, collectors.AgreementProbe{PrincipalARN: p.PrincipalARN, Action: p.Action, ResourceARN: p.ResourceARN, Context: p.Context, Decision: p.Decision})
	}
	r := collectors.CompareWithSimulator(ctx, api, agreement)
	var allowed, denied, unknown int
	for _, p := range agreement {
		switch p.Decision.Status {
		case "VALIDATED_ALLOWED":
			allowed++
		case "VALIDATED_DENIED":
			denied++
		default:
			unknown++
		}
	}
	rep := verifyReport{ScanID: scanID, Compared: r.Compared, Agree: r.Agree, LocalAllowed: allowed, LocalDenied: denied, LocalUnknown: unknown, FalseAllows: nz(r.FalseAllows), BadDenies: nz(r.BadDenies),
		Conservative: nz(r.Conservative), NotComparable: skipped, Errors: nz(r.Errors),
		Note: "The simulator evaluates identity policies and permissions boundaries only. It does not evaluate resource policies, trust policies, SCPs or RCPs."}
	if rep.NotComparable == nil {
		rep.NotComparable = []blastradius.SimSkipped{}
	}
	failed := len(r.FalseAllows) > 0 || len(r.BadDenies) > 0
	switch {
	case failed:
		rep.Result = "CONFIRMED_DISAGREEMENT"
	case r.Compared == 0:
		rep.Result = "INCOMPARABLE"
	default:
		rep.Result = "AGREEMENT"
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return failed, enc.Encode(rep)
	}
	fmt.Fprintf(out, "Result: %s (scan %s)\n", rep.Result, scanID)
	fmt.Fprintf(out, "Cloudrift answered: %d allowed, %d denied, %d unknown\n", rep.LocalAllowed, rep.LocalDenied, rep.LocalUnknown)
	fmt.Fprintf(out, "Compared %d: %d agree, %d false allows, %d bad denies, %d conservative (local unknown where the simulator allows), %d not comparable, %d errors\n",
		rep.Compared, rep.Agree, len(rep.FalseAllows), len(rep.BadDenies), len(rep.Conservative), len(rep.NotComparable), len(rep.Errors))
	for _, s := range rep.FalseAllows {
		fmt.Fprintf(out, "  FALSE ALLOW   %s\n", s)
	}
	for _, s := range rep.BadDenies {
		fmt.Fprintf(out, "  BAD DENY      %s\n", s)
	}
	for _, s := range rep.Errors {
		fmt.Fprintf(out, "  ERROR         %s\n", s)
	}
	fmt.Fprintln(out, rep.Note)
	return failed, nil
}

func nz(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
