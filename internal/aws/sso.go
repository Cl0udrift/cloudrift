package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	smithy "github.com/aws/smithy-go"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// validProfileRe restricts profile names passed to exec.Command to safe characters only.
var validProfileRe = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,128}$`)

// IsSSOExpiredError returns true when err indicates an AWS SSO session has expired
// or a cached token is missing. Covers both LoadDefaultConfig failures and STS
// ExpiredTokenException responses.
func IsSSOExpiredError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if apiErr.ErrorCode() == "ExpiredTokenException" {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no cached sso token") ||
		(strings.Contains(msg, "sso") && strings.Contains(msg, "expired")) ||
		strings.Contains(msg, "token is expired") ||
		strings.Contains(msg, "failed to refresh cached credentials")
}

// SSOLoginCommand returns the shell command the user should run to refresh their
// SSO session for the given profile ("" means the default profile).
func SSOLoginCommand(profile string) string {
	if profile == "" {
		return "aws sso login"
	}
	return fmt.Sprintf("aws sso login --profile %s", profile)
}

// CheckCredentials loads AWS config for the given profile and verifies it with
// a quick STS GetCallerIdentity call. Returns nil when credentials are valid.
func CheckCredentials(ctx context.Context, profile string) error {
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithDefaultRegion("us-east-1")}
	if profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return err
	}
	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

// TriggerSSOLogin fires `aws sso login [--profile profile]` as a background
// process so the browser opens immediately on the user's machine. The caller
// should poll CheckCredentials to know when authentication is complete.
//
// Returns (awsCLIFound, error). When awsCLIFound is false the aws CLI is not
// in PATH; the caller should show SSOLoginCommand for manual execution.
func TriggerSSOLogin(profile string) (bool, error) {
	awsPath, err := exec.LookPath("aws")
	if err != nil {
		return false, nil
	}
	if profile != "" && !validProfileRe.MatchString(profile) {
		return true, fmt.Errorf("invalid profile name %q", profile)
	}
	args := []string{"sso", "login"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	// #nosec G204 -- awsPath is from exec.LookPath; profile validated above.
	cmd := exec.Command(awsPath, args...)
	if err := cmd.Start(); err != nil {
		return true, fmt.Errorf("start aws sso login: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return true, nil
}

// WaitSSOLogin runs `aws sso login [--profile profile]` and blocks until the
// process exits. Suitable for interactive CLI use where stdin/stdout are a
// real terminal.
//
// Returns (awsCLIFound, error). When awsCLIFound is false the aws CLI is not
// in PATH.
func WaitSSOLogin(ctx context.Context, profile string) (bool, error) {
	awsPath, err := exec.LookPath("aws")
	if err != nil {
		return false, nil
	}
	if profile != "" && !validProfileRe.MatchString(profile) {
		return true, fmt.Errorf("invalid profile name %q", profile)
	}
	args := []string{"sso", "login"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	// #nosec G204 -- awsPath is from exec.LookPath; profile validated above.
	cmd := exec.CommandContext(ctx, awsPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("aws sso login: %w", err)
	}
	return true, nil
}
