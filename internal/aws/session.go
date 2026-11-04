package aws

import (
	"context"
	"fmt"
	"sync"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type SessionManager struct {
	baseConfig awsv2.Config
	roleName   string

	mu    sync.RWMutex
	cache map[string]awsv2.Config
}

func NewSessionManager(ctx context.Context, profile, roleName string) (*SessionManager, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(profile), awsconfig.WithDefaultRegion("us-east-1"))
	if err != nil {
		return nil, err
	}
	return NewSessionManagerFromConfig(cfg, roleName), nil
}

func NewSessionManagerFromConfig(cfg awsv2.Config, roleName string) *SessionManager {
	return &SessionManager{
		baseConfig: cfg,
		roleName:   roleName,
		cache:      map[string]awsv2.Config{},
	}
}

func (m *SessionManager) AssumeAccount(ctx context.Context, accountID string) (awsv2.Config, error) {
	// No-assume mode: an empty role name means "use the base credentials directly"
	// instead of assuming a per-account audit role. This supports single-account scans
	// where the caller already holds the needed read permissions, so no CloudriftAuditRole
	// (or any cross-account role) needs to be deployed.
	if m.roleName == "" {
		return m.baseConfig, nil
	}

	m.mu.RLock()
	if cfg, ok := m.cache[accountID]; ok {
		m.mu.RUnlock()
		return cfg, nil
	}
	m.mu.RUnlock()

	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, m.roleName)
	creds := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(m.baseConfig), roleARN)
	cfg := m.baseConfig.Copy()
	cfg.Credentials = awsv2.NewCredentialsCache(creds)

	m.mu.Lock()
	m.cache[accountID] = cfg
	m.mu.Unlock()
	return cfg, nil
}
