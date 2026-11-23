package validators

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// BucketState asks S3 whether a bucket name is registered by anyone. "missing" means the name is free, so anyone
// can create the bucket; "exists" means some account holds it (access is irrelevant here); "unknown" is any
// other result. The request is anonymous and names only the bucket.
func BucketState(ctx context.Context, name string) string {
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Path-style on the global endpoint works for dotted names, which fail TLS in virtual-host style.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://s3.amazonaws.com/"+name, nil)
	if err != nil {
		return "unknown"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return bucketStateFrom(resp.StatusCode, string(body))
}

func bucketStateFrom(status int, body string) string {
	switch {
	case status == http.StatusNotFound && strings.Contains(body, "NoSuchBucket"):
		return "missing"
	case status == http.StatusOK, status == http.StatusForbidden, status == http.StatusMovedPermanently, status == http.StatusTemporaryRedirect, status == http.StatusBadRequest && strings.Contains(body, "AuthorizationHeaderMalformed"):
		return "exists"
	}
	return "unknown"
}

// CheckDeletedTarget reports whether a name that points at an AWS resource (an origin or record target) no longer
// resolves because that resource is gone. It returns the fingerprint and whether the name can be registered again.
func CheckDeletedTarget(ctx context.Context, name, target, service string) (fingerprint string, claimable, ok bool) {
	node := models.AssetNode{Name: name, Properties: map[string]any{"value": target, "target_service": service}}
	res, deleted := targetDeleted(ctx, node, net.DefaultResolver)
	return res.ErrorFingerprint, res.Claimable, deleted
}
