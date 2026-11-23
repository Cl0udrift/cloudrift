package scorers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Takeover beyond DNS: a resource that names an S3 bucket or an AWS endpoint that no longer exists. Anyone can
// register a free bucket name, and Elastic Beanstalk names, so whatever still points at them hands that party
// the traffic, the logs or the data.

// BucketProbe returns "missing", "exists" or "unknown" for a bucket name.
type BucketProbe func(ctx context.Context, name string) string

// TargetProbe reports whether a name's AWS target was deleted, and whether the name can be registered again.
type TargetProbe func(ctx context.Context, name, target, service string) (fingerprint string, claimable, ok bool)

var (
	bucketRefPatterns = []*regexp.Regexp{regexp.MustCompile(`arn:aws[a-z-]*:s3:::([^/\s"',]+)`), regexp.MustCompile(`s3://([^/\s"',]+)`)}
	bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
	// Asset types that name buckets as their own identity or hold no references of their own.
	skipRefTypes = map[models.AssetType]bool{models.AssetS3Bucket: true, models.AssetS3Object: true, "collection_status": true, "workload_collection_status": true, models.AssetIAMAuthorizationDecision: true, models.AssetDNSRecord: true, models.AssetCloudFrontDist: true, models.AssetIAMRole: true}
)

const maxBucketProbes = 150

type bucketRef struct {
	Kind, ARN, Name, Account string
}

// bucketNamesIn finds exact bucket names (no wildcard or template) anywhere inside a property value.
func bucketNamesIn(v any, out map[string]bool) {
	switch x := v.(type) {
	case string:
		for _, re := range bucketRefPatterns {
			for _, m := range re.FindAllStringSubmatch(x, -1) {
				if bucketNamePattern.MatchString(m[1]) {
					out[m[1]] = true
				}
			}
		}
	case []string:
		for _, s := range x {
			bucketNamesIn(s, out)
		}
	case []any:
		for _, s := range x {
			bucketNamesIn(s, out)
		}
	case map[string]any:
		for _, s := range x {
			bucketNamesIn(s, out)
		}
	}
}

// ScoreResourceTakeover finds buckets that are referenced but do not exist, and CloudFront origins whose AWS
// endpoint was deleted. A nil bucket probe (HTTP probing off) skips the bucket check rather than guessing.
func ScoreResourceTakeover(ctx context.Context, assets []models.AssetNode, bucket BucketProbe, target TargetProbe) []models.Finding {
	var findings []models.Finding
	findings = append(findings, scoreDeletedOrigins(ctx, assets, target)...)
	if bucket != nil {
		findings = append(findings, scoreUnownedBuckets(ctx, assets, bucket)...)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

func scoreUnownedBuckets(ctx context.Context, assets []models.AssetNode, probe BucketProbe) []models.Finding {
	owned := map[string]bool{}
	for _, a := range assets {
		if a.AssetType == models.AssetS3Bucket {
			owned[a.Name] = true
		}
	}
	refs := map[string][]bucketRef{}
	add := func(name string, r bucketRef) {
		if !owned[name] {
			refs[name] = append(refs[name], r)
		}
	}
	for _, a := range assets {
		switch {
		case a.AssetType == models.AssetCloudFrontDist:
			for _, o := range stringList(a.Properties["origins"]) {
				if b := originBucket(o); b != "" && bucketNamePattern.MatchString(b) {
					add(b, bucketRef{"cloudfront_origin", a.ARN, a.Name, a.AccountID})
				}
			}
		case skipRefTypes[a.AssetType]:
		default:
			found := map[string]bool{}
			bucketNamesIn(a.Properties, found)
			for b := range found {
				add(b, bucketRef{string(a.AssetType), a.ARN, a.Name, a.AccountID})
			}
		}
	}
	names := make([]string, 0, len(refs))
	for n := range refs {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxBucketProbes {
		names = names[:maxBucketProbes]
	}
	state := make(map[string]string, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, n := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s := probe(ctx, n)
			mu.Lock()
			state[n] = s
			mu.Unlock()
		}(n)
	}
	wg.Wait()

	var out []models.Finding
	for _, n := range names {
		if state[n] != "missing" {
			continue
		}
		out = append(out, bucketFinding(n, refs[n]))
	}
	return out
}

// originBucket is bucketFromOrigin for scorers: the bucket an S3 origin domain names.
var originBucketRe = regexp.MustCompile(`^(.+?)\.s3[.-]`)

func originBucket(origin string) string {
	if m := originBucketRe.FindStringSubmatch(strings.ToLower(origin)); m != nil {
		return m[1]
	}
	return ""
}

func bucketFinding(name string, refs []bucketRef) models.Finding {
	sort.Slice(refs, func(i, j int) bool { return refs[i].ARN < refs[j].ARN })
	sev, viaEdge := models.SeverityHigh, false
	var shown []map[string]string
	for i, r := range refs {
		if r.Kind == "cloudfront_origin" {
			sev, viaEdge = models.SeverityCritical, true
		}
		if i < 10 {
			shown = append(shown, map[string]string{"kind": r.Kind, "arn": r.ARN, "name": r.Name, "account_id": r.Account})
		}
	}
	impact := fmt.Sprintf("%d resource(s) use the S3 bucket %q, but no account holds it. Anyone can create a bucket with that name and receive whatever those resources write to it or serve from it.", len(refs), name)
	if viaEdge {
		impact = fmt.Sprintf("A CloudFront distribution serves content from the S3 bucket %q, which does not exist. Anyone who creates a bucket with that name controls what your distribution, and any domain on it, serves.", name)
	}
	h := sha256.Sum256([]byte(string(models.ModuleOrphanedEdge) + "|s3_reference|" + name))
	f := models.Finding{
		ID: hex.EncodeToString(h[:])[:12], Title: fmt.Sprintf("S3 bucket %s is referenced but does not exist (anyone can create it)", name),
		Severity: sev, Module: models.ModuleOrphanedEdge, Claimability: models.ClaimReclaimable,
		AffectedARN: "arn:aws:s3:::" + name, AccountID: refs[0].Account, Hostname: name, Impact: impact,
		Recommendation: "Create the bucket in your own account with public access blocked, or remove the reference.",
		RemediationCmd: fmt.Sprintf("aws s3api create-bucket --bucket %s --region us-east-1\naws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", name, name),
		Evidence:       map[string]any{"fingerprint": "s3_bucket_unowned_referenced", "target_service": "s3", "bucket_name": name, "reference_count": len(refs), "references": shown, "claimable": true},
	}
	annotateRemediation(&f, "s3_bucket_unowned_referenced", false, "")
	return f
}

func scoreDeletedOrigins(ctx context.Context, assets []models.AssetNode, probe TargetProbe) []models.Finding {
	if probe == nil {
		return nil
	}
	var out []models.Finding
	for _, a := range assets {
		if a.AssetType != models.AssetCloudFrontDist {
			continue
		}
		for _, o := range stringList(a.Properties["origins"]) {
			if originBucket(o) != "" {
				continue
			}
			service := collectors.ClassifyTargetService(o)
			fp, claimable, ok := probe(ctx, a.Name, o, service)
			if !ok {
				continue
			}
			sev, c := models.SeverityHigh, models.ClaimDangling
			if claimable {
				c = models.ClaimReclaimable
			}
			h := sha256.Sum256([]byte(string(models.ModuleOrphanedEdge) + "|origin|" + a.ARN + "|" + o))
			f := models.Finding{
				ID: hex.EncodeToString(h[:])[:12], Title: fmt.Sprintf("CloudFront distribution %s has an origin that no longer exists (%s)", a.Name, o),
				Severity: sev, Module: models.ModuleOrphanedEdge, Claimability: c, AffectedARN: a.ARN, AccountID: a.AccountID, Hostname: a.Name,
				Impact:         "The distribution's origin name no longer resolves because its AWS resource was deleted. If the name can be registered again, whoever does controls what the distribution serves.",
				Recommendation: "Remove the origin from the distribution, or recreate the resource in your own account.",
				RemediationCmd: fmt.Sprintf("aws cloudfront get-distribution-config --id %s > dist.json  # remove origin %s, then update-distribution with the ETag", distributionID(a.ARN), o),
				Evidence:       map[string]any{"fingerprint": fp, "target_service": service, "origin": o, "claimable": claimable},
			}
			annotateRemediation(&f, fp, false, "")
			out = append(out, f)
		}
	}
	return out
}

func distributionID(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func stringList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, s := range x {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
