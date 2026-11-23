package blastradius

import (
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// ResourceTargetTypeFor is the kind of data resource an action is asked of: an S3 bucket for object access, a secret, a
// KMS key. It is empty for an action that is not a data action.
func ResourceTargetTypeFor(action string) models.AssetType {
	switch action {
	case iamauth.ActionGetObject, "s3:PutObject", "s3:DeleteObject":
		return models.AssetS3Bucket
	case "secretsmanager:GetSecretValue":
		return models.AssetSecret
	case "kms:Decrypt":
		return models.AssetKMSKey
	}
	return ""
}

// probeObjectKey names the one object a bucket question is evaluated against. The evaluator needs a concrete ARN.
const probeObjectKey = "cloudrift-probe-object"

// WhoCanOnResource evaluates a data action on a bucket, secret or key for every collected user and role. It applies the
// caller's own policies, boundary and SCPs together with the resource's own policy (bucket policy, secret policy, key
// policy) and, for a secret, the key that encrypts it. For a bucket the question is access to objects anywhere in it: the
// action is evaluated against one object at the top level, so access limited to a prefix (such as logs/*) is not listed.
func WhoCanOnResource(scanID, action string, target models.AssetNode, assets []models.AssetNode, rels []models.Relationship, when time.Time) (list []schema.RoleAssumer, unknownCallers []schema.UnknownCaller, evaluated int) {
	if when.IsZero() {
		when = time.Unix(0, 0).UTC()
	}
	buckets := assetsOfType(assets, models.AssetS3Bucket)
	keys := assetsOfType(assets, models.AssetKMSKey)
	cap := capOf(action)
	resource := target
	if target.AssetType == models.AssetS3Bucket {
		resource.ARN = "arn:aws:s3:::" + bucketName(target) + "/" + probeObjectKey
	}
	return whoCanLoop(scanID, action, target, assets, rels, func(caller models.AssetNode) iamauth.AuthorizationRequest {
		req := whoCanRequest(scanID, action, caller, resource, assets, rels, when, iamauth.PolicySlot{}, "this action does not use a resource policy", nil)
		switch cap.Evaluation {
		case iamauth.EvalS3Object:
			req.ResourcePolicy = bucketPolicySlot(resource, buckets)
			req.S3ObjectACL, req.S3BlockPublicAccess, req.S3KMSKeyPolicy = s3Constraints(resource, buckets, req.S3ObjectACL, req.S3BlockPublicAccess, req.S3KMSKeyPolicy)
		case iamauth.EvalSecret:
			req.ResourcePolicy = secretPolicySlot(target)
			req.SecretKMS = secretKMSEvidence(target, keys, assets, caller, iamauth.PolicySlot{})
		case iamauth.EvalKMSKey:
			req.ResourcePolicy = keyPolicySlot(target)
			req.KMSGrants = grantsOf(target)
		}
		return req
	})
}
