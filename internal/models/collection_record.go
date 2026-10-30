package models

// CollectionRecord reports whether supported collectors were stored and whether
// every stored supported collector finished successfully.
// recorded is false when the scan has no collection_status rows for supported collectors.
// complete is true only when those rows exist and every status is succeeded,
// including ec2, lambda, ecs, and eks.
func CollectionRecord(assets []AssetNode) (recorded bool, complete bool) {
	seenRegional := map[string]struct{}{}
	bad := false
	for _, asset := range assets {
		if asset.AssetType != "collection_status" && asset.AssetType != "workload_collection_status" {
			continue
		}
		collector, _ := asset.Properties["collector"].(string)
		status, _ := asset.Properties["status"].(string)
		if !supportedCollector(collector) {
			continue
		}
		recorded = true
		if status != "succeeded" {
			bad = true
		}
		if regionalCollector(collector) {
			seenRegional[collector] = struct{}{}
		}
	}
	if !recorded {
		return false, false
	}
	for _, name := range []string{"ec2", "lambda", "ecs", "eks"} {
		if _, ok := seenRegional[name]; !ok {
			bad = true
		}
	}
	return true, !bad
}

func supportedCollector(name string) bool {
	switch name {
	case "ec2", "lambda", "ecs", "eks", "iam", "s3", "route53", "cloudfront", "region_discovery":
		return true
	default:
		return false
	}
}

func regionalCollector(name string) bool {
	switch name {
	case "ec2", "lambda", "ecs", "eks":
		return true
	default:
		return false
	}
}
