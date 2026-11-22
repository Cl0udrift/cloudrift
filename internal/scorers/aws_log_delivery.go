package scorers

import "strings"

// awsELBLogAccounts are the AWS-owned Elastic Load Balancing accounts that write access logs
// to a customer bucket. Source: AWS docs, "Enable access logs for your Application Load
// Balancer" (legacy bucket policy). Regions launched after Aug 2022 use a service principal.
var awsELBLogAccounts = map[string]bool{
	"127311923021": true, "033677994240": true, "027434742980": true, "797873946194": true,
	"098369216593": true, "754344448648": true, "589379963580": true, "718504428378": true,
	"383597477331": true, "600734575887": true, "114774131450": true, "783225319266": true,
	"582318560864": true, "985666609251": true, "054676820928": true, "156460612806": true,
	"652711504416": true, "635631232127": true, "009996457667": true, "897822967062": true,
	"076674570225": true, "507241528517": true, "190560391635": true, "048591011584": true,
}

// isAWSLogDelivery is true only for an AWS ELB log account granted nothing but s3:PutObject,
// so a broader grant to the same account still gets the normal external-write finding.
func isAWSLogDelivery(account string, actions []string) bool {
	if !awsELBLogAccounts[account] || len(actions) == 0 {
		return false
	}
	for _, a := range actions {
		if !strings.EqualFold(a, "s3:putobject") {
			return false
		}
	}
	return true
}
