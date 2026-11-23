package validators

import (
	"context"
	"net"
	"strings"
	"time"
)

// IsEC2Address reports whether an IPv4 address belongs to the EC2 public range, judged by its reverse DNS name
// (ec2-203-0-113-9.compute-1.amazonaws.com). Other AWS services and other providers report false, so a record
// pointing at them is never called released.
func IsEC2Address(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return false
	}
	return anyEC2Name(names)
}

func anyEC2Name(names []string) bool {
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if strings.HasPrefix(n, "ec2-") && strings.HasSuffix(n, ".amazonaws.com") {
			return true
		}
	}
	return false
}
