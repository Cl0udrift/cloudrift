package validators

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// delegationProbe asks one name server whether it serves a zone. It returns "answered", "refused" (the server
// does not know the zone: SERVFAIL or REFUSED) or "timeout". It is a variable so tests can replace the network.
var delegationProbe = realDelegationProbe

func realDelegationProbe(ctx context.Context, zone, nsHost string) string {
	ips, err := net.DefaultResolver.LookupHost(ctx, nsHost)
	if err != nil || len(ips) == 0 {
		return "refused" // the name server's own name does not resolve, so it cannot serve anything
	}
	r := &net.Resolver{PreferGo: true, Dial: func(c context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(c, "udp", net.JoinHostPort(ips[0], "53"))
	}}
	_, err = r.LookupNS(ctx, zone)
	if err == nil {
		return "answered"
	}
	if dnsErr, ok := err.(*net.DNSError); ok {
		switch {
		case dnsErr.IsNotFound:
			return "answered" // the server is authoritative and says there is nothing at this name
		case dnsErr.IsTimeout:
			return "timeout"
		}
	}
	return "refused"
}

// validateDelegation checks an NS record below a zone apex: every name server it delegates to must serve the zone.
// A delegation where none does is lame; when the servers are Route 53's, anyone can create a hosted zone with that
// name and receive the traffic.
func validateDelegation(ctx context.Context, node models.AssetNode, _ DNSResolver) ValidationResult {
	var hosts []string
	switch v := node.Properties["values"].(type) {
	case []string:
		hosts = v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				hosts = append(hosts, s)
			}
		}
	}
	if len(hosts) == 0 {
		return ValidationResult{DNSStatus: "unknown"}
	}
	allRoute53, refused := true, 0
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if !strings.Contains(h, "awsdns-") {
			allRoute53 = false
		}
		switch delegationProbe(ctx, node.Name, h) {
		case "answered":
			return ValidationResult{DNSStatus: "resolved"}
		case "refused":
			refused++
		default:
			return ValidationResult{DNSStatus: "timeout"} // an unreachable server proves nothing
		}
	}
	if refused == len(hosts) {
		return ValidationResult{DNSStatus: "delegation_lame", ErrorFingerprint: "ns_delegation_lame", Claimable: allRoute53}
	}
	return ValidationResult{DNSStatus: "unknown"}
}
