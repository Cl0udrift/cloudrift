package ciem

import (
	"fmt"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

// ApplyBoundary narrows a capability summary by the principal's permissions boundary. A boundary only limits: a service
// the boundary does not allow is removed, and the level and scope are the narrower of the two. It does not apply a
// Deny inside the boundary. When a boundary is attached but its document was not read, nothing is narrowed and the
// note says the result may be wider than what is allowed.
func ApplyBoundary(caps []schema.RoleCapability, note string, principal models.AssetNode) ([]schema.RoleCapability, string) {
	status := strProp(principal, "permissions_boundary_status")
	if status == "" || status == "confirmed_absent" {
		return caps, note
	}
	doc := strProp(principal, "permissions_boundary_document")
	join := func(extra string) string {
		if note == "" {
			return extra
		}
		return note + " " + extra
	}
	name := strProp(principal, "permissions_boundary_arn")
	name = name[strings.LastIndex(name, "/")+1:]
	if status != "present" || strings.TrimSpace(doc) == "" {
		return caps, join("A permissions boundary is attached but its document was not read, so what is shown may be wider than what is allowed.")
	}
	parsed, err := models.NormalizeIdentityPolicy(principal.ARN+"#boundary", "boundary", principal.AccountID, doc)
	if err != nil {
		return caps, join("A permissions boundary is attached but could not be read, so what is shown may be wider than what is allowed.")
	}
	var stmts []scorers.RoleStatement
	for _, st := range parsed {
		stmts = append(stmts, scorers.RoleStatement{PolicyARN: "boundary", Effect: st.Effect, Actions: st.Action, Resources: st.Resource, NotAction: len(st.NotAction) > 0 || len(st.NotResource) > 0, Conditional: len(st.Condition) > 0})
	}
	bcaps, _ := CapabilitiesFromStatements(stmts, nil)
	bounds := map[string]schema.RoleCapability{}
	for _, b := range bcaps {
		bounds[b.Service] = b
	}
	all, hasAll := bounds["all services"]
	var out []schema.RoleCapability
	changed := 0
	for _, c := range caps {
		b, ok := bounds[c.Service]
		if !ok && hasAll {
			b, ok = all, true
		}
		if c.Service == "all services" && !hasAll {
			// An all-services grant is cut to the services the boundary names.
			for _, bc := range bcaps {
				out = append(out, narrow(schema.RoleCapability{Service: bc.Service, Level: c.Level, Scope: c.Scope, Policies: c.Policies, Actions: c.Actions, Conditional: c.Conditional}, bc))
			}
			changed++
			continue
		}
		if !ok {
			changed++
			continue
		}
		n := narrow(c, b)
		if n.Limited {
			changed++
		}
		out = append(out, n)
	}
	sortCaps(out)
	return out, join(fmt.Sprintf("Limited by the permissions boundary %s: %d row%s removed or narrowed. A Deny inside the boundary is not applied.", name, changed, map[bool]string{true: "", false: "s"}[changed == 1]))
}

// narrow returns c cut down to what boundary b allows.
func narrow(c, b schema.RoleCapability) schema.RoleCapability {
	out := c
	if levelRank(b.Level) < levelRank(c.Level) {
		out.Level, out.Limited = b.Level, true
	}
	if c.Scope == "all resources" && b.Scope != "all resources" {
		out.Scope, out.Limited = b.Scope, true
	}
	out.Conditional = c.Conditional || b.Conditional
	return out
}
