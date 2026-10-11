package blastradius

import (
	"fmt"
	"sort"
	"strings"
)

// workingGraph holds de-duplicated nodes and edges for blast-radius v1.
type workingGraph struct {
	Nodes     map[string]rawNode
	Edges     map[string]rawEdge
	HasTrusts bool
}

type rawNode struct {
	ID    string
	Label string
	NType string
	Props map[string]any
}

type rawEdge struct {
	ID    string
	Src   string
	Tgt   string
	Type  string
	Props map[string]any
}

// PathTriple is a directed edge with logical source/target ids (ARNs or account:…).
// Props carries relationship evidence hydrated from Neo4j (source_kind, is_public, and so on).
type PathTriple struct {
	Src, Dst, Type string
	Props          map[string]any
}

func newWorkingGraph() *workingGraph {
	return &workingGraph{
		Nodes: make(map[string]rawNode),
		Edges: make(map[string]rawEdge),
	}
}

func (g *workingGraph) addNode(id, label, nType string, props map[string]any) {
	if id == "" {
		return
	}
	if _, ok := g.Nodes[id]; ok {
		return
	}
	if props == nil {
		props = map[string]any{}
	}
	g.Nodes[id] = rawNode{ID: id, Label: label, NType: nType, Props: props}
}

func (g *workingGraph) addEdge(src, tgt, relType string) {
	g.addEdgeWithProps(src, tgt, relType, nil)
}

func (g *workingGraph) addEdgeWithProps(src, tgt, relType string, props map[string]any) {
	if src == "" || tgt == "" || relType == "" {
		return
	}
	if relType == "TRUSTS" {
		g.HasTrusts = true
	}
	eid := edgeKey(src, relType, tgt)
	if existing, ok := g.Edges[eid]; ok {
		if existing.Props == nil && len(props) > 0 {
			existing.Props = props
			g.Edges[eid] = existing
		}
		return
	}
	g.Edges[eid] = rawEdge{ID: eid, Src: src, Tgt: tgt, Type: relType, Props: props}
}

func (g *workingGraph) setAssetNode(arn string, props map[string]any) {
	if arn == "" {
		return
	}
	if props == nil {
		props = map[string]any{}
	}
	g.Nodes[arn] = rawNode{ID: arn, Label: "Asset", NType: "asset", Props: props}
}

func edgeKey(a, t, b string) string { return a + "→" + t + "→" + b }

func (g *workingGraph) addTriples(triples []PathTriple) {
	for _, t := range triples {
		if t.Src == "" || t.Dst == "" {
			continue
		}
		g.ensureMinimalNode(t.Src)
		g.ensureMinimalNode(t.Dst)
		g.addEdgeWithProps(t.Src, t.Dst, t.Type, t.Props)
	}
}

// ensureMinimalNode creates a shell node so edge endpoints always exist in the explorer payload.
func (g *workingGraph) ensureMinimalNode(id string) {
	if id == "" {
		return
	}
	if _, ok := g.Nodes[id]; ok {
		return
	}
	if strings.HasPrefix(id, "account:") {
		acc := strings.TrimPrefix(id, "account:")
		g.addNode(id, "AwsAccount", "account", map[string]any{"account_id": acc})
		return
	}
	if strings.HasPrefix(id, "finding:") {
		fid := strings.TrimPrefix(id, "finding:")
		g.addNode(id, "Finding", "finding", map[string]any{"id": fid})
		return
	}
	g.addNode(id, "Asset", "asset", map[string]any{"arn": id})
}

// AddAssetNode registers an Asset for explorer labeling (if not present).
func (g *workingGraph) AddAssetNode(arn, accountID, assetType, name, region, scanID string) {
	props := map[string]any{
		"arn":        arn,
		"account_id": accountID,
		"asset_type": assetType,
		"name":       name,
		"region":     region,
		"scan_id":    scanID,
	}
	g.addNode(arn, "Asset", "asset", props)
}

// AddAccountNode adds AwsAccount.
func (g *workingGraph) AddAccountNode(accountID string) {
	id := "account:" + accountID
	props := map[string]any{"account_id": accountID}
	g.addNode(id, "AwsAccount", "account", props)
}

// AddFindingNode adds a Finding reference.
func (g *workingGraph) AddFindingNode(findingID, title, scanID, severity, affected string) {
	id := "finding:" + findingID
	props := map[string]any{
		"id":           findingID,
		"title":        title,
		"scan_id":      scanID,
		"severity":     severity,
		"affected_arn": affected,
	}
	g.addNode(id, "Finding", "finding", props)
}

// TopAccountIDs ranks accounts touched in the working graph.
func (g *workingGraph) topAccountIDs(n int) []string {
	seen := make(map[string]int)
	for id, node := range g.Nodes {
		if node.NType == "account" {
			acc := strings.TrimPrefix(id, "account:")
			seen[acc]++
		}
		_ = id
	}
	for id, node := range g.Nodes {
		if node.NType == "asset" {
			acc, _ := node.Props["account_id"].(string)
			acc = strings.TrimSpace(acc)
			if acc != "" {
				seen[acc] += 1
			}
		}
		_ = id
	}
	type kv struct {
		k string
		c int
	}
	var kvs []kv
	for a, c := range seen {
		kvs = append(kvs, kv{a, c})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].c != kvs[j].c {
			return kvs[i].c > kvs[j].c
		}
		return kvs[i].k < kvs[j].k
	})
	out := make([]string, 0, n)
	for i := 0; i < len(kvs) && len(out) < n; i++ {
		if kvs[i].k != "" {
			out = append(out, kvs[i].k)
		}
	}
	return out
}

// TopResourceTypes from asset_type on Asset nodes.
func (g *workingGraph) topAssetTypes(n int) []string {
	counts := make(map[string]int)
	for id, node := range g.Nodes {
		if node.NType != "asset" {
			_ = id
			continue
		}
		typ, _ := node.Props["asset_type"].(string)
		typ = strings.TrimSpace(typ)
		if typ == "" {
			typ = "unknown"
		}
		counts[typ]++
	}
	type kv struct {
		t string
		c int
	}
	var kvs []kv
	for t, c := range counts {
		kvs = append(kvs, kv{t, c})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].c != kvs[j].c {
			return kvs[i].c > kvs[j].c
		}
		return kvs[i].t < kvs[j].t
	})
	out := make([]string, 0, n)
	for i := 0; i < len(kvs) && len(out) < n; i++ {
		out = append(out, kvs[i].t)
	}
	return out
}

func (g *workingGraph) countReachableResources() int {
	c := 0
	for id, n := range g.Nodes {
		if n.NType == "asset" {
			// focus root is often asset: count others (optional)
			_ = id
			c++
		}
	}
	return c
}

func (g *workingGraph) countAccountsTouched() int {
	acc := make(map[string]struct{})
	for id, n := range g.Nodes {
		switch n.NType {
		case "account":
			acc[strings.TrimPrefix(id, "account:")] = struct{}{}
		case "asset":
			aid, _ := n.Props["account_id"].(string)
			aid = strings.TrimSpace(aid)
			if aid != "" {
				acc[aid] = struct{}{}
			}
		}
		_ = id
	}
	return len(acc)
}

func fmtUnavailableSummary(reason UnavailableReason) string {
	switch reason {
	case ReasonNeo4jDisabled, ReasonNeo4jConnectError:
		return "Graph-backed blast radius requires Neo4j and a prior scan export. Core findings and risk scores remain available; connect Neo4j to explore reachability in 3D."
	case ReasonNoGraphProjection:
		return "No matching graph nodes were found in Neo4j for this context (export may be missing or scan_id mismatch)."
	default:
		return "Blast-radius graph data is not available for this item."
	}
}

// Safe summary string builder.
func joinAccounts(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	if len(ids) <= 3 {
		return strings.Join(ids, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(ids[:3], ", "), len(ids)-3)
}
