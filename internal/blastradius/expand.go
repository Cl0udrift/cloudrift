package blastradius

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// cypherExpandBlastRadius walks bounded undirected hops through [V1TraversalRels].
// Logical ids: Asset uses arn; AwsAccount uses "account:" + account_id (matches ensureMinimalNode).
const cypherExpandBlastRadius = `
MATCH (start:Asset {arn: $arn, scan_id: $scan_id})
MATCH p = (start)-[rels*1..%d]-(m)
WHERE all(rel IN rels WHERE type(rel) IN $allowed AND rel.scan_id = $scan_id)
  AND all(n IN nodes(p) WHERE n:AwsAccount OR (n:Asset AND n.scan_id = $scan_id))
  AND none(n IN nodes(p)[1..-1] WHERE n:AwsAccount)
  AND (m:Asset OR m:AwsAccount)
UNWIND rels AS rel
WITH rel, startNode(rel) AS sn, endNode(rel) AS en
WITH rel, sn, en,
  CASE
    WHEN sn:Asset THEN sn.arn
    WHEN sn:AwsAccount THEN 'account:' + sn.account_id
    ELSE null
  END AS s,
  CASE
    WHEN en:Asset THEN en.arn
    WHEN en:AwsAccount THEN 'account:' + en.account_id
    ELSE null
  END AS e
WHERE s IS NOT NULL AND e IS NOT NULL
RETURN DISTINCT s AS src, e AS dst, type(rel) AS rel_type, rel.properties_json AS properties_json
LIMIT $edge_limit
`

// cypherExpandAttackPath walks directed outbound hops. Callers choose the allowlist:
// identity exposure passes trust configuration and unevaluated policy candidates; attack path passes validated transitions only.
// Relationship scan_id keeps a shared AwsAccount from bridging into another scan.
const cypherExpandAttackPath = `
MATCH (start:Asset {arn: $arn, scan_id: $scan_id})
MATCH p = (start)-[rels*1..%d]->(m)
WHERE all(rel IN rels WHERE type(rel) IN $allowed AND rel.scan_id = $scan_id)
  AND all(n IN nodes(p) WHERE n:AwsAccount OR (n:Asset AND n.scan_id = $scan_id))
  AND none(n IN nodes(p)[1..-1] WHERE n:AwsAccount)
  AND (m:Asset OR m:AwsAccount)
UNWIND rels AS rel
WITH rel, startNode(rel) AS sn, endNode(rel) AS en
WITH rel, sn, en,
  CASE
    WHEN sn:Asset THEN sn.arn
    WHEN sn:AwsAccount THEN 'account:' + sn.account_id
    ELSE null
  END AS s,
  CASE
    WHEN en:Asset THEN en.arn
    WHEN en:AwsAccount THEN 'account:' + en.account_id
    ELSE null
  END AS e
WHERE s IS NOT NULL AND e IS NOT NULL
RETURN DISTINCT s AS src, e AS dst, type(rel) AS rel_type, rel.properties_json AS properties_json
LIMIT $edge_limit
`

const cypherExpandOneHop = `
MATCH (n)
WHERE (
  ($is_account = true AND n:AwsAccount AND ('account:' + n.account_id) = $node_id)
  OR
  ($is_account = false AND n:Asset AND n.arn = $node_id AND n.scan_id = $scan_id)
)
MATCH (n)-[rel]-(m)
WHERE type(rel) IN $allowed
  AND rel.scan_id = $scan_id
  AND (m:Asset OR m:AwsAccount)
  AND (
    (m:Asset AND m.scan_id = $scan_id)
    OR m:AwsAccount
  )
WITH rel, startNode(rel) AS sn, endNode(rel) AS en
WITH rel, sn, en,
  CASE
    WHEN sn:Asset THEN sn.arn
    WHEN sn:AwsAccount THEN 'account:' + sn.account_id
    ELSE null
  END AS s,
  CASE
    WHEN en:Asset THEN en.arn
    WHEN en:AwsAccount THEN 'account:' + en.account_id
    ELSE null
  END AS e
WHERE s IS NOT NULL AND e IS NOT NULL
RETURN DISTINCT s AS src, e AS dst, type(rel) AS rel_type, rel.properties_json AS properties_json
LIMIT $edge_limit
`

const (
	oneHopMaxNeighbors = 8
	oneHopRawEdgeCap   = 24
)

// expandFromAsset walks a bounded undirected pattern from one Asset in the given scan.
func expandFromAsset(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	database string,
	arn, scanID string,
	maxHops int,
	mode BlastMode,
) (*workingGraph, error) {
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > V1MaxHops {
		maxHops = V1MaxHops
	}
	lim := V1ExplorerEdgeCap
	if mode == ModeAttackPath {
		lim = 60
	}
	allowed := traversalRels(mode)
	if mode == ModeAttackPath && len(allowed) == 0 {
		// No stored relationship is a validated attacker transition. Return the
		// starting asset only so the API can say so without inventing a path.
		g := newWorkingGraph()
		g.ensureMinimalNode(arn)
		return g, nil
	}
	queryTemplate := cypherExpandBlastRadius
	if mode == ModeAttackPath || mode == ModeIdentityExposure {
		queryTemplate = cypherExpandAttackPath
	}
	q := fmt.Sprintf(queryTemplate, maxHops)
	recs, err := readList(ctx, driver, database, q, map[string]any{
		"arn":        arn,
		"scan_id":    scanID,
		"allowed":    allowed,
		"edge_limit": lim,
	})
	if err != nil {
		return nil, err
	}
	g := newWorkingGraph()
	var triples []PathTriple
	for _, rec := range recs {
		if rec == nil {
			continue
		}
		src, ok1 := rec.Get("src")
		dst, ok2 := rec.Get("dst")
		rt, ok3 := rec.Get("rel_type")
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		s, _ := src.(string)
		d, _ := dst.(string)
		t, _ := rt.(string)
		if s == "" || d == "" || t == "" {
			continue
		}
		triples = append(triples, PathTriple{Src: s, Dst: d, Type: t, Props: relationshipProps(rec)})
	}
	if mode == ModeAttackPath {
		triples = prioritizeAttackTriples(triples, lim)
	}
	g.addTriples(triples)
	if err := hydrateAssets(ctx, driver, database, g, scanID); err != nil {
		return nil, err
	}
	// Focal resource should carry metadata if present
	g.ensureMinimalNode(arn)
	return g, nil
}

func prioritizeAttackTriples(in []PathTriple, edgeCap int) []PathTriple {
	type scored struct {
		t PathTriple
		w int
	}
	if len(in) == 0 {
		return in
	}
	out := make([]scored, 0, len(in))
	for _, t := range in {
		w := 1
		switch t.Type {
		case "TRUSTS":
			w = 8
			srcAcct := accountForNode(nil, t.Src)
			dstAcct := accountForNode(nil, t.Dst)
			if ext := strings.TrimSpace(stringProp(t.Props, "external_account_id")); ext != "" && srcAcct != "" && srcAcct != ext {
				dstAcct = ext
			}
			if srcAcct != "" && dstAcct != "" && srcAcct != dstAcct {
				w += 3
			}
		case "POINTS_TO", "FRONTS":
			w = 4
		case "USES_CERT":
			w = 2
		case "OWNED_BY":
			w = 1
		}
		out = append(out, scored{t: t, w: w})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].w != out[j].w {
			return out[i].w > out[j].w
		}
		if out[i].t.Src != out[j].t.Src {
			return out[i].t.Src < out[j].t.Src
		}
		if out[i].t.Dst != out[j].t.Dst {
			return out[i].t.Dst < out[j].t.Dst
		}
		return out[i].t.Type < out[j].t.Type
	})
	if edgeCap <= 0 || len(out) <= edgeCap {
		res := make([]PathTriple, 0, len(out))
		for _, s := range out {
			res = append(res, s.t)
		}
		return res
	}
	res := make([]PathTriple, 0, edgeCap)
	for i := 0; i < edgeCap; i++ {
		res = append(res, out[i].t)
	}
	return res
}

func expandOneHopFromNode(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	database string,
	nodeID string,
	scanID string,
	mode BlastMode,
) (*workingGraph, []PathTriple, error) {
	allowed := traversalRels(mode)
	if len(allowed) == 0 {
		return newWorkingGraph(), nil, nil
	}
	isAccount := strings.HasPrefix(nodeID, "account:")
	recs, err := readList(ctx, driver, database, cypherExpandOneHop, map[string]any{
		"node_id":    nodeID,
		"scan_id":    scanID,
		"allowed":    allowed,
		"is_account": isAccount,
		"edge_limit": oneHopRawEdgeCap,
	})
	if err != nil {
		return nil, nil, err
	}
	triples := make([]PathTriple, 0, len(recs))
	for _, rec := range recs {
		if rec == nil {
			continue
		}
		src, ok1 := rec.Get("src")
		dst, ok2 := rec.Get("dst")
		rt, ok3 := rec.Get("rel_type")
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		s, _ := src.(string)
		d, _ := dst.(string)
		t, _ := rt.(string)
		if s == "" || d == "" || t == "" {
			continue
		}
		triples = append(triples, PathTriple{Src: s, Dst: d, Type: t, Props: relationshipProps(rec)})
	}
	triples = prioritizeOneHopTriples(nodeID, triples, mode, oneHopMaxNeighbors)
	g := newWorkingGraph()
	g.addTriples(triples)
	if err := hydrateAssets(ctx, driver, database, g, scanID); err != nil {
		return nil, nil, err
	}
	return g, triples, nil
}

func prioritizeOneHopTriples(focusNodeID string, in []PathTriple, mode BlastMode, maxNeighbors int) []PathTriple {
	type scored struct {
		t PathTriple
		w int
	}
	if len(in) == 0 || maxNeighbors <= 0 {
		return nil
	}
	scoredTriples := make([]scored, 0, len(in))
	for _, t := range in {
		if t.Src != focusNodeID && t.Dst != focusNodeID {
			continue
		}
		neighbor := t.Dst
		if t.Dst == focusNodeID {
			neighbor = t.Src
		}
		if mode == ModeAttackPath && !attackTriple(t) {
			continue
		}
		if mode == ModeIdentityExposure && !identityTriple(t) {
			continue
		}
		w := 1 + expansionSemanticWeight(t.Type)
		if mode == ModeIdentityExposure && t.Type == "TRUSTS" {
			w += 2
		}
		if strings.HasPrefix(neighbor, "account:") {
			w += 2
		}
		srcA := accountForNode(nil, t.Src)
		dstA := accountForNode(nil, t.Dst)
		if ext := strings.TrimSpace(stringProp(t.Props, "external_account_id")); ext != "" && srcA != "" && srcA != ext {
			dstA = ext
		}
		if srcA != "" && dstA != "" && srcA != dstA {
			w += 2
		}
		// Keep low-signal bookkeeping edges only when they are the only available context.
		if t.Type == "OWNED_BY" && mode == ModeAttackPath {
			w -= 2
		}
		scoredTriples = append(scoredTriples, scored{t: t, w: w})
	}
	sort.Slice(scoredTriples, func(i, j int) bool {
		if scoredTriples[i].w != scoredTriples[j].w {
			return scoredTriples[i].w > scoredTriples[j].w
		}
		if scoredTriples[i].t.Src != scoredTriples[j].t.Src {
			return scoredTriples[i].t.Src < scoredTriples[j].t.Src
		}
		if scoredTriples[i].t.Dst != scoredTriples[j].t.Dst {
			return scoredTriples[i].t.Dst < scoredTriples[j].t.Dst
		}
		return scoredTriples[i].t.Type < scoredTriples[j].t.Type
	})

	out := make([]PathTriple, 0, maxNeighbors)
	seenNeighbors := map[string]struct{}{}
	for _, s := range scoredTriples {
		if len(out) >= maxNeighbors {
			break
		}
		neighbor := s.t.Dst
		if s.t.Dst == focusNodeID {
			neighbor = s.t.Src
		}
		if _, ok := seenNeighbors[neighbor]; ok {
			continue
		}
		seenNeighbors[neighbor] = struct{}{}
		out = append(out, s.t)
	}
	return out
}

func attackTriple(t PathTriple) bool {
	sem, ok := RelationshipSemanticsFor(t.Type)
	return ok && sem.AttackTraversable
}

func identityTriple(t PathTriple) bool {
	sem, ok := RelationshipSemanticsFor(t.Type)
	return ok && sem.IdentityTraversable
}

func expansionSemanticWeight(relType string) int {
	switch relType {
	case "TRUSTS":
		return 10
	case "POINTS_TO", "FRONTS":
		return 6
	case "USES_CERT":
		return 3
	case "OWNED_BY":
		return 1
	default:
		return 1
	}
}

const cypherHydrateAssets = `
MATCH (a:Asset {scan_id: $scan_id})
WHERE a.arn IN $arns
RETURN a.arn AS arn, a.account_id AS account_id, a.asset_type AS asset_type, a.name AS name, a.region AS region,
       a.resolution_status AS resolution_status, a.ownership_status AS ownership_status,
       a.discovered_in_account_id AS discovered_in_account_id, a.owning_account_id AS owning_account_id,
       a.properties_json AS properties_json
`

func hydrateAssets(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	database string,
	g *workingGraph,
	scanID string,
) error {
	var arns []any
	for id, n := range g.Nodes {
		if n.NType == "asset" {
			arns = append(arns, id)
		}
	}
	if len(arns) == 0 {
		return nil
	}
	recs, err := readList(ctx, driver, database, cypherHydrateAssets, map[string]any{
		"arns":    arns,
		"scan_id": scanID,
	})
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec == nil {
			continue
		}
		arn, _ := rec.Get("arn")
		arnStr, _ := arn.(string)
		if arnStr == "" {
			continue
		}
		acc, _ := rec.Get("account_id")
		at, _ := rec.Get("asset_type")
		nm, _ := rec.Get("name")
		rg, _ := rec.Get("region")
		props := map[string]any{
			"arn":        arnStr,
			"account_id": acc,
			"asset_type": at,
			"name":       nm,
			"region":     rg,
			"scan_id":    scanID,
		}
		copyStringProp(props, "resolution_status", rec)
		copyStringProp(props, "ownership_status", rec)
		copyStringProp(props, "discovered_in_account_id", rec)
		copyStringProp(props, "owning_account_id", rec)
		if raw, ok := rec.Get("properties_json"); ok {
			if s, _ := raw.(string); s != "" {
				props["properties_json"] = s
				if parsed := parsePropsJSON(s); len(parsed) > 0 {
					props["properties"] = parsed
				}
			}
		}
		g.setAssetNode(arnStr, props)
	}
	return nil
}

// Merge another graph (e.g. second root) into g.
func mergeWorking(dst, src *workingGraph) {
	if src == nil {
		return
	}
	for id, n := range src.Nodes {
		if id == "" {
			continue
		}
		if _, ok := dst.Nodes[id]; !ok {
			dst.addNode(n.ID, n.Label, n.NType, n.Props)
		}
	}
	for id, e := range src.Edges {
		if _, ok := dst.Edges[id]; !ok {
			dst.Edges[id] = e
			if e.Type == "TRUSTS" {
				dst.HasTrusts = true
			}
		}
	}
}

// Ingest finding focus + AFFECTS edge if the projection exists in Neo4j.
const cypherFindingContext = `
MATCH (f:Finding {id: $fid})
WHERE f.scan_id = $scan_id
OPTIONAL MATCH (f)-[:AFFECTS]->(a:Asset {scan_id: $scan_id})
RETURN f.id AS fid, f.title AS title, f.severity AS severity, f.affected_arn AS aff, a.arn AS affected_asset
LIMIT 1
`

type findingContextRow struct {
	FindingID     string
	Title         string
	Severity      string
	Affected      string
	AffectedAsset *string
}

func loadFindingContext(
	ctx context.Context,
	driver neo4j.DriverWithContext,
	database, scanID, findingID string,
) (*findingContextRow, error) {
	rec, err := readSingle(ctx, driver, database, cypherFindingContext, map[string]any{
		"fid":     findingID,
		"scan_id": scanID,
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	fid, _ := rec.Get("fid")
	title, _ := rec.Get("title")
	sev, _ := rec.Get("severity")
	aff, _ := rec.Get("aff")
	aa, _ := rec.Get("affected_asset")
	row := &findingContextRow{
		FindingID: fmt.Sprint(fid),
		Title:     fmt.Sprint(title),
		Severity:  fmt.Sprint(sev),
		Affected:  fmt.Sprint(aff),
	}
	if s, ok := aa.(string); ok && s != "" {
		row.AffectedAsset = &s
	} else {
		af := row.Affected
		if af != "" {
			row.AffectedAsset = &af
		}
	}
	return row, nil
}

func relationshipProps(rec *neo4j.Record) map[string]any {
	if rec == nil {
		return nil
	}
	raw, ok := rec.Get("properties_json")
	if !ok || raw == nil {
		return nil
	}
	s, _ := raw.(string)
	return parsePropsJSON(s)
}

func parsePropsJSON(s string) map[string]any {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "{}" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil || len(m) == 0 {
		return nil
	}
	return m
}

func copyStringProp(dst map[string]any, key string, rec *neo4j.Record) {
	raw, ok := rec.Get(key)
	if !ok || raw == nil {
		return
	}
	s, _ := raw.(string)
	if strings.TrimSpace(s) != "" {
		dst[key] = strings.TrimSpace(s)
	}
}
