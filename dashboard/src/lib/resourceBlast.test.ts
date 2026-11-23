import { describe, expect, it } from "vitest";
import type { InventoryDetail, WhoCanResponse } from "../api/types";
import { describeResource } from "./resourceBlast";

const detail = (over: Partial<InventoryDetail> = {}, type = "dns_record"): InventoryDetail =>
  ({
    scan_id: "s", resource: { id: "r", arn: "arn:aws:route53:::hostedzone/Z/api.legacy.corp", resource_type: type, resource_type_name: "x", name: "api.legacy.corp", finding_count: 0, relationship_count: 0, identity_associated: false } as InventoryDetail["resource"],
    findings: [], relationships: [], identity_links: [], facts: [], evidence: {}, evidence_note: "", ...over
  }) as InventoryDetail;

describe("describeResource", () => {
  it("states takeover risk with what would be received, and what the record points at", () => {
    const a = describeResource(
      detail({ findings: [{ id: "f", title: "Dangling CNAME", severity: "high", module: "orphaned_edge" }], relationships: [{ rel_type: "POINTS_TO", direction: "outgoing", other_id: "arn:aws:cloudfront::1:distribution/E1", other_type: "cloudfront_dist", semantic: "configuration" }] }),
      {}
    );
    expect(a.takeover).toBe(true);
    expect(a.lines.join(" ")).toMatch(/points at the CloudFront distribution E1/);
    expect(a.lines.join(" ")).toMatch(/Takeover risk: Dangling CNAME. Whoever claims it would receive what is sent to api.legacy.corp/);
    expect(a.lines[a.lines.length - 1]).toBe("No owner tag.");
  });

  it("says plainly when nobody can use a bucket", () => {
    const empty = { callers: [] } as unknown as WhoCanResponse;
    const a = describeResource(detail({}, "s3_bucket"), { "s3:GetObject": empty, "s3:PutObject": empty, "s3:DeleteObject": empty });
    expect(a.lines[0]).toBe("No user or role in this scan can read objects in it, write objects to it, delete objects from it.");
  });

  it("counts who can use a bucket, separates administrators, and lists what points at it", () => {
    const caller = (name: string, admin: boolean) => ({ arn: name, name, kind: "user", account_id: "1", status: "VALIDATED_ALLOWED", reason: "", admin }) as WhoCanResponse["callers"][number];
    const who = { "s3:GetObject": { callers: [caller("alice", false), caller("root-ish", true)] }, "s3:DeleteObject": { callers: [caller("root-ish", true)] } } as unknown as Record<string, WhoCanResponse>;
    const a = describeResource(detail({ relationships: [{ rel_type: "POINTS_TO", direction: "incoming", other_id: "arn:aws:route53:::hostedzone/Z/a.example.com", other_type: "dns_record", semantic: "configuration" }] }, "s3_bucket"), who);
    const text = a.lines.join(" ");
    expect(text).toMatch(/2 identities can read objects in it, 1 identity can delete objects from it/);
    expect(text).toMatch(/Administrators among them: root-ish/);
    expect(text).toMatch(/specific grant, not as administrators: alice/);
    expect(text).toMatch(/1 DNS name points at it: a.example.com/);
  });
});
