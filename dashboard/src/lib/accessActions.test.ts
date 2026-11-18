import { describe, expect, it } from "vitest";
import { actionFits, actionsFor, ACTION_TARGET } from "./accessActions";

describe("accessActions", () => {
  it("offers only the actions that fit the target", () => {
    expect(actionsFor("user")).not.toContain("sts:AssumeRole");
    expect(actionsFor("role")).toContain("sts:AssumeRole");
    expect(actionsFor("group")).toEqual(["iam:AttachGroupPolicy", "iam:PutGroupPolicy", "iam:AddUserToGroup"]);
    expect(actionsFor("")).toHaveLength(Object.keys(ACTION_TARGET).length);
  });
  it("flags a mismatched pair and lets an unknown action through", () => {
    expect(actionFits("sts:AssumeRole", "user")).toBe(false);
    expect(actionFits("iam:PutUserPolicy", "user")).toBe(true);
    expect(actionFits("s3:GetObject", "user")).toBe(true);
  });
});
