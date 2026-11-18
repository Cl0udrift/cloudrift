export type TargetKind = "role" | "user" | "group";

/** The kind of identity each action is performed on. The server enforces the same pairing. */
export const ACTION_TARGET: Record<string, TargetKind> = {
  "sts:AssumeRole": "role",
  "iam:PassRole": "role",
  "iam:AttachRolePolicy": "role",
  "iam:PutRolePolicy": "role",
  "iam:UpdateAssumeRolePolicy": "role",
  "iam:AttachUserPolicy": "user",
  "iam:PutUserPolicy": "user",
  "iam:CreateAccessKey": "user",
  "iam:CreateLoginProfile": "user",
  "iam:UpdateLoginProfile": "user",
  "iam:AttachGroupPolicy": "group",
  "iam:PutGroupPolicy": "group",
  "iam:AddUserToGroup": "group"
};

/** Actions that can be asked of a target of this kind. With no target chosen, every action is offered. */
export function actionsFor(kind: TargetKind | ""): string[] {
  const all = Object.keys(ACTION_TARGET);
  return kind ? all.filter((a) => ACTION_TARGET[a] === kind) : all;
}

export function actionFits(action: string, kind: TargetKind | ""): boolean {
  return !kind || ACTION_TARGET[action] === undefined || ACTION_TARGET[action] === kind;
}

/** Target kind from the label the picker uses ("role x", "user y", "group z"). */
export function kindOf(raw: string): TargetKind | "" {
  return raw === "role" || raw === "user" || raw === "group" ? raw : "";
}
