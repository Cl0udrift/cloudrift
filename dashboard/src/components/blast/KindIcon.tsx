/** A small glyph for the kind of thing a box stands for, so a route reads without labels. */
const PATHS: Record<string, JSX.Element> = {
  user: <><circle cx="12" cy="8" r="3.5" /><path d="M5 20c0-4 3.2-6 7-6s7 2 7 6" /></>,
  group: <><circle cx="9" cy="9" r="3" /><circle cx="16" cy="10" r="2.5" /><path d="M3 19c0-3.3 2.7-5 6-5s6 1.7 6 5M15 15c3 0 6 1.4 6 4" /></>,
  role: <><path d="M12 3l8 3v6c0 4.5-3.2 7.5-8 9-4.8-1.5-8-4.5-8-9V6z" /><path d="M9 12l2 2 4-4" /></>,
  bucket: <><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v11c0 1.7 3.1 3 7 3s7-1.3 7-3V6" /></>,
  database: <><ellipse cx="12" cy="6" rx="7" ry="3" /><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v5c0 1.7 3.1 3 7 3s7-1.3 7-3v-5" /></>,
  key: <><circle cx="8" cy="12" r="3.5" /><path d="M11.5 12H21M18 12v3M15 12v2.5" /></>,
  cert: <><circle cx="12" cy="9" r="5" /><path d="M9 13.5L8 21l4-2 4 2-1-7.5M10 9l1.5 1.5L14.5 7" /></>,
  dns: <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.5 2.4 3.8 5.3 3.8 8.5s-1.3 6.1-3.8 8.5c-2.5-2.4-3.8-5.3-3.8-8.5S9.5 5.9 12 3.5z" /></>,
  cdn: <><path d="M7 18h10a4 4 0 000-8 5.5 5.5 0 00-10.6-1A4.5 4.5 0 007 18z" /></>,
  compute: <><rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3" /></>,
  action: <><path d="M13 3L5 13h6l-1 8 8-10h-6z" /></>,
  box: <><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" /><path d="M4 7.5L12 12l8-4.5M12 12v9" /></>
};

const MAP: Record<string, string> = {
  user: "user", iam_user: "user", group: "group", iam_group: "group", role: "role", iam_role: "role",
  s3_bucket: "bucket", bucket: "bucket", rds_instance: "database", secret: "key", kms_key: "key", key: "key",
  acm_cert: "cert", dns_record: "dns", cloudfront_dist: "cdn", ec2_instance: "compute", lambda_function: "compute", load_balancer: "cdn"
};

export function KindIcon({ kind, className = "" }: { kind: string; className?: string }) {
  const k = PATHS[MAP[kind] ?? kind] ? MAP[kind] ?? kind : "box";
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={`shrink-0 ${className}`}>
      {PATHS[k]}
    </svg>
  );
}
