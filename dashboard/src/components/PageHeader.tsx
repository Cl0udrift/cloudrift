interface PageHeaderProps {
  title: string;
  /** One short line. */
  description: string;
  /** Longer definitions, endpoints or caveats. Kept behind a disclosure so pages stay uncluttered. */
  details?: string;
}

export function PageHeader({ title, description, details }: PageHeaderProps) {
  return (
    <div className="mb-4">
      <h2 className="cr-page-title">{title}</h2>
      <p className="cr-body mt-1 max-w-3xl text-slate-600 dark:text-slate-400">{description}</p>
      {details ? (
        <details className="mt-1 max-w-3xl">
          <summary className="hs-focus-ring w-fit cursor-pointer rounded text-xs text-cyan-800 dark:text-cyan-300">About this page</summary>
          <p className="cr-helper mt-1">{details}</p>
        </details>
      ) : null}
    </div>
  );
}
