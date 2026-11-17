const TITLES: Record<number, string> = {
  403: 'Access denied',
  502: 'Bad gateway',
  503: 'Service unavailable',
  504: 'Gateway timeout',
};

/** A plain starting point for a custom page: inline style, no script (#335). */
export function errorPageTemplate(status: number): string {
  const title = TITLES[status] ?? 'Error';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${status} ${title}</title>
  <style>
    body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
           font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a; }
    main { text-align: center; padding: 2rem; }
    h1 { font-size: 4rem; margin: 0; }
    p { color: #475569; }
  </style>
</head>
<body>
  <main>
    <h1>${status}</h1>
    <p>${title}</p>
  </main>
</body>
</html>
`;
}
