import { useEffect, useState } from 'react';

// Tracks document.visibilityState so React Query polling can pause on hidden
// tabs. Query intervals keep firing for the lifetime of the QueryClient cache
// (~5 min by default) even after a component unmounts, which adds up to
// hundreds of wasted requests over a normal admin session — pausing on hidden
// tabs reclaims that traffic without losing freshness when the user returns.
export function usePageVisibility(): boolean {
  const [visible, setVisible] = useState(() =>
    typeof document === 'undefined' ? true : !document.hidden
  );

  useEffect(() => {
    if (typeof document === 'undefined') return;
    const onChange = () => setVisible(!document.hidden);
    document.addEventListener('visibilitychange', onChange);
    return () => document.removeEventListener('visibilitychange', onChange);
  }, []);

  return visible;
}
