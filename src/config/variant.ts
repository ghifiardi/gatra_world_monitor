export const SITE_VARIANT: string = (() => {
  const envVariant = (import.meta.env.VITE_VARIANT || 'full').trim();
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('worldmonitor-variant');
    if (stored === 'tech' || stored === 'full' || stored === 'finance' || stored === 'cyber') return stored;
  }
  return envVariant;
})();
