/**
 * CISA KEV (Known Exploited Vulnerabilities) Proxy — Vercel Edge Function
 *
 * Fetches the CISA KEV catalog and returns the most recent entries.
 * Free, no API key required. Updated by CISA ~daily.
 *
 * GET /api/cisa-kev
 * Returns: { vulnerabilities: [...], catalogVersion, count, totalKnown, source }
 */

import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const FETCH_TIMEOUT = 12_000;
const CACHE_TTL = 5 * 60_000; // 5 minutes (KEV updates ~daily, no need for aggressive polling)
const MAX_ENTRIES = 50; // Return the 50 most recent entries

let cache = { data: null, timestamp: 0 };

async function fetchWithTimeout(url, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json', 'User-Agent': 'WorldMonitor/1.0' },
    });
  } finally {
    clearTimeout(timeout);
  }
}

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // Check cache
  if (cache.data && Date.now() - cache.timestamp < CACHE_TTL) {
    return new Response(cache.data, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300, s-maxage=300, stale-while-revalidate=120',
        'X-Cache': 'HIT',
        ...corsHeaders,
      },
    });
  }

  try {
    const resp = await fetchWithTimeout(KEV_URL);
    if (!resp.ok) throw new Error(`CISA returned ${resp.status}`);

    const raw = await resp.json();
    const allVulns = raw.vulnerabilities || [];

    // Sort by dateAdded descending (most recent first)
    allVulns.sort((a, b) => (b.dateAdded || '').localeCompare(a.dateAdded || ''));

    // Take the most recent entries
    const recent = allVulns.slice(0, MAX_ENTRIES);

    const payload = JSON.stringify({
      vulnerabilities: recent,
      catalogVersion: raw.catalogVersion || '',
      count: recent.length,
      totalKnown: allVulns.length,
      source: 'cisa_kev',
    });

    cache = { data: payload, timestamp: Date.now() };

    return new Response(payload, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=300, s-maxage=300, stale-while-revalidate=120',
        'X-Cache': 'MISS',
        ...corsHeaders,
      },
    });
  } catch (error) {
    console.error('[cisa-kev] Error:', error.message);
    return new Response(JSON.stringify({
      error: 'Failed to fetch CISA KEV data',
      details: error.message,
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}
