/**
 * IOC Lookup API — Vercel Edge Function
 *
 * Proxies IOC queries to VirusTotal (requires VIRUSTOTAL_API_KEY env var).
 * Called by the client-side SOC Chat IOC lookup service.
 *
 * GET /api/ioc-lookup?q=<ioc>&type=<ip|hash|domain|url>
 *
 * VirusTotal free tier: 4 req/min, 500 req/day.
 * Results are cached in-memory for 5 minutes.
 */

import { getCorsHeaders, isDisallowedOrigin } from './_cors.js';
export const config = { runtime: 'edge' };

const VT_BASE = 'https://www.virustotal.com/api/v3';
const FETCH_TIMEOUT = 8000;

// ── In-memory cache ────────────────────────────────────────────
const cache = new Map();
const CACHE_TTL = 5 * 60_000;

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { cache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  cache.set(key, { data, ts: Date.now() });
  if (cache.size > 200) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
}

// ── Timed fetch ────────────────────────────────────────────────
function timedFetch(url, opts) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
  return fetch(url, { ...opts, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

// ── VirusTotal lookups by type ─────────────────────────────────

async function vtLookupIP(ip, apiKey) {
  const res = await timedFetch(`${VT_BASE}/ip_addresses/${encodeURIComponent(ip)}`, {
    headers: { 'x-apikey': apiKey },
  });
  if (res.status === 429) return { source: 'VirusTotal', rateLimited: true };
  if (res.status === 404) return { source: 'VirusTotal', verdict: 'not_found' };
  if (!res.ok) return null;

  const data = await res.json();
  const attr = data.data?.attributes;
  if (!attr) return null;

  const stats = attr.last_analysis_stats || {};
  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
  return {
    source: 'VirusTotal',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: total,
    verdict: stats.malicious > 5 ? 'malicious' : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean',
    confidence: total > 0 ? Math.round((stats.malicious / total) * 100) : 0,
    asOwner: attr.as_owner || null,
    country: attr.country || null,
    reputation: attr.reputation ?? null,
    network: attr.network || null,
    link: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
  };
}

async function vtLookupHash(hash, apiKey) {
  const res = await timedFetch(`${VT_BASE}/files/${encodeURIComponent(hash)}`, {
    headers: { 'x-apikey': apiKey },
  });
  if (res.status === 429) return { source: 'VirusTotal', rateLimited: true };
  if (res.status === 404) return { source: 'VirusTotal', verdict: 'not_found' };
  if (!res.ok) return null;

  const data = await res.json();
  const attr = data.data?.attributes;
  if (!attr) return null;

  const stats = attr.last_analysis_stats || {};
  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
  return {
    source: 'VirusTotal',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: total,
    verdict: stats.malicious > 5 ? 'malicious' : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean',
    confidence: total > 0 ? Math.round((stats.malicious / total) * 100) : 0,
    fileName: attr.meaningful_name || attr.names?.[0] || null,
    fileType: attr.type_description || null,
    fileSize: attr.size || null,
    tags: (attr.tags || []).slice(0, 5),
    popularThreatName: attr.popular_threat_classification?.suggested_threat_label || null,
    link: `https://www.virustotal.com/gui/file/${encodeURIComponent(hash)}`,
  };
}

async function vtLookupDomain(domain, apiKey) {
  const res = await timedFetch(`${VT_BASE}/domains/${encodeURIComponent(domain)}`, {
    headers: { 'x-apikey': apiKey },
  });
  if (res.status === 429) return { source: 'VirusTotal', rateLimited: true };
  if (res.status === 404) return { source: 'VirusTotal', verdict: 'not_found' };
  if (!res.ok) return null;

  const data = await res.json();
  const attr = data.data?.attributes;
  if (!attr) return null;

  const stats = attr.last_analysis_stats || {};
  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
  return {
    source: 'VirusTotal',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: total,
    verdict: stats.malicious > 5 ? 'malicious' : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean',
    confidence: total > 0 ? Math.round((stats.malicious / total) * 100) : 0,
    registrar: attr.registrar || null,
    creationDate: attr.creation_date ? new Date(attr.creation_date * 1000).toISOString().slice(0, 10) : null,
    categories: attr.categories ? Object.values(attr.categories).slice(0, 3) : [],
    link: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`,
  };
}

async function vtLookupURL(url, apiKey) {
  // VT URL lookup uses a URL identifier (base64-encoded URL without padding)
  const urlId = btoa(url).replace(/=+$/, '');
  const res = await timedFetch(`${VT_BASE}/urls/${urlId}`, {
    headers: { 'x-apikey': apiKey },
  });
  if (res.status === 429) return { source: 'VirusTotal', rateLimited: true };
  if (res.status === 404) return { source: 'VirusTotal', verdict: 'not_found' };
  if (!res.ok) return null;

  const data = await res.json();
  const attr = data.data?.attributes;
  if (!attr) return null;

  const stats = attr.last_analysis_stats || {};
  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
  return {
    source: 'VirusTotal',
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    totalEngines: total,
    verdict: stats.malicious > 5 ? 'malicious' : (stats.malicious > 0 || stats.suspicious > 2) ? 'suspicious' : 'clean',
    confidence: total > 0 ? Math.round((stats.malicious / total) * 100) : 0,
    link: `https://www.virustotal.com/gui/url/${urlId}`,
  };
}

// ── Main handler ───────────────────────────────────────────────

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req);

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (isDisallowedOrigin(req)) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const url = new URL(req.url);
  const query = url.searchParams.get('q')?.trim();
  const type = url.searchParams.get('type')?.trim();

  if (!query) {
    return new Response(JSON.stringify({ error: 'Missing "q" parameter' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  if (!vtKey) {
    return new Response(JSON.stringify({ error: 'VirusTotal API key not configured', source: 'VirusTotal' }), {
      status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // Check cache
  const cacheKey = `${type}:${query.toLowerCase()}`;
  const cached = getCached(cacheKey);
  if (cached) {
    return new Response(JSON.stringify({ ...cached, cached: true }), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' },
    });
  }

  try {
    let result = null;
    switch (type) {
      case 'ip':
        result = await vtLookupIP(query, vtKey);
        break;
      case 'hash':
        result = await vtLookupHash(query, vtKey);
        break;
      case 'domain':
        result = await vtLookupDomain(query, vtKey);
        break;
      case 'url':
        result = await vtLookupURL(query, vtKey);
        break;
      default:
        return new Response(JSON.stringify({ error: `Unknown type "${type}". Use: ip, hash, domain, url` }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }

    if (!result) {
      return new Response(JSON.stringify({ source: 'VirusTotal', verdict: 'error', details: 'API returned unexpected response' }), {
        status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (result.rateLimited) {
      return new Response(JSON.stringify({ source: 'VirusTotal', rateLimited: true, note: 'Rate limited — 4 req/min free tier' }), {
        status: 429, headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '60' },
      });
    }

    // Cache successful results
    setCache(cacheKey, result);

    return new Response(JSON.stringify(result), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ source: 'VirusTotal', verdict: 'error', details: err?.message || 'Unknown error' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}
