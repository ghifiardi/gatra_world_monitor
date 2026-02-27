/**
 * Security Check API — proxies privacy-preserving security checks.
 *
 * Supported actions:
 *   ?action=pwned-password&prefix=ABCDE     — HIBP Pwned Passwords (k-anonymity)
 *   ?action=dns-spf&domain=example.com       — SPF record check via Cloudflare DoH
 *   ?action=dns-dmarc&domain=example.com     — DMARC record check via Cloudflare DoH
 *   ?action=dns-mx&domain=example.com        — MX record check via Cloudflare DoH
 *
 * Privacy guarantees:
 *   - Pwned Passwords uses k-anonymity (only first 5 chars of SHA-1 hash)
 *   - DNS queries check public records only
 *   - No PII is logged or stored server-side
 */
import { getCorsHeaders } from './_cors.js';

export const config = { runtime: 'edge' };

// Validate SHA-1 prefix: exactly 5 hex characters
const HEX5_RE = /^[0-9A-Fa-f]{5}$/;

// Validate domain: basic sanity check
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;

async function fetchWithTimeout(url, options, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function handlePwnedPassword(prefix, corsHeaders) {
  if (!HEX5_RE.test(prefix)) {
    return new Response(JSON.stringify({ error: 'Invalid prefix: must be 5 hex characters' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  const resp = await fetchWithTimeout(
    `https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`,
    { headers: { 'User-Agent': 'WorldMonitor-SecurityCheck/1.0' } },
  );

  const text = await resp.text();

  // Parse into JSON for easier client consumption
  const entries = text.trim().split('\n').map(line => {
    const [suffix, count] = line.split(':');
    return { suffix: suffix.trim(), count: parseInt(count.trim(), 10) };
  });

  return new Response(JSON.stringify({ prefix: prefix.toUpperCase(), entries }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300',
      ...corsHeaders,
    },
  });
}

async function handleDnsCheck(domain, recordType, corsHeaders) {
  if (!DOMAIN_RE.test(domain)) {
    return new Response(JSON.stringify({ error: 'Invalid domain' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }

  // DMARC records live at _dmarc.domain
  const queryDomain = recordType === 'dmarc' ? `_dmarc.${domain}` : domain;
  const dnsType = recordType === 'mx' ? 'MX' : 'TXT';

  const resp = await fetchWithTimeout(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(queryDomain)}&type=${dnsType}`,
    {
      headers: {
        'Accept': 'application/dns-json',
        'User-Agent': 'WorldMonitor-SecurityCheck/1.0',
      },
    },
  );

  const data = await resp.json();

  // Filter for relevant records
  let records = data.Answer || [];
  if (recordType === 'spf') {
    records = records.filter(r => {
      const txt = (r.data || '').replace(/^"|"$/g, '');
      return txt.startsWith('v=spf1');
    });
  } else if (recordType === 'dmarc') {
    records = records.filter(r => {
      const txt = (r.data || '').replace(/^"|"$/g, '');
      return txt.startsWith('v=DMARC1');
    });
  }

  return new Response(JSON.stringify({
    domain,
    recordType,
    found: records.length > 0,
    records: records.map(r => ({
      data: (r.data || '').replace(/^"|"$/g, ''),
      ttl: r.TTL,
    })),
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
      ...corsHeaders,
    },
  });
}

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const url = new URL(req.url);
  const action = url.searchParams.get('action');

  try {
    switch (action) {
      case 'pwned-password': {
        const prefix = url.searchParams.get('prefix') || '';
        return await handlePwnedPassword(prefix, corsHeaders);
      }
      case 'dns-spf': {
        const domain = url.searchParams.get('domain') || '';
        return await handleDnsCheck(domain, 'spf', corsHeaders);
      }
      case 'dns-dmarc': {
        const domain = url.searchParams.get('domain') || '';
        return await handleDnsCheck(domain, 'dmarc', corsHeaders);
      }
      case 'dns-mx': {
        const domain = url.searchParams.get('domain') || '';
        return await handleDnsCheck(domain, 'mx', corsHeaders);
      }
      default:
        return new Response(JSON.stringify({
          error: 'Unknown action',
          available: ['pwned-password', 'dns-spf', 'dns-dmarc', 'dns-mx'],
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    return new Response(JSON.stringify({
      error: isTimeout ? 'Check timed out' : 'Check failed',
      details: err.message,
    }), {
      status: isTimeout ? 504 : 502,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
}
