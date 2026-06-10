export const config = { runtime: 'edge' };

import { ConvexHttpClient } from 'convex/browser';
import { getCorsHeaders, isDisallowedOrigin } from './_cors.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 320;

const rateLimitMap = new Map();
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;

// Module-level Maps are per-instance and ephemeral on the edge runtime,
// so use Upstash Redis when configured; the in-memory map remains as a
// best-effort fallback.
async function isRateLimited(ip) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) {
    try {
      const key = `rl:register-interest:${ip}`;
      const res = await fetch(`${url}/pipeline`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify([
          ['INCR', key],
          ['EXPIRE', key, String(Math.ceil(RATE_WINDOW_MS / 1000)), 'NX'],
        ]),
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const results = await res.json();
        return Number(results?.[0]?.result || 0) > RATE_LIMIT;
      }
    } catch {
      // Redis unreachable — fall through to in-memory limiter
    }
  }
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimitMap.set(ip, { windowStart: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT;
}

export default async function handler(req) {
  if (isDisallowedOrigin(req)) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const cors = getCorsHeaders(req, 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (await isRateLimited(ip)) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const { email, source, appVersion } = body;
  if (!email || typeof email !== 'string' || email.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(email)) {
    return new Response(JSON.stringify({ error: 'Invalid email address' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const convexUrl = process.env.CONVEX_URL;
  if (!convexUrl) {
    return new Response(JSON.stringify({ error: 'Registration service unavailable' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  try {
    const client = new ConvexHttpClient(convexUrl);
    const result = await client.mutation('registerInterest:register', {
      email,
      source: source || 'unknown',
      appVersion: appVersion || 'unknown',
    });
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  } catch (err) {
    console.error('[register-interest] Convex error:', err);
    return new Response(JSON.stringify({ error: 'Registration failed' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }
}
