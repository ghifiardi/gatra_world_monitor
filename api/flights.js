/**
 * OpenSky Network Proxy — Vercel Serverless Function (Node.js)
 *
 * Proxies live aircraft state vectors from OpenSky for the Gulf/CENTCOM region.
 * Uses native Node.js https module for maximum compatibility.
 *
 * GET /api/flights?lamin=13&lamax=43&lomin=27&lomax=57
 */

import https from 'https';

const OPENSKY_HOST = 'opensky-network.org';
const OPENSKY_PATH = '/api/states/all';
const FETCH_TIMEOUT = 25000;

// In-memory cache
let cache = { data: null, timestamp: 0, key: '' };
const CACHE_TTL = 30_000;

function fetchOpenSky(params) {
  return new Promise((resolve, reject) => {
    const qs = new URLSearchParams(params).toString();
    const options = {
      hostname: OPENSKY_HOST,
      path: `${OPENSKY_PATH}?${qs}`,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'WorldMonitor/2.5',
      },
      timeout: FETCH_TIMEOUT,
    };

    // Add auth if configured
    const clientId = process.env.OPENSKY_CLIENT_ID;
    const clientSecret = process.env.OPENSKY_CLIENT_SECRET;
    if (clientId && clientSecret) {
      options.headers['Authorization'] = 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    }

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, body });
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('OpenSky timeout'));
    });

    req.end();
  });
}

function getCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

export default async function handler(req, res) {
  const origin = req.headers.origin || req.headers.referer || '*';
  const cors = getCorsHeaders(origin);
  Object.entries(cors).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const lamin = parseFloat(req.query.lamin);
  const lamax = parseFloat(req.query.lamax);
  const lomin = parseFloat(req.query.lomin);
  const lomax = parseFloat(req.query.lomax);

  if ([lamin, lamax, lomin, lomax].some(isNaN)) {
    return res.status(400).json({ error: 'Missing or invalid bounding box params' });
  }

  if (lamax - lamin > 60 || lomax - lomin > 60) {
    return res.status(400).json({ error: 'Bounding box too large (max 60° span)' });
  }

  // Check cache
  const cacheKey = `${lamin},${lamax},${lomin},${lomax}`;
  if (cache.data && cache.key === cacheKey && Date.now() - cache.timestamp < CACHE_TTL) {
    res.setHeader('Cache-Control', 'public, max-age=30, s-maxage=30, stale-while-revalidate=15');
    res.setHeader('X-Cache', 'HIT');
    res.setHeader('Content-Type', 'application/json');
    return res.status(200).send(cache.data);
  }

  try {
    const result = await fetchOpenSky({
      lamin: String(lamin),
      lamax: String(lamax),
      lomin: String(lomin),
      lomax: String(lomax),
    });

    if (result.status === 429) {
      res.setHeader('Retry-After', '60');
      return res.status(429).json({ error: 'OpenSky rate limited', retryAfter: 60 });
    }

    if (result.status < 200 || result.status >= 300) {
      console.error('[flights] OpenSky returned', result.status);
      return res.status(502).json({ error: 'OpenSky upstream error', status: result.status });
    }

    // Update cache
    cache = { data: result.body, timestamp: Date.now(), key: cacheKey };

    res.setHeader('Cache-Control', 'public, max-age=30, s-maxage=30, stale-while-revalidate=15');
    res.setHeader('X-Cache', 'MISS');
    res.setHeader('Content-Type', 'application/json');
    return res.status(200).send(result.body);
  } catch (error) {
    const isTimeout = error.message?.includes('timeout');
    console.error('[flights] Error:', error.message);
    return res.status(isTimeout ? 504 : 502).json({
      error: isTimeout ? 'OpenSky timeout' : 'Failed to fetch flight data',
      details: error.message,
    });
  }
}

export const config = {
  maxDuration: 30,
  // Deploy to European region — OpenSky (Swiss) blocks US cloud IPs
  regions: ['fra1'],
};
