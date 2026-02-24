/**
 * Ransomware Tracker Service
 *
 * Fetches recent ransomware victim data from the ransomware.live public API.
 * Falls back to realistic mock data when the API is unreachable (CORS, network).
 *
 * Data sources:
 *   - https://api.ransomware.live/recentvictims  (recent victims)
 *   - https://api.ransomware.live/groups          (group profiles)
 *
 * Caches results for 15 minutes to avoid excessive API calls.
 */

import type { RansomwareVictim, RansomwareGroup, RansomwareStats } from '@/types';

// ── Cache ────────────────────────────────────────────────────────────

const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

let victimsCache: CacheEntry<RansomwareVictim[]> | null = null;
let groupsCache: CacheEntry<RansomwareGroup[]> | null = null;

function isFresh<T>(entry: CacheEntry<T> | null): entry is CacheEntry<T> {
  return entry !== null && Date.now() - entry.timestamp < CACHE_TTL_MS;
}

// ── API fetch helpers ────────────────────────────────────────────────

const VICTIMS_URL = 'https://api.ransomware.live/recentvictims';
const GROUPS_URL = 'https://api.ransomware.live/groups';

/** Parse ISO date or YYYY-MM-DD to Date, returns null on failure. */
function parseDate(raw: string | null | undefined): Date | null {
  if (!raw) return null;
  const d = new Date(raw);
  return isNaN(d.getTime()) ? null : d;
}

/** Try a direct fetch with a timeout. */
async function fetchWithTimeout(url: string, timeoutMs = 8000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    return resp;
  } finally {
    clearTimeout(timer);
  }
}

// ── API → typed converters ───────────────────────────────────────────

/* eslint-disable @typescript-eslint/no-explicit-any */
function parseVictim(raw: any, idx: number): RansomwareVictim {
  return {
    id: raw.id?.toString() ?? `rv-${idx}`,
    victimName: raw.post_title ?? raw.victim ?? raw.name ?? 'Unknown',
    group: raw.group_name ?? raw.group ?? 'Unknown',
    discoveredDate: parseDate(raw.discovered ?? raw.published ?? raw.date) ?? new Date(),
    country: raw.country ?? null,
    sector: raw.activity ?? raw.sector ?? null,
    website: raw.website ?? raw.post_url ?? null,
    description: raw.description ?? null,
  };
}

function parseGroup(raw: any): RansomwareGroup {
  return {
    name: raw.name ?? 'Unknown',
    description: raw.description ?? raw.profile ?? null,
    firstSeen: parseDate(raw.first_seen ?? raw.firstSeen),
    victimCount: typeof raw.locations?.length === 'number' ? raw.locations.length : 0,
    locations: Array.isArray(raw.locations) ? raw.locations.map((l: any) => l.slug ?? l.fqdn ?? String(l)) : [],
  };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ── Fetch with fallback ──────────────────────────────────────────────

async function fetchVictimsFromApi(): Promise<RansomwareVictim[] | null> {
  try {
    const resp = await fetchWithTimeout(VICTIMS_URL);
    if (!resp.ok) return null;
    const json = await resp.json();
    const raw = Array.isArray(json) ? json : [];
    // Filter to last 30 days
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const victims = raw
      .map((r: unknown, i: number) => parseVictim(r, i))
      .filter((v) => v.discoveredDate.getTime() >= cutoff);
    victims.sort((a, b) => b.discoveredDate.getTime() - a.discoveredDate.getTime());
    return victims;
  } catch {
    return null;
  }
}

async function fetchGroupsFromApi(): Promise<RansomwareGroup[] | null> {
  try {
    const resp = await fetchWithTimeout(GROUPS_URL);
    if (!resp.ok) return null;
    const json = await resp.json();
    const raw = Array.isArray(json) ? json : [];
    return raw.map((r: unknown) => parseGroup(r));
  } catch {
    return null;
  }
}

// ── Mock data ────────────────────────────────────────────────────────
// Realistic fallback when the API is unreachable (CORS, offline, etc.)

const MOCK_GROUPS_LIST = [
  'LockBit 3.0', 'BlackCat/ALPHV', 'Cl0p', 'Play', 'Royal',
  'Black Basta', '8Base', 'Akira', 'Medusa', 'BianLian',
  'NoEscape', 'Rhysida', 'Hunters International', 'Cactus', 'INC Ransom',
];

const MOCK_COUNTRIES = [
  'US', 'UK', 'DE', 'FR', 'CA', 'AU', 'IT', 'BR', 'JP', 'IN',
  'NL', 'ES', 'MX', 'KR', 'SE', 'CH', 'BE', 'PL', 'AT', 'SG',
];

const MOCK_SECTORS = [
  'Manufacturing', 'Healthcare', 'Technology', 'Education', 'Financial Services',
  'Government', 'Construction', 'Legal', 'Retail', 'Transportation',
  'Energy', 'Real Estate', 'Hospitality', 'Telecommunications', 'Media',
];

const MOCK_VICTIM_NAMES = [
  'Meridian Health Systems', 'Apex Manufacturing Corp', 'Titan Logistics Group',
  'Pinnacle Education Trust', 'Sterling Financial Holdings', 'Catalyst Technologies Inc',
  'Pacific Rim Exports', 'Nordic Steel Works', 'Harborview Medical Center',
  'Continental Law Partners', 'Summit Construction LLC', 'Greenfield Energy Solutions',
  'Atlas Retail Group', 'Bayshore Hospitality', 'Spectrum Telecom Services',
  'Keystone Pharmaceuticals', 'Falcon Defense Systems', 'Prairie Agricultural Co-op',
  'Oceanview Real Estate', 'Silverline Insurance', 'Metro Transit Authority',
  'Grandview University', 'Coastal Engineering Corp', 'Redwood Data Solutions',
  'Heritage Banking Group', 'Bridgeway Consulting', 'Whitfield Manufacturing',
  'Eastgate Medical Group', 'New Horizon Shipping', 'Clearwater Utilities',
  'Benchmark Analytics', 'Ironclad Security Systems', 'Vanguard Aerospace',
  'Compass Legal Services', 'Riverside School District', 'Trident Marine Inc',
  'Crestline Financial', 'Global Packaging Solutions', 'Monarch Insurance',
  'Quantum Research Labs', 'Polaris Defense Corp', 'Beacon Health Partners',
  'Starfield Technologies', 'Cobalt Mining Group', 'Vertex Engineering',
];

/** Simple deterministic PRNG (mulberry32). */
function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function generateMockVictims(): RansomwareVictim[] {
  // Seed from 15-min bucket so data appears stable
  const bucket = Math.floor(Date.now() / (15 * 60 * 1000));
  const rng = mulberry32(bucket);
  const now = Date.now();
  const count = 60 + Math.floor(rng() * 40); // 60-100 victims over 30 days
  const victims: RansomwareVictim[] = [];

  for (let i = 0; i < count; i++) {
    const groupIdx = Math.floor(rng() * MOCK_GROUPS_LIST.length);
    // Weight towards top groups: LockBit, ALPHV, Cl0p get more victims
    const weightedGroupIdx = rng() < 0.45
      ? Math.floor(rng() * 5)  // top 5 groups
      : groupIdx;

    const daysAgo = Math.floor(rng() * 30);
    const hoursAgo = Math.floor(rng() * 24);

    victims.push({
      id: `mock-rv-${bucket}-${i}`,
      victimName: MOCK_VICTIM_NAMES[Math.floor(rng() * MOCK_VICTIM_NAMES.length)] ?? 'Unknown Corp',
      group: MOCK_GROUPS_LIST[weightedGroupIdx] ?? 'LockBit 3.0',
      discoveredDate: new Date(now - daysAgo * 86_400_000 - hoursAgo * 3_600_000),
      country: MOCK_COUNTRIES[Math.floor(rng() * MOCK_COUNTRIES.length)] ?? null,
      sector: MOCK_SECTORS[Math.floor(rng() * MOCK_SECTORS.length)] ?? null,
      website: null,
      description: null,
    });
  }

  victims.sort((a, b) => b.discoveredDate.getTime() - a.discoveredDate.getTime());
  return victims;
}

function generateMockGroups(): RansomwareGroup[] {
  const bucket = Math.floor(Date.now() / (15 * 60 * 1000));
  const rng = mulberry32(bucket + 99);

  return MOCK_GROUPS_LIST.map((name) => ({
    name,
    description: `${name} ransomware operation`,
    firstSeen: new Date(Date.now() - Math.floor(rng() * 365 * 3 * 86_400_000)),
    victimCount: 20 + Math.floor(rng() * 400),
    locations: [],
  }));
}

// ── Public API ───────────────────────────────────────────────────────

export async function fetchRansomwareVictims(): Promise<RansomwareVictim[]> {
  if (isFresh(victimsCache)) return victimsCache.data;

  const apiData = await fetchVictimsFromApi();
  const data = apiData ?? generateMockVictims();

  victimsCache = { data, timestamp: Date.now() };

  if (!apiData) {
    console.warn('[RansomwareTracker] API unreachable, using mock data');
  }

  return data;
}

export async function fetchRansomwareGroups(): Promise<RansomwareGroup[]> {
  if (isFresh(groupsCache)) return groupsCache.data;

  const apiData = await fetchGroupsFromApi();
  const data = apiData ?? generateMockGroups();

  groupsCache = { data, timestamp: Date.now() };
  return data;
}

/** Compute summary stats from the victims list. */
export function computeRansomwareStats(victims: RansomwareVictim[]): RansomwareStats {
  const groupCounts = new Map<string, number>();
  const countryCounts = new Map<string, number>();
  const sectorCounts = new Map<string, number>();

  for (const v of victims) {
    groupCounts.set(v.group, (groupCounts.get(v.group) ?? 0) + 1);
    if (v.country) countryCounts.set(v.country, (countryCounts.get(v.country) ?? 0) + 1);
    if (v.sector) sectorCounts.set(v.sector, (sectorCounts.get(v.sector) ?? 0) + 1);
  }

  const sortedEntries = (m: Map<string, number>) =>
    [...m.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, count }));

  return {
    totalVictims30d: victims.length,
    topGroups: sortedEntries(groupCounts).slice(0, 10),
    topCountries: sortedEntries(countryCounts).slice(0, 10),
    topSectors: sortedEntries(sectorCounts).slice(0, 10),
  };
}

/** Fetch both victims and groups, compute stats. */
export async function fetchRansomwareData(): Promise<{
  victims: RansomwareVictim[];
  groups: RansomwareGroup[];
  stats: RansomwareStats;
}> {
  const [victims, groups] = await Promise.all([
    fetchRansomwareVictims(),
    fetchRansomwareGroups(),
  ]);
  const stats = computeRansomwareStats(victims);
  return { victims, groups, stats };
}
