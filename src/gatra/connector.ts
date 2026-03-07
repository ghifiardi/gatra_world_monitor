/**
 * GATRA SOC Connector — unified integration layer
 *
 * Data flow:
 *   1. Try /api/gatra-data  (real GATRA API — production predictions + activity logs)
 *   2. Fall back to mock data from @/services/gatra if the API is unavailable
 *
 * Consumers (panels, layers) always get the same GatraConnectorSnapshot shape
 * regardless of whether the data is live or mock.
 */

import {
  fetchGatraAlerts,
  fetchGatraAgentStatus,
  fetchGatraIncidentSummary,
  fetchGatraCRAActions,
  fetchGatraTAAAnalyses,
  fetchGatraCorrelations,
} from '@/services/gatra';

import type {
  GatraAlert,
  GatraAgentStatus,
  GatraIncidentSummary,
  GatraCRAAction,
  GatraTAAAnalysis,
  GatraCorrelation,
  GatraConnectorSnapshot,
} from '@/types';

import { getActiveAssetProfile } from '@/config/asset-profile';

// ── Connector state ─────────────────────────────────────────────────

let _snapshot: GatraConnectorSnapshot | null = null;
let _refreshing = false;
let _source: 'live' | 'mock' = 'mock';
const _listeners: Set<(snap: GatraConnectorSnapshot) => void> = new Set();

// ── GATRA API fetch ─────────────────────────────────────────────────

/** Attempt to load real GATRA data from the API route (BigQuery-backed).
 *  DISABLED: BigQuery endpoint is returning 500 errors and burning serverless quota.
 *  Re-enable once the BigQuery tables/permissions are fixed. */
async function fetchFromGatraAPI(): Promise<GatraConnectorSnapshot | null> {
  // Short-circuit: skip the API call entirely to stop wasting serverless invocations
  return null;
  try {
    const res = await fetch('/api/gatra-data', { signal: AbortSignal.timeout(30000) });
    if (!res.ok) return null;

    const data = await res.json() as {
      alerts: Array<Omit<GatraAlert, 'timestamp'> & { timestamp: string }>;
      agents: Array<Omit<GatraAgentStatus, 'lastHeartbeat'> & { lastHeartbeat: string }>;
      summary: GatraIncidentSummary;
      craActions: Array<Omit<GatraCRAAction, 'timestamp'> & { timestamp: string }>;
      taaAnalyses: Array<Omit<GatraTAAAnalysis, 'timestamp'> & { timestamp: string }>;
      correlations: Array<Omit<GatraCorrelation, 'timestamp'> & { timestamp: string }>;
      source?: string;
      error?: string;
    };

    if (data.error) {
      console.warn('[GatraConnector] GATRA API returned error:', data.error);
      return null;
    }

    // Parse ISO date strings back to Date objects
    const alerts: GatraAlert[] = (data.alerts ?? []).map(a => ({
      ...a,
      timestamp: new Date(a.timestamp),
    }));

    const agents: GatraAgentStatus[] = (data.agents ?? []).map(a => ({
      ...a,
      lastHeartbeat: new Date(a.lastHeartbeat),
    }));

    const craActions: GatraCRAAction[] = (data.craActions ?? []).map(a => ({
      ...a,
      timestamp: new Date(a.timestamp),
    }));

    const taaAnalyses: GatraTAAAnalysis[] = (data.taaAnalyses ?? []).map(a => ({
      ...a,
      timestamp: new Date(a.timestamp),
    }));

    const correlations: GatraCorrelation[] = (data.correlations ?? []).map(c => ({
      ...c,
      timestamp: new Date(c.timestamp),
    }));

    return {
      alerts,
      agents,
      summary: data.summary,
      craActions,
      taaAnalyses,
      correlations,
      lastRefresh: new Date(),
    };
  } catch (err) {
    console.warn('[GatraConnector] GATRA API unreachable, will use mock:', err);
    return null;
  }
}

// ── CISA KEV fetch (live data replacement) ──────────────────────────

/** Geo-locations to distribute KEV alerts on the map (global tech hubs). */
const KEV_LOCATIONS: Array<{ name: string; lat: number; lon: number; infra: string }> = [
  { name: 'Washington D.C.', lat: 38.90, lon: -77.04, infra: 'GOV-FED-DC' },
  { name: 'San Francisco',   lat: 37.77, lon: -122.42, infra: 'TECH-CLOUD-SFO' },
  { name: 'New York',        lat: 40.71, lon: -74.01, infra: 'FIN-CORE-NYC' },
  { name: 'Seattle',         lat: 47.61, lon: -122.33, infra: 'CLOUD-AWS-SEA' },
  { name: 'London',          lat: 51.51, lon: -0.13, infra: 'FIN-EU-LON' },
  { name: 'Singapore',       lat: 1.35, lon: 103.82, infra: 'APAC-DC-SIN' },
  { name: 'Jakarta',         lat: -6.21, lon: 106.85, infra: 'TELCO-CORE-JKT' },
  { name: 'Austin',          lat: 30.27, lon: -97.74, infra: 'TECH-HQ-AUS' },
  { name: 'Tokyo',           lat: 35.68, lon: 139.69, infra: 'CLOUD-APAC-TYO' },
  { name: 'Frankfurt',       lat: 50.11, lon: 8.68, infra: 'DC-EU-FRA' },
];

/** Simple CWE → MITRE ATT&CK mapping for common weakness classes. */
function cweToMitre(cwes: string[]): { id: string; name: string } {
  const cwe = cwes[0] || '';
  // Map common CWE categories to MITRE techniques
  if (/CWE-(78|77|94|95|96)/.test(cwe))  return { id: 'T1059', name: 'Command and Scripting Interpreter' };
  if (/CWE-(89|564)/.test(cwe))           return { id: 'T1190', name: 'Exploit Public-Facing Application' };
  if (/CWE-(287|306|862|863)/.test(cwe))  return { id: 'T1078', name: 'Valid Accounts' };
  if (/CWE-(22|23|36)/.test(cwe))         return { id: 'T1083', name: 'File and Directory Discovery' };
  if (/CWE-(787|119|120|122|125)/.test(cwe)) return { id: 'T1203', name: 'Exploitation for Client Execution' };
  if (/CWE-(79|80)/.test(cwe))            return { id: 'T1189', name: 'Drive-by Compromise' };
  if (/CWE-(502|1321)/.test(cwe))         return { id: 'T1059', name: 'Command and Scripting Interpreter' };
  if (/CWE-(434)/.test(cwe))              return { id: 'T1105', name: 'Ingress Tool Transfer' };
  if (/CWE-(918)/.test(cwe))              return { id: 'T1090', name: 'Proxy' };
  if (/CWE-(200|209|532)/.test(cwe))      return { id: 'T1005', name: 'Data from Local System' };
  // Default: Exploit Public-Facing Application
  return { id: 'T1190', name: 'Exploit Public-Facing Application' };
}

// ── Asset relevance scoring ─────────────────────────────────────────

interface RelevanceResult {
  score: number;
  matchedVendors: string[];
  matchedProducts: string[];
  industryMatch: boolean;
}

/**
 * Compute a 0-100 relevance score for a CISA KEV entry against the active asset profile.
 *
 * Scoring (max 100):
 *   Vendor match:        40 pts  (scaled by entry weight)
 *   Product match:       30 pts  (scaled by entry weight)
 *   Industry keyword:    15 pts
 *   Ransomware campaign: 10 pts
 *   Due date urgency:     5 pts
 */
function computeRelevanceScore(
  kevVendor: string,
  kevProduct: string,
  kevDescription: string,
  isRansomware: boolean,
  dueSoon: boolean,
): RelevanceResult {
  const profile = getActiveAssetProfile();
  let score = 0;
  const matchedVendors: string[] = [];
  const matchedProducts: string[] = [];
  let industryMatch = false;

  const vendorLower = kevVendor.toLowerCase().trim();
  const productLower = kevProduct.toLowerCase().trim();
  const descLower = kevDescription.toLowerCase();

  // 1. Vendor + Product matching (max 70 points)
  // Two passes: first check vendor name, then check if vendor name appears in product/description
  // (handles cases like KEV vendor "Broadcom" with product "VMware vCenter Server")
  for (const entry of profile.vendors) {
    const entryVendorLower = entry.vendor.toLowerCase();
    const weight = entry.weight ?? 1.0;

    // Fuzzy vendor match: either contains the other (handles "Palo Alto" vs "Palo Alto Networks")
    const vendorMatch =
      vendorLower.includes(entryVendorLower) ||
      entryVendorLower.includes(vendorLower) ||
      // Also check if our vendor name appears in the KEV product name or description
      productLower.includes(entryVendorLower) ||
      descLower.includes(entryVendorLower);

    if (vendorMatch) {
      matchedVendors.push(entry.vendor);
      score += Math.round(40 * weight);

      // Product match within matched vendor
      if (entry.products && entry.products.length > 0) {
        for (const prod of entry.products) {
          const prodLower = prod.toLowerCase();
          if (
            productLower.includes(prodLower) ||
            prodLower.includes(productLower) ||
            descLower.includes(prodLower)
          ) {
            matchedProducts.push(prod);
            score += Math.round(30 * weight);
            break; // Only count product match once per vendor
          }
        }
      } else {
        // Vendor match but no specific products listed → partial credit
        score += Math.round(10 * weight);
      }
      break; // Best vendor match wins
    }
  }

  // 2. Industry keyword match (max 15 points)
  for (const keyword of profile.industryKeywords) {
    if (descLower.includes(keyword.toLowerCase())) {
      industryMatch = true;
      score += 15;
      break;
    }
  }

  // 3. Ransomware universal threat boost (10 points)
  if (isRansomware) {
    score += 10;
  }

  // 4. Urgency boost — CISA deadline within 7 days (5 points)
  if (dueSoon) {
    score += 5;
  }

  return {
    score: Math.min(100, score),
    matchedVendors: [...new Set(matchedVendors)],
    matchedProducts: [...new Set(matchedProducts)],
    industryMatch,
  };
}

// ── CISA KEV types ──────────────────────────────────────────────────

interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: string;
  cwes: string[];
  notes?: string;
}

/** Fetch live vulnerability data from CISA KEV feed via our edge proxy. */
async function fetchFromCisaKev(): Promise<GatraConnectorSnapshot | null> {
  try {
    const res = await fetch('/api/cisa-kev', { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;

    const data = await res.json() as {
      vulnerabilities: CisaKevEntry[];
      catalogVersion: string;
      count: number;
      totalKnown: number;
      source: string;
    };

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) return null;

    const now = new Date();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    // ── Map KEV entries → GatraAlert[] ──
    const alerts: GatraAlert[] = data.vulnerabilities.map((kev, i) => {
      const loc = KEV_LOCATIONS[i % KEV_LOCATIONS.length]!;
      const mitre = cweToMitre(kev.cwes || []);
      const isRansomware = kev.knownRansomwareCampaignUse === 'Known';
      const dueDate = new Date(kev.dueDate);
      const dateAdded = new Date(kev.dateAdded);
      const dueSoon = dueDate.getTime() - now.getTime() < sevenDaysMs;

      let severity: GatraAlert['severity'];
      if (isRansomware) severity = 'critical';
      else if (dueSoon) severity = 'high';
      else if (now.getTime() - dateAdded.getTime() < 30 * 24 * 60 * 60 * 1000) severity = 'medium';
      else severity = 'low';

      const desc = `${kev.vulnerabilityName} — ${kev.shortDescription}`.slice(0, 300);
      const relevance = computeRelevanceScore(
        kev.vendorProject,
        kev.product,
        desc,
        isRansomware,
        dueSoon,
      );

      return {
        id: kev.cveID,
        severity,
        mitreId: mitre.id,
        mitreName: mitre.name,
        description: desc,
        confidence: isRansomware ? 99 : 95,
        lat: loc.lat,
        lon: loc.lon,
        locationName: `${loc.name} (${kev.vendorProject})`,
        infrastructure: `${loc.infra} · ${kev.product}`,
        timestamp: dateAdded,
        agent: isRansomware ? 'ADA' as const : 'TAA' as const,
        // Asset relevance
        relevanceScore: relevance.score,
        matchedVendors: relevance.matchedVendors,
        matchedProducts: relevance.matchedProducts,
        industryMatch: relevance.industryMatch,
        kevVendor: kev.vendorProject,
        kevProduct: kev.product,
      };
    });

    // ── Synthetic agent statuses (all "online" since we have live feed) ──
    const agents: GatraAgentStatus[] = [
      { name: 'ADA', fullName: 'Anomaly Detection Agent',     status: 'online', lastHeartbeat: now },
      { name: 'TAA', fullName: 'Threat Analysis Agent',       status: 'online', lastHeartbeat: now },
      { name: 'CRA', fullName: 'Containment Response Agent',  status: 'online', lastHeartbeat: now },
      { name: 'CLA', fullName: 'Compliance & Logging Agent',  status: 'online', lastHeartbeat: now },
      { name: 'RVA', fullName: 'Risk & Vulnerability Agent',  status: 'processing', lastHeartbeat: now },
    ];

    // ── Summary from real counts ──
    const criticalCount = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
    const summary: GatraIncidentSummary = {
      activeIncidents: criticalCount,
      mttrMinutes: 12, // Simulated MTTR
      alerts24h: alerts.length,
      responses24h: Math.min(alerts.length, 15),
    };

    // ── CRA actions from requiredAction field ──
    const craActions: GatraCRAAction[] = data.vulnerabilities
      .filter(kev => kev.knownRansomwareCampaignUse === 'Known' || new Date(kev.dueDate).getTime() - now.getTime() < sevenDaysMs)
      .slice(0, 8)
      .map((kev, i) => ({
        id: `cra-${kev.cveID}`,
        action: `${kev.requiredAction} [${kev.cveID}]`.slice(0, 200),
        actionType: (i % 2 === 0 ? 'rule_pushed' : 'playbook_triggered') as GatraCRAAction['actionType'],
        target: `${KEV_LOCATIONS[i % KEV_LOCATIONS.length]!.infra} · ${kev.product}`,
        timestamp: new Date(kev.dueDate),
        success: true,
      }));

    // ── TAA analyses from ransomware-linked entries ──
    const taaAnalyses: GatraTAAAnalysis[] = data.vulnerabilities
      .filter(kev => kev.knownRansomwareCampaignUse === 'Known')
      .slice(0, 6)
      .map(kev => {
        return {
          id: `taa-${kev.cveID}`,
          alertId: kev.cveID,
          actorAttribution: 'Ransomware Operator',
          campaign: `KEV-${kev.vendorProject}-${kev.product}`.slice(0, 50),
          killChainPhase: 'exploitation' as const,
          confidence: 92,
          iocs: [kev.cveID, ...(kev.cwes || [])],
          timestamp: new Date(kev.dateAdded),
        };
      });

    // ── Correlations (empty — will be filled by ACLED engine) ──
    const correlations: GatraCorrelation[] = [];

    console.log(`[GatraConnector] CISA KEV live: ${alerts.length} vulns (${criticalCount} critical/high, ${taaAnalyses.length} ransomware-linked)`);

    return { alerts, agents, summary, craActions, taaAnalyses, correlations, lastRefresh: now };
  } catch (err) {
    console.warn('[GatraConnector] CISA KEV fetch failed:', err);
    return null;
  }
}

// ── Mock data fetch (fallback) ──────────────────────────────────────

async function fetchFromMock(): Promise<GatraConnectorSnapshot> {
  const [alerts, agents, summary, craActions] = await Promise.all([
    fetchGatraAlerts(),
    fetchGatraAgentStatus(),
    fetchGatraIncidentSummary(),
    fetchGatraCRAActions(),
  ]);

  const [taaAnalyses, correlations] = await Promise.all([
    fetchGatraTAAAnalyses(alerts),
    fetchGatraCorrelations(alerts),
  ]);

  return { alerts, agents, summary, craActions, taaAnalyses, correlations, lastRefresh: new Date() };
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Fetch all GATRA data — tries GATRA API first, falls back to mock.
 * Returns a unified snapshot that panels, layers, and other consumers
 * can read without issuing their own requests.
 */
export async function refreshGatraData(): Promise<GatraConnectorSnapshot> {
  if (_refreshing && _snapshot) return _snapshot;
  _refreshing = true;

  try {
    // Cascade: GATRA API → CISA KEV → mock data
    const apiSnap = await fetchFromGatraAPI();

    if (apiSnap && apiSnap.alerts.length > 0) {
      _snapshot = apiSnap;
      _source = 'live';
      console.log(`[GatraConnector] Live data: ${apiSnap.alerts.length} alerts from GATRA API`);
    } else {
      // Try CISA KEV live feed before falling back to mock
      const kevSnap = await fetchFromCisaKev();
      if (kevSnap && kevSnap.alerts.length > 0) {
        _snapshot = kevSnap;
        _source = 'live';
      } else {
        _snapshot = await fetchFromMock();
        _source = 'mock';
        console.log(`[GatraConnector] Using mock data: ${_snapshot.alerts.length} alerts`);
      }
    }

    // Notify subscribers
    for (const fn of _listeners) {
      try { fn(_snapshot); } catch (e) { console.error('[GatraConnector] listener error:', e); }
    }

    return _snapshot;
  } catch (err) {
    console.error('[GatraConnector] refresh failed:', err);
    if (_snapshot) return _snapshot;
    throw err;
  } finally {
    _refreshing = false;
  }
}

/** Return the last cached snapshot (may be null before first refresh). */
export function getGatraSnapshot(): GatraConnectorSnapshot | null {
  return _snapshot;
}

/** Whether the last refresh used real GATRA API data or mock. */
export function getGatraSource(): 'live' | 'mock' {
  return _source;
}

/** Subscribe to snapshot updates. Returns an unsubscribe function. */
export function onGatraUpdate(fn: (snap: GatraConnectorSnapshot) => void): () => void {
  _listeners.add(fn);
  return () => { _listeners.delete(fn); };
}

// ── ACLED Conflict Correlation Engine ─────────────────────────────

// Southeast Asia + nearby regions relevant to GATRA's telco infrastructure
const SEA_COUNTRIES = new Set([
  'Indonesia', 'Malaysia', 'Philippines', 'Singapore', 'Thailand',
  'Vietnam', 'Myanmar', 'Cambodia', 'Laos', 'Brunei', 'Timor-Leste',
  'Papua New Guinea', 'Australia',
]);

// Bounding box: broader SE Asia / Indo-Pacific region
const SEA_BOUNDS = { latMin: -15, latMax: 25, lonMin: 90, lonMax: 160 };

interface ConflictEventLike {
  id: string;
  eventType: string;
  country: string;
  location: string;
  lat: number;
  lon: number;
  time: Date;
  fatalities: number;
  actors: string[];
  source: string;
  region?: string;
}

/**
 * Ingest ACLED conflict events and correlate with current GATRA alerts.
 *
 * Produces GatraCorrelation entries that link regional instability to
 * cyber threat posture. Called from App.ts after both ACLED and GATRA
 * data have loaded.
 *
 * Update frequency: 10-minute TTL (matches ACLED cache).
 * Agent target: TAA (Threat Analysis Agent).
 */
export function ingestConflictCorrelations(conflicts: ConflictEventLike[]): void {
  if (!_snapshot) return;

  // Filter to SE Asia / Indo-Pacific region
  const regional = conflicts.filter(c =>
    SEA_COUNTRIES.has(c.country) ||
    (c.lat >= SEA_BOUNDS.latMin && c.lat <= SEA_BOUNDS.latMax &&
     c.lon >= SEA_BOUNDS.lonMin && c.lon <= SEA_BOUNDS.lonMax)
  );

  if (regional.length === 0) {
    console.log('[GatraConnector] No SEA-region conflicts to correlate');
    return;
  }

  // Group by country
  const byCountry = new Map<string, ConflictEventLike[]>();
  for (const c of regional) {
    const list = byCountry.get(c.country) || [];
    list.push(c);
    byCountry.set(c.country, list);
  }

  // Build correlations — one per country with active conflicts
  const correlations: GatraCorrelation[] = [];
  const gatraAlerts = _snapshot.alerts;

  for (const [country, events] of byCountry) {
    if (events.length === 0) continue;
    const totalFatalities = events.reduce((sum, e) => sum + e.fatalities, 0);
    const topEvent = events.reduce((best, e) => e.fatalities > best.fatalities ? e : best, events[0]!)!

    // Determine severity from fatality count and event volume
    let severity: 'critical' | 'high' | 'medium' | 'low';
    if (totalFatalities >= 50 || events.length >= 20) severity = 'critical';
    else if (totalFatalities >= 10 || events.length >= 10) severity = 'high';
    else if (totalFatalities >= 1 || events.length >= 3) severity = 'medium';
    else severity = 'low';

    // Determine correlation type
    const hasAptActors = events.some(e =>
      e.actors.some(a => /military|army|rebel|militia|state/i.test(a))
    );
    const eventType: GatraCorrelation['worldMonitorEventType'] =
      hasAptActors ? 'apt_activity'
      : country === 'Indonesia' ? 'cii_spike'
      : 'geopolitical';

    // Find GATRA alerts in the same country/region for linking
    const nearbyAlertIds = gatraAlerts
      .filter(a => {
        if (country === 'Indonesia') return true; // All GATRA alerts are Indonesian infra
        // Proximity match: within ~3 degrees
        return events.some(e =>
          Math.abs(a.lat - e.lat) < 3 && Math.abs(a.lon - e.lon) < 3
        );
      })
      .slice(0, 5)
      .map(a => a.id);

    // Build event type breakdown
    const types = events.map(e => e.eventType);
    const battles = types.filter(t => t.includes('battle') || t.includes('Battle')).length;
    const explosions = types.filter(t => t.includes('xplosion') || t.includes('remote')).length;
    const civilian = types.filter(t => t.includes('civilian') || t.includes('Civilian')).length;

    const parts: string[] = [];
    if (battles) parts.push(`${battles} battle${battles > 1 ? 's' : ''}`);
    if (explosions) parts.push(`${explosions} explosion${explosions > 1 ? 's' : ''}`);
    if (civilian) parts.push(`${civilian} civilian targeting`);
    const breakdown = parts.join(', ') || `${events.length} conflict event${events.length > 1 ? 's' : ''}`;

    let summary = `ACLED: ${breakdown} in ${country}`;
    if (totalFatalities > 0) summary += ` (${totalFatalities} fatalities)`;
    summary += `. ${topEvent.location || topEvent.region || country}`;
    if (country === 'Indonesia') {
      summary += ' — direct threat to monitored CII infrastructure.';
    } else {
      summary += ' — regional instability may elevate APT activity targeting ASEAN telcos.';
    }

    correlations.push({
      id: `acled-corr-${country.toLowerCase().replace(/\s+/g, '-')}`,
      gatraAlertIds: nearbyAlertIds,
      worldMonitorEventType: eventType,
      region: country,
      summary,
      severity,
      timestamp: topEvent.time,
    });
  }

  // Sort: critical first, then by fatalities
  correlations.sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sevOrder[a.severity] - sevOrder[b.severity]);
  });

  // Update snapshot with correlations
  _snapshot = { ..._snapshot, correlations };

  // Notify subscribers
  for (const fn of _listeners) {
    try { fn(_snapshot); } catch (e) { console.error('[GatraConnector] listener error:', e); }
  }

  console.log(`[GatraConnector] ACLED correlation: ${correlations.length} regions, ${regional.length} events in SEA`);
}

// ── Convenience accessors ───────────────────────────────────────────

export function getAlerts(): GatraAlert[] {
  return _snapshot?.alerts ?? [];
}

export function getAgentStatus(): GatraAgentStatus[] {
  return _snapshot?.agents ?? [];
}

export function getIncidentSummary(): GatraIncidentSummary | null {
  return _snapshot?.summary ?? null;
}

export function getCRAActions(): GatraCRAAction[] {
  return _snapshot?.craActions ?? [];
}

export function getTAAAnalyses(): GatraTAAAnalysis[] {
  return _snapshot?.taaAnalyses ?? [];
}

export function getCorrelations(): GatraCorrelation[] {
  return _snapshot?.correlations ?? [];
}
