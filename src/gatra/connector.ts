/**
 * GATRA SOC Connector — unified integration layer
 *
 * Data flow:
 *   1. Try /api/gatra-data  (real BigQuery — production predictions + activity logs)
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

// ── Connector state ─────────────────────────────────────────────────

let _snapshot: GatraConnectorSnapshot | null = null;
let _refreshing = false;
let _source: 'bigquery' | 'mock' = 'mock';
const _listeners: Set<(snap: GatraConnectorSnapshot) => void> = new Set();

// ── BigQuery API fetch ──────────────────────────────────────────────

/** Attempt to load real GATRA data from the BigQuery API route. */
async function fetchFromBigQuery(): Promise<GatraConnectorSnapshot | null> {
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
      console.warn('[GatraConnector] BQ API returned error:', data.error);
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
    console.warn('[GatraConnector] BQ API unreachable, will use mock:', err);
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
 * Fetch all GATRA data — tries BigQuery first, falls back to mock.
 * Returns a unified snapshot that panels, layers, and other consumers
 * can read without issuing their own requests.
 */
export async function refreshGatraData(): Promise<GatraConnectorSnapshot> {
  if (_refreshing && _snapshot) return _snapshot;
  _refreshing = true;

  try {
    // Try real BigQuery data first
    const bqSnap = await fetchFromBigQuery();

    if (bqSnap && bqSnap.alerts.length > 0) {
      _snapshot = bqSnap;
      _source = 'bigquery';
      console.log(`[GatraConnector] Live data: ${bqSnap.alerts.length} alerts from BigQuery`);
    } else {
      _snapshot = await fetchFromMock();
      _source = 'mock';
      console.log(`[GatraConnector] Using mock data: ${_snapshot.alerts.length} alerts`);
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

/** Whether the last refresh used real BigQuery data or mock. */
export function getGatraSource(): 'bigquery' | 'mock' {
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
