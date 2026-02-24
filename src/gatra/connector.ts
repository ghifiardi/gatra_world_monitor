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
