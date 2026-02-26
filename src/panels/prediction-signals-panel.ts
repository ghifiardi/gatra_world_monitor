/**
 * Prediction Market Signals Panel — GATRA Cyber variant.
 *
 * Surfaces geopolitical probability signals from prediction markets that serve
 * as early warning indicators for cyber threat escalation.  Two signal modes:
 *
 *   1. Probability extremity — markets far from 50% indicate strong consensus
 *      on geopolitical outcomes (works immediately, no history needed)
 *   2. Velocity — rapid probability shifts over time (requires 2+ data points)
 *
 * Computes an `early_warning_multiplier` fed into the CII panel's R_geo.
 *
 * Data flow:
 *   fetchPredictions() → filter by relevance keywords → assess threat level
 *   → compute early_warning_multiplier
 *   → dispatch 'gatra-early-warning-update' event → CII panel R_geo
 */

import { Panel } from '@/components/Panel';
import { escapeHtml } from '@/utils/sanitize';
import type { PredictionMarket } from '@/services/prediction';

// ── Relevance keyword tiers ──────────────────────────────────────

const RELEVANCE_KEYWORDS: Record<number, string[]> = {
  1: [
    'cyberattack', 'cyber', 'hack', 'ransomware', 'malware',
    'indonesia', 'southeast asia', 'asean', 'jakarta',
    'data breach', 'infrastructure attack',
  ],
  2: [
    'china', 'taiwan', 'south china sea', 'philippines', 'myanmar',
    'north korea', 'pyongyang', 'beijing', 'asia',
    'pacific', 'india', 'modi',
  ],
  3: [
    'russia', 'ukraine', 'iran', 'israel', 'gaza', 'hezbollah',
    'war', 'invasion', 'ceasefire', 'military', 'conflict',
    'nato', 'missile', 'nuclear', 'sanction', 'weapon',
    'attack', 'strike', 'drone',
  ],
  4: [
    'election', 'president', 'trump', 'tariff', 'trade',
    'recession', 'crisis', 'coup', 'protest', 'middle east',
    'oil', 'energy', 'embargo', 'geopolit',
  ],
};

const TIER_WEIGHTS: Record<number, number> = { 1: 1.0, 2: 0.7, 3: 0.4, 4: 0.2 };

interface MarketRelevance {
  tier: number;
  weight: number;
  keywords: string[];
}

function classifyMarket(question: string): MarketRelevance | null {
  const q = question.toLowerCase();
  for (const tier of [1, 2, 3, 4]) {
    const kws = RELEVANCE_KEYWORDS[tier]!;
    const matched = kws.filter(kw => q.includes(kw));
    if (matched.length > 0) {
      return { tier, weight: TIER_WEIGHTS[tier]!, keywords: matched };
    }
  }
  return null;
}

// ── In-memory probability history ────────────────────────────────

interface ProbabilityPoint {
  timestamp: number;
  probability: number;
}

const probabilityHistory = new Map<string, ProbabilityPoint[]>();

function recordProbability(title: string, probability: number): void {
  const history = probabilityHistory.get(title) || [];
  history.push({ timestamp: Date.now(), probability });
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const trimmed = history.filter(h => h.timestamp > cutoff);
  probabilityHistory.set(title, trimmed);
}

function computeVelocity(title: string, windowHours = 6): number {
  const history = probabilityHistory.get(title);
  if (!history || history.length < 2) return 0;

  const windowStart = Date.now() - windowHours * 60 * 60 * 1000;
  const recent = history.filter(h => h.timestamp > windowStart);
  if (recent.length < 2) return 0;

  const oldest = recent[0]!;
  const newest = recent[recent.length - 1]!;
  const hoursDelta = (newest.timestamp - oldest.timestamp) / (1000 * 60 * 60);
  if (hoursDelta < 0.05) return 0;

  return (newest.probability - oldest.probability) / hoursDelta;
}

// ── Signal assessment ────────────────────────────────────────────
// Two dimensions: probability extremity (immediate) + velocity (over time)

interface TrackedMarket {
  title: string;
  probability: number;
  volume: number;
  velocity: number;
  relevance: MarketRelevance;
  url?: string;
  threatLevel: 'critical' | 'high' | 'elevated' | 'moderate' | 'low';
  extremity: number;       // |prob - 50| / 50, 0 = neutral, 1 = extreme
  signalScore: number;     // composite: extremity × weight, used for sorting & EW
}

function assessThreat(probability: number, velocity: number, weight: number): TrackedMarket['threatLevel'] {
  const extremity = Math.abs(probability - 50) / 50;
  const signal = extremity * weight;

  // Velocity boost
  const absVel = Math.abs(velocity);
  if (absVel >= 5.0 && signal > 0.1) return 'critical';
  if (absVel >= 2.5 && signal > 0.1) return 'high';

  // Probability-based
  if (signal >= 0.6) return 'critical';
  if (signal >= 0.4) return 'high';
  if (signal >= 0.25) return 'elevated';
  if (signal >= 0.1) return 'moderate';
  return 'low';
}

const THREAT_COLORS: Record<TrackedMarket['threatLevel'], string> = {
  critical: '#ef4444',
  high: '#f97316',
  elevated: '#eab308',
  moderate: '#22c55e',
  low: '#6b7280',
};

const THREAT_LABELS: Record<TrackedMarket['threatLevel'], string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  elevated: 'ELEVATED',
  moderate: 'MODERATE',
  low: 'LOW',
};

// ── Early warning multiplier ─────────────────────────────────────
// Based on probability extremity × relevance weight (works without history)

function computeEarlyWarningMultiplier(markets: TrackedMarket[]): number {
  let multiplier = 1.0;

  for (const m of markets) {
    if (m.threatLevel === 'low' || m.threatLevel === 'moderate') continue;
    // Contribution: signalScore scaled 0-0.5 per market
    const contribution = Math.min(m.signalScore * 0.5, 0.5);
    multiplier += contribution;
  }

  return Math.min(Math.round(multiplier * 10) / 10, 3.0);
}

// ── Formatting helpers ───────────────────────────────────────────

function formatVolume(volume: number): string {
  if (volume >= 1_000_000) return `$${(volume / 1_000_000).toFixed(1)}M`;
  if (volume >= 1_000) return `$${(volume / 1_000).toFixed(0)}K`;
  return `$${volume.toFixed(0)}`;
}

// ── CSS injection ────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const style = document.createElement('style');
  style.textContent = `
.pred-signals { font-size: 11px; line-height: 1.4; }

.pred-header {
  display: flex; align-items: center; gap: 6px;
  padding: 6px 0 4px; margin-bottom: 4px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.pred-label { font-weight: 600; font-size: 10px; letter-spacing: 0.5px; text-transform: uppercase; color: #ccc; }
.pred-badge {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 600; letter-spacing: 0.3px;
}
.pred-badge-live { background: rgba(34,197,94,0.15); color: #22c55e; }
.pred-badge-live::before {
  content: ''; width: 5px; height: 5px; border-radius: 50%;
  background: #22c55e; animation: pred-pulse 2s infinite;
}
.pred-badge-ew { background: rgba(100,100,100,0.2); color: #888; }
.pred-badge-ew.active { background: rgba(255,152,0,0.2); color: #ff9800; }
.pred-badge-ew.critical { background: rgba(239,68,68,0.2); color: #ef4444; }
@keyframes pred-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Market card — full view */
.pred-card {
  background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 8px 10px; margin-bottom: 5px;
}

.pred-card-top {
  display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;
  margin-bottom: 5px;
}
.pred-card-question {
  font-size: 11px; color: #e0e0e0; line-height: 1.4; flex: 1;
}
.pred-card-prob {
  font-size: 18px; font-weight: 700; white-space: nowrap;
  line-height: 1.2;
}
.pred-card-threat {
  display: inline-block; font-size: 9px; font-weight: 700;
  letter-spacing: 0.5px; padding: 1px 5px; border-radius: 2px;
  margin-bottom: 4px;
}

.pred-bar-outer {
  height: 4px; background: rgba(255,255,255,0.06);
  border-radius: 2px; overflow: hidden; margin-bottom: 4px;
}
.pred-bar-inner { height: 100%; border-radius: 2px; transition: width 0.6s ease; }

.pred-card-meta {
  display: flex; gap: 10px; font-size: 10px; color: #888; flex-wrap: wrap;
}
.pred-card-meta span { white-space: nowrap; }

/* Compact rows */
.pred-compact-section {
  margin-top: 4px; padding-top: 4px;
  border-top: 1px solid rgba(255,255,255,0.04);
}
.pred-compact-row {
  display: flex; align-items: center; gap: 6px;
  padding: 3px 0; font-size: 10px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.pred-compact-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.pred-compact-title {
  flex: 1; color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  min-width: 0;
}
.pred-compact-prob { font-weight: 600; color: #e0e0e0; width: 34px; text-align: right; flex-shrink: 0; }
.pred-compact-threat { font-size: 8px; font-weight: 700; width: 28px; text-align: center; flex-shrink: 0; }

/* EW summary */
.pred-ew-box {
  margin-top: 6px; padding: 6px 8px;
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05);
  border-radius: 4px;
}
.pred-ew-row { display: flex; align-items: center; gap: 6px; }
.pred-ew-label { font-size: 9px; font-weight: 600; color: #888; letter-spacing: 0.3px; text-transform: uppercase; }
.pred-ew-value {
  font-weight: 700; font-size: 14px; padding: 1px 6px; border-radius: 3px;
}
.pred-ew-elevated { background: rgba(255,152,0,0.15); color: #ff9800; }
.pred-ew-nominal { background: rgba(34,197,94,0.1); color: #22c55e; }
.pred-ew-detail { font-size: 9px; color: #555; margin-top: 3px; }

/* Footer */
.pred-footer {
  margin-top: 4px; padding-top: 4px;
  border-top: 1px solid rgba(255,255,255,0.04);
  font-size: 9px; color: #555;
}

/* Empty states */
.pred-empty {
  padding: 16px 12px; text-align: center; color: #888; font-size: 11px;
}
.pred-empty-title { font-weight: 600; margin-bottom: 4px; color: #aaa; }
  `;
  document.head.appendChild(style);
}

// ── Panel class ──────────────────────────────────────────────────

export class PredictionSignalsPanel extends Panel {
  private trackedMarkets: TrackedMarket[] = [];
  private earlyWarningMultiplier = 1.0;
  private lastSyncTime: number | null = null;
  private totalMarketsScanned = 0;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private dataAvailable = false;

  constructor() {
    super({
      id: 'prediction-signals',
      title: 'Predictive Signals',
      infoTooltip:
        'Prediction market probability signals for geopolitical threat assessment. ' +
        'Markets with extreme probabilities or rapid shifts trigger early warning ' +
        'multipliers in GATRA\'s CII R_geo formula.',
    });
    injectCSS();
    this.showLoading();
    this.refreshTimer = setInterval(() => this.refresh(), 5 * 60 * 1000);
    setTimeout(() => this.refresh(), 4000);
  }

  // ── Public API ──────────────────────────────────────────────────

  public updatePredictions(predictions: PredictionMarket[]): void {
    this.totalMarketsScanned = predictions.length;

    // Record probabilities for velocity tracking
    for (const p of predictions) {
      recordProbability(p.title, p.yesPrice);
    }

    // Filter and assess
    const tracked: TrackedMarket[] = [];
    for (const p of predictions) {
      const relevance = classifyMarket(p.title);
      if (!relevance) continue;

      const velocity = computeVelocity(p.title);
      const extremity = Math.abs(p.yesPrice - 50) / 50;
      const signalScore = extremity * relevance.weight;
      const threatLevel = assessThreat(p.yesPrice, velocity, relevance.weight);

      tracked.push({
        title: p.title,
        probability: p.yesPrice,
        volume: p.volume ?? 0,
        velocity,
        relevance,
        url: p.url,
        threatLevel,
        extremity,
        signalScore,
      });
    }

    // Sort by signal score descending (strongest signals first)
    tracked.sort((a, b) => b.signalScore - a.signalScore);

    this.trackedMarkets = tracked;
    this.dataAvailable = true;

    // Compute EW multiplier & sync
    this.earlyWarningMultiplier = computeEarlyWarningMultiplier(tracked);
    this.syncEarlyWarning();

    const elevated = tracked.filter(m => m.threatLevel !== 'low' && m.threatLevel !== 'moderate').length;
    this.setDataBadge('live', `${tracked.length} signals`);

    if (elevated > 0) {
      this.setCount(elevated);
    }

    this.render();
  }

  public async refresh(): Promise<void> {
    if (this.trackedMarkets.length > 0) {
      this.render();
    }
  }

  // ── Sync to CII panel ──────────────────────────────────────────

  private syncEarlyWarning(): void {
    this.lastSyncTime = Date.now();
    window.dispatchEvent(new CustomEvent('gatra-early-warning-update', {
      detail: {
        multiplier: this.earlyWarningMultiplier,
        activeMarkets: this.trackedMarkets.filter(m => m.threatLevel !== 'low' && m.threatLevel !== 'moderate').length,
        timestamp: Date.now(),
        source: 'prediction-markets',
      },
    }));
  }

  // ── Render ─────────────────────────────────────────────────────

  private render(): void {
    if (!this.dataAvailable) {
      this.renderUnavailable();
      return;
    }
    if (this.trackedMarkets.length === 0) {
      this.renderNoSignals();
      return;
    }

    // Top 3 as full cards, rest as compact
    const topMarkets = this.trackedMarkets.slice(0, 3);
    const restMarkets = this.trackedMarkets.slice(3);

    const html = `
      <div class="pred-signals">
        ${this.renderHeader()}
        ${topMarkets.map(m => this.renderCard(m)).join('')}
        ${restMarkets.length > 0 ? this.renderCompactSection(restMarkets) : ''}
        ${this.renderEWSummary()}
        ${this.renderFooter()}
      </div>`;

    this.setContent(html);
  }

  private renderUnavailable(): void {
    this.setContent(`
      <div class="pred-signals">
        ${this.renderHeader()}
        <div class="pred-empty">
          <div class="pred-empty-title">UNAVAILABLE</div>
          <div>Prediction market feeds offline.</div>
          <div style="margin-top:6px;">Early warning: <b>\u00D71.0</b></div>
        </div>
      </div>`);
  }

  private renderNoSignals(): void {
    const empty = this.totalMarketsScanned === 0;
    this.setContent(`
      <div class="pred-signals">
        ${this.renderHeader()}
        <div class="pred-empty">
          ${empty ? `
            <div class="pred-empty-title">AWAITING DATA</div>
            <div>Loading prediction market feeds...</div>
          ` : `
            <div class="pred-empty-title">NOMINAL</div>
            <div>Scanned ${this.totalMarketsScanned} markets \u2014 no geopolitical signals detected.</div>
          `}
          <div style="margin-top:6px;">Early warning: <b>\u00D71.0</b></div>
        </div>
      </div>`);
  }

  // ── Header ─────────────────────────────────────────────────────

  private renderHeader(): string {
    const elevated = this.trackedMarkets.filter(m =>
      m.threatLevel === 'critical' || m.threatLevel === 'high' || m.threatLevel === 'elevated'
    ).length;

    const ewClass = this.earlyWarningMultiplier >= 1.5
      ? 'pred-badge pred-badge-ew critical'
      : elevated > 0
        ? 'pred-badge pred-badge-ew active'
        : 'pred-badge pred-badge-ew';

    const ewLabel = this.earlyWarningMultiplier > 1.0
      ? `EW \u00D7${this.earlyWarningMultiplier.toFixed(1)}`
      : 'BASELINE';

    return `
      <div class="pred-header">
        <span class="pred-label">THREAT SIGNALS</span>
        <span class="pred-badge pred-badge-live">LIVE</span>
        <span class="${ewClass}">${escapeHtml(ewLabel)}</span>
      </div>`;
  }

  // ── Full card ──────────────────────────────────────────────────

  private renderCard(m: TrackedMarket): string {
    const color = THREAT_COLORS[m.threatLevel];
    const label = THREAT_LABELS[m.threatLevel];
    const barColor = m.probability >= 60 ? '#ef4444' : m.probability >= 30 ? '#f97316' : '#22c55e';

    const velocityHasData = (probabilityHistory.get(m.title)?.length ?? 0) >= 2;
    const velocityText = velocityHasData
      ? `${m.velocity >= 0 ? '+' : ''}${m.velocity.toFixed(1)}pp/h`
      : '';

    const tierLabel = ['', 'CYBER/ID', 'INDO-PAC', 'CONFLICT', 'GEOPOLIT'][m.relevance.tier] ?? `T${m.relevance.tier}`;

    return `
      <div class="pred-card" style="border-left: 3px solid ${color};">
        <span class="pred-card-threat" style="background:${color}20;color:${color};">${label}</span>
        <div class="pred-card-top">
          <div class="pred-card-question">${escapeHtml(m.title)}</div>
          <div class="pred-card-prob" style="color:${barColor};">${Math.round(m.probability)}%</div>
        </div>
        <div class="pred-bar-outer">
          <div class="pred-bar-inner" style="width:${m.probability}%;background:${barColor};"></div>
        </div>
        <div class="pred-card-meta">
          <span style="color:${color};">${tierLabel}</span>
          ${m.volume > 0 ? `<span>${formatVolume(m.volume)} liquidity</span>` : ''}
          ${velocityText ? `<span>Vel: ${escapeHtml(velocityText)}</span>` : ''}
          <span>Signal: ${(m.signalScore * 100).toFixed(0)}%</span>
        </div>
      </div>`;
  }

  // ── Compact section ────────────────────────────────────────────

  private renderCompactSection(markets: TrackedMarket[]): string {
    const rows = markets.slice(0, 8).map(m => {
      const color = THREAT_COLORS[m.threatLevel];
      const label = THREAT_LABELS[m.threatLevel].substring(0, 4);

      return `
        <div class="pred-compact-row" title="${escapeHtml(m.title)}">
          <span class="pred-compact-dot" style="background:${color};"></span>
          <span class="pred-compact-title">${escapeHtml(m.title)}</span>
          <span class="pred-compact-prob">${Math.round(m.probability)}%</span>
          <span class="pred-compact-threat" style="color:${color};">${label}</span>
        </div>`;
    }).join('');

    return `<div class="pred-compact-section">${rows}</div>`;
  }

  // ── EW summary ─────────────────────────────────────────────────

  private renderEWSummary(): string {
    const isElevated = this.earlyWarningMultiplier > 1.0;
    const ewClass = isElevated ? 'pred-ew-value pred-ew-elevated' : 'pred-ew-value pred-ew-nominal';

    const elevated = this.trackedMarkets.filter(m =>
      m.threatLevel === 'critical' || m.threatLevel === 'high' || m.threatLevel === 'elevated'
    ).length;

    const syncAgo = this.lastSyncTime
      ? `${Math.round((Date.now() - this.lastSyncTime) / 1000)}s ago`
      : 'pending';

    return `
      <div class="pred-ew-box">
        <div class="pred-ew-row">
          <span class="pred-ew-label">Early Warning \u2192 CII</span>
          <span class="${ewClass}">\u00D7${this.earlyWarningMultiplier.toFixed(1)}</span>
          <span style="color:#666;font-size:10px;">${elevated > 0 ? `${elevated} elevated` : 'baseline'}</span>
        </div>
        <div class="pred-ew-detail">
          Feeds R_geo multiplier \u00B7 Synced ${escapeHtml(syncAgo)}
        </div>
      </div>`;
  }

  // ── Footer ─────────────────────────────────────────────────────

  private renderFooter(): string {
    return `
      <div class="pred-footer">
        ${this.totalMarketsScanned} markets scanned \u2192 ${this.trackedMarkets.length} relevant
      </div>`;
  }

  // ── Lifecycle ──────────────────────────────────────────────────

  public destroy(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    super.destroy();
  }
}
