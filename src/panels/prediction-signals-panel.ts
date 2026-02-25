/**
 * Prediction Market Signals Panel — GATRA Cyber variant.
 *
 * Surfaces geopolitical probability shifts from Polymarket that serve as
 * early warning indicators for cyber threat escalation.  Computes an
 * `early_warning_multiplier` fed into the CII panel's R_geo formula.
 *
 * Data flow:
 *   fetchPredictions() → filter by relevance keywords → track history
 *   → compute velocity → compute early_warning_multiplier
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
  const key = title;
  const history = probabilityHistory.get(key) || [];
  history.push({ timestamp: Date.now(), probability });
  // Keep last 24h
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const trimmed = history.filter(h => h.timestamp > cutoff);
  probabilityHistory.set(key, trimmed);
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

  return (newest.probability - oldest.probability) / hoursDelta; // pp/hour (already 0-100 scale)
}

function getPreviousProbability(title: string): number | null {
  const history = probabilityHistory.get(title);
  if (!history || history.length < 2) return null;
  return history[0]!.probability;
}

// ── Velocity thresholds ──────────────────────────────────────────

const VELOCITY_THRESHOLDS = {
  elevated: 1.0,   // >1 pp/h = significant
  warning: 2.5,    // >2.5 pp/h = major shift
  critical: 5.0,   // >5 pp/h = extreme movement
};

const MIN_VOLUME_USD = 100_000;

// ── Signal type ──────────────────────────────────────────────────

interface TrackedMarket {
  title: string;
  probability: number;
  previousProbability: number | null;
  delta24h: number;
  volume: number;
  velocity: number;
  relevance: MarketRelevance;
  url?: string;
  signalLevel: 'critical' | 'elevated' | 'normal' | 'declining';
  isElevated: boolean;
}

function getSignalLevel(velocity: number, volume: number): TrackedMarket['signalLevel'] {
  if (volume < MIN_VOLUME_USD) return 'normal';
  if (velocity >= VELOCITY_THRESHOLDS.critical) return 'critical';
  if (velocity >= VELOCITY_THRESHOLDS.elevated) return 'elevated';
  if (velocity < -VELOCITY_THRESHOLDS.elevated) return 'declining';
  return 'normal';
}

// ── Early warning multiplier ─────────────────────────────────────

function computeEarlyWarningMultiplier(markets: TrackedMarket[]): number {
  let multiplier = 1.0;

  for (const m of markets) {
    if (!m.isElevated) continue;
    const velocityNorm = Math.min(m.velocity / VELOCITY_THRESHOLDS.warning, 2.0);
    const volumeConfidence = Math.min(m.volume / 1_000_000, 1.0);
    const contribution = velocityNorm * m.relevance.weight * volumeConfidence;
    multiplier += contribution;
  }

  return Math.min(multiplier, 3.0);
}

// ── Formatting helpers ───────────────────────────────────────────

function formatVolume(volume: number): string {
  if (volume >= 1_000_000) return `$${(volume / 1_000_000).toFixed(1)}M`;
  if (volume >= 1_000) return `$${(volume / 1_000).toFixed(0)}K`;
  return `$${volume.toFixed(0)}`;
}

function formatDelta(delta: number): string {
  const sign = delta >= 0 ? '+' : '';
  return `${sign}${delta.toFixed(0)}pp`;
}

function formatVelocity(v: number): string {
  if (v === 0) return '0.0pp/h';
  const sign = v >= 0 ? '+' : '';
  return `${sign}${v.toFixed(1)}pp/h`;
}

// ── CSS injection ────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const style = document.createElement('style');
  style.textContent = `
/* Prediction Signals Panel */
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
.pred-badge-ew.elevated { background: rgba(255,152,0,0.2); color: #ff9800; }
.pred-badge-ew.critical { background: rgba(239,68,68,0.2); color: #ef4444; }

@keyframes pred-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Market card */
.pred-card {
  background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 8px; margin-bottom: 4px;
}
.pred-card.elevated { border-color: rgba(255,152,0,0.3); }
.pred-card.critical { border-color: rgba(239,68,68,0.3); }

.pred-card-status {
  font-size: 9px; font-weight: 700; letter-spacing: 0.3px;
  text-transform: uppercase; margin-bottom: 3px;
}
.pred-status-active { color: #ff9800; }
.pred-status-critical { color: #ef4444; }
.pred-status-normal { color: #4caf50; }
.pred-status-declining { color: #2196f3; }

.pred-card-question {
  font-size: 11px; color: #e0e0e0; margin-bottom: 5px;
  line-height: 1.35;
}

.pred-prob-row {
  display: flex; align-items: center; gap: 6px; margin-bottom: 4px;
}
.pred-prob-text { font-size: 11px; color: #ccc; }
.pred-prob-delta { font-weight: 600; }
.pred-delta-up { color: #ff9800; }
.pred-delta-down { color: #2196f3; }
.pred-delta-flat { color: #888; }

.pred-bar-outer {
  flex: 1; height: 4px; background: rgba(255,255,255,0.06);
  border-radius: 2px; overflow: hidden;
}
.pred-bar-inner { height: 100%; border-radius: 2px; transition: width 0.6s ease; }

.pred-meta-row {
  display: flex; gap: 8px; font-size: 10px; color: #888; flex-wrap: wrap;
}
.pred-meta-row span { white-space: nowrap; }

.pred-signal-label {
  font-size: 10px; font-weight: 600; margin-top: 3px;
}

/* Early warning summary */
.pred-ew-summary {
  margin-top: 6px; padding: 5px 7px;
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.04);
  border-radius: 3px; font-size: 10px;
}
.pred-ew-title { font-weight: 600; color: #aaa; margin-bottom: 2px; }
.pred-ew-value {
  font-weight: 700; font-size: 12px; padding: 0 5px; border-radius: 2px;
  display: inline-block;
}
.pred-ew-elevated { background: rgba(255,152,0,0.15); color: #ff9800; }
.pred-ew-nominal { background: rgba(34,197,94,0.1); color: #22c55e; }
.pred-ew-formula { color: #666; font-family: 'SF Mono', monospace; font-size: 9px; margin-top: 2px; }
.pred-ew-sync { color: #555; font-size: 9px; margin-top: 1px; }

/* Compact mode */
.pred-compact-row {
  display: flex; align-items: center; gap: 6px;
  padding: 3px 0; font-size: 10px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.pred-compact-status { width: 14px; text-align: center; }
.pred-compact-title { flex: 1; color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pred-compact-prob { font-weight: 600; color: #e0e0e0; width: 30px; text-align: right; }
.pred-compact-delta { font-weight: 600; width: 40px; text-align: right; }
.pred-compact-vol { color: #888; width: 40px; text-align: right; }

/* Footer */
.pred-footer {
  margin-top: 6px; padding-top: 5px;
  border-top: 1px solid rgba(255,255,255,0.06);
  font-size: 9px; color: #666; line-height: 1.5;
}
.pred-footer-row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }

/* Empty / unavailable states */
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
  private activeSignalCount = 0;
  private lastSyncTime: number | null = null;
  private totalMarketsScanned = 0;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private dataAvailable = false;

  constructor() {
    super({
      id: 'prediction-signals',
      title: 'Predictive Signals',
      infoTooltip:
        'Prediction market probability shifts that precede traditional threat intelligence. ' +
        'Markets with significant probability movement toward geopolitical instability trigger ' +
        'early warning multipliers in GATRA\'s RL pipeline.',
    });
    injectCSS();
    this.showLoading();

    // Auto-refresh every 5 minutes
    this.refreshTimer = setInterval(() => this.refresh(), 5 * 60 * 1000);

    // Initial attempt after short delay
    setTimeout(() => this.refresh(), 4000);
  }

  // ── Public API (called by App.ts) ──────────────────────────────

  /** Receive latest Polymarket data from the shared prediction refresh cycle. */
  public updatePredictions(predictions: PredictionMarket[]): void {
    this.totalMarketsScanned = predictions.length;

    // 1. Record current probabilities
    for (const p of predictions) {
      recordProbability(p.title, p.yesPrice);
    }

    // 2. Filter for geopolitically relevant markets
    const tracked: TrackedMarket[] = [];
    for (const p of predictions) {
      const relevance = classifyMarket(p.title);
      if (!relevance) continue;

      const velocity = computeVelocity(p.title);
      const prev = getPreviousProbability(p.title);
      const delta24h = prev !== null ? p.yesPrice - prev : 0;
      const signalLevel = getSignalLevel(velocity, p.volume ?? 0);
      const isElevated = signalLevel === 'elevated' || signalLevel === 'critical';

      tracked.push({
        title: p.title,
        probability: p.yesPrice,
        previousProbability: prev,
        delta24h,
        volume: p.volume ?? 0,
        velocity,
        relevance,
        url: p.url,
        signalLevel,
        isElevated,
      });
    }

    // Sort by signal strength: elevated first, then by velocity magnitude
    tracked.sort((a, b) => {
      if (a.isElevated !== b.isElevated) return a.isElevated ? -1 : 1;
      return Math.abs(b.velocity) - Math.abs(a.velocity);
    });

    this.trackedMarkets = tracked;
    this.dataAvailable = true;

    // 3. Compute early warning multiplier
    this.earlyWarningMultiplier = computeEarlyWarningMultiplier(tracked);
    this.activeSignalCount = tracked.filter(m => m.isElevated).length;

    // 4. Dispatch to CII panel
    this.syncEarlyWarning();

    // 5. Update badges
    this.setDataBadge('live', `${tracked.length} markets`);

    // 6. Render
    this.render();
  }

  public async refresh(): Promise<void> {
    // This panel is primarily data-driven via updatePredictions().
    // refresh() re-renders from latest tracked data (e.g. for velocity recalc).
    if (this.trackedMarkets.length > 0) {
      this.render();
    }
  }

  // ── Sync early warning to CII panel ────────────────────────────

  private syncEarlyWarning(): void {
    this.lastSyncTime = Date.now();
    window.dispatchEvent(new CustomEvent('gatra-early-warning-update', {
      detail: {
        multiplier: this.earlyWarningMultiplier,
        activeMarkets: this.activeSignalCount,
        timestamp: Date.now(),
        source: 'polymarket',
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

    // Check panel height — compact mode if constrained
    const panelHeight = this.element?.clientHeight ?? 400;
    const useCompact = panelHeight < 300 || this.trackedMarkets.length > 5;

    const html = [
      this.renderHeader(),
      useCompact ? this.renderCompact() : this.renderFullCards(),
      this.renderEWSummary(),
      this.renderFooter(),
    ].join('');

    this.setContent(html);
  }

  private renderUnavailable(): void {
    const html = `
      <div class="pred-signals">
        ${this.renderHeader()}
        <div class="pred-empty">
          <div class="pred-empty-title">UNAVAILABLE</div>
          <div>Polymarket data feed offline.</div>
          <div style="margin-top:6px;">Early warning multiplier: <b>\u00D71.0</b></div>
          <div style="color:#555;">GATRA RL operating on CII only</div>
        </div>
      </div>`;
    this.setContent(html);
  }

  private renderNoSignals(): void {
    const isDataEmpty = this.totalMarketsScanned === 0;
    const html = `
      <div class="pred-signals">
        ${this.renderHeader()}
        <div class="pred-empty">
          ${isDataEmpty ? `
            <div class="pred-empty-title">AWAITING DATA</div>
            <div>Polymarket feed loading. Data typically arrives within 1\u20132 minutes.</div>
            <div style="margin-top:4px;color:#555;">Cloudflare JA3 protection may delay initial fetch. Auto-retry active.</div>
          ` : `
            <div class="pred-empty-title">NOMINAL</div>
            <div>No geopolitically relevant markets with significant activity detected.</div>
            <div style="margin-top:4px;color:#555;">Scanned ${this.totalMarketsScanned} active markets. Filtered to 0 relevant signals.</div>
          `}
          <div style="margin-top:6px;">Early warning multiplier: <b>\u00D71.0</b></div>
        </div>
      </div>`;
    this.setContent(html);
  }

  // ── Header ─────────────────────────────────────────────────────

  private renderHeader(): string {
    const ewClass = this.activeSignalCount > 1
      ? 'pred-badge pred-badge-ew critical'
      : this.activeSignalCount === 1
        ? 'pred-badge pred-badge-ew elevated'
        : 'pred-badge pred-badge-ew';

    const ewLabel = this.earlyWarningMultiplier > 1.0
      ? `EW \u00D7${this.earlyWarningMultiplier.toFixed(1)}`
      : 'EARLY WARNING';

    return `
      <div class="pred-header">
        <span class="pred-label">PREDICTIVE SIGNALS</span>
        <span class="pred-badge pred-badge-live">LIVE</span>
        <span class="${ewClass}">${escapeHtml(ewLabel)}</span>
      </div>`;
  }

  // ── Full card view ─────────────────────────────────────────────

  private renderFullCards(): string {
    return this.trackedMarkets.slice(0, 6).map(m => this.renderMarketCard(m)).join('');
  }

  private renderMarketCard(m: TrackedMarket): string {
    const cardClass = m.signalLevel === 'critical'
      ? 'pred-card critical'
      : m.signalLevel === 'elevated'
        ? 'pred-card elevated'
        : 'pred-card';

    const statusIcon = m.isElevated ? '\u26A1' : '\u25CF';
    const statusText = m.isElevated ? 'SIGNAL ACTIVE' : 'MONITORING';
    const statusClass = `pred-status-${m.signalLevel}`;

    const probText = m.previousProbability !== null
      ? `${Math.round(m.previousProbability)}% \u2192 ${Math.round(m.probability)}%`
      : `${Math.round(m.probability)}%`;

    const deltaNum = m.delta24h;
    const deltaClass = deltaNum > 0 ? 'pred-delta-up' : deltaNum < 0 ? 'pred-delta-down' : 'pred-delta-flat';
    const deltaArrow = deltaNum < 0 ? '\u25BC' : '\u25B2';
    const deltaDisplay = deltaNum !== 0
      ? `${deltaArrow}${formatDelta(Math.abs(deltaNum))} (24h)`
      : 'stable';

    const barColor = m.probability >= 60 ? '#ef4444' : m.probability >= 30 ? '#ff9800' : '#4caf50';

    const velocityText = probabilityHistory.has(m.title) && (probabilityHistory.get(m.title)?.length ?? 0) >= 2
      ? formatVelocity(m.velocity)
      : 'calculating...';

    const signalDesc = m.isElevated
      ? `ELEVATED \u2014 triggers early_warning \u00D7${(1.0 + m.velocity / VELOCITY_THRESHOLDS.warning * m.relevance.weight).toFixed(1)}`
      : m.signalLevel === 'declining'
        ? 'DECLINING \u2014 risk decreasing'
        : 'NORMAL \u2014 within baseline fluctuation';

    const tierLabel = `T${m.relevance.tier}`;

    return `
      <div class="${cardClass}">
        <div class="pred-card-status ${statusClass}">${statusIcon} ${statusText}</div>
        <div class="pred-card-question">${escapeHtml(m.title)}</div>
        <div class="pred-prob-row">
          <span class="pred-prob-text">${escapeHtml(probText)}</span>
          <span class="pred-prob-delta ${deltaClass}">${escapeHtml(deltaDisplay)}</span>
        </div>
        <div class="pred-bar-outer">
          <div class="pred-bar-inner" style="width:${m.probability}%;background:${barColor};"></div>
        </div>
        <div class="pred-meta-row">
          <span>Vol: ${formatVolume(m.volume)}</span>
          <span>Velocity: ${escapeHtml(velocityText)}</span>
          <span style="opacity:0.5;">${tierLabel}</span>
        </div>
        <div class="pred-signal-label ${statusClass}">${escapeHtml(signalDesc)}</div>
      </div>`;
  }

  // ── Compact view ───────────────────────────────────────────────

  private renderCompact(): string {
    const rows = this.trackedMarkets.slice(0, 8).map(m => {
      const icon = m.isElevated ? '\u26A1' : '\u25CF';
      const statusClass = `pred-status-${m.signalLevel}`;
      const deltaClass = m.delta24h > 0 ? 'pred-delta-up' : m.delta24h < 0 ? 'pred-delta-down' : 'pred-delta-flat';

      // Truncate title for compact view
      const shortTitle = m.title.length > 40 ? m.title.substring(0, 37) + '...' : m.title;

      return `
        <div class="pred-compact-row">
          <span class="pred-compact-status ${statusClass}">${icon}</span>
          <span class="pred-compact-title" title="${escapeHtml(m.title)}">${escapeHtml(shortTitle)}</span>
          <span class="pred-compact-prob">${Math.round(m.probability)}%</span>
          <span class="pred-compact-delta ${deltaClass}">${formatDelta(m.delta24h)}</span>
          <span class="pred-compact-vol">${formatVolume(m.volume)}</span>
        </div>`;
    }).join('');

    return `<div style="padding:2px 0;">${rows}</div>`;
  }

  // ── Early warning summary ──────────────────────────────────────

  private renderEWSummary(): string {
    const ewClass = this.earlyWarningMultiplier > 1.0 ? 'pred-ew-value pred-ew-elevated' : 'pred-ew-value pred-ew-nominal';
    const ewText = `\u00D7${this.earlyWarningMultiplier.toFixed(1)}`;
    const countText = this.activeSignalCount > 0
      ? `(${this.activeSignalCount} market${this.activeSignalCount > 1 ? 's' : ''} elevated)`
      : '(no elevated markets)';

    const syncAgo = this.lastSyncTime
      ? `${Math.round((Date.now() - this.lastSyncTime) / 1000)}s ago`
      : 'pending';

    return `
      <div class="pred-ew-summary">
        <div class="pred-ew-title">EARLY WARNING MULTIPLIER \u2192 CII PANEL</div>
        <div>
          Current: <span class="${ewClass}">${ewText}</span>
          <span style="color:#666;margin-left:4px;">${escapeHtml(countText)}</span>
        </div>
        <div class="pred-ew-formula">
          Formula: max(1.0, 1.0 + \u03A3(velocity_norm \u00D7 relevance_weight \u00D7 vol_confidence))
        </div>
        <div class="pred-ew-sync">
          Feeding: R_geo early_warning_multiplier &middot; Last sync: ${escapeHtml(syncAgo)}
        </div>
      </div>`;
  }

  // ── Footer ─────────────────────────────────────────────────────

  private renderFooter(): string {
    const totalTracked = this.trackedMarkets.length;
    const t1 = this.trackedMarkets.filter(m => m.relevance.tier === 1).length;
    const t2 = this.trackedMarkets.filter(m => m.relevance.tier === 2).length;
    const t3 = this.trackedMarkets.filter(m => m.relevance.tier === 3).length;
    const t4 = this.trackedMarkets.filter(m => m.relevance.tier === 4).length;

    return `
      <div class="pred-footer">
        <div class="pred-footer-row">
          <span>Scanned: ${this.totalMarketsScanned} markets \u2192 ${totalTracked} relevant</span>
        </div>
        <div class="pred-footer-row">
          <span>Tiers: T1:${t1} T2:${t2} T3:${t3} T4:${t4}</span>
          <span>\u00B7 Velocity window: 6h</span>
        </div>
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
