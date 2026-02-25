/**
 * CII Score Panel — Country Instability Index for GATRA Cyber variant.
 *
 * Shows CII scores for Indonesia and ASEAN/Pacific neighbors,
 * deviation from baseline (which feeds GATRA's RL reward signal),
 * and R_geo impact on the autonomous SOC defensive posture.
 *
 * Data flow:
 *   country-instability.ts  →  calculateCII()  →  this panel
 *   + R_geo computed locally from CII deviation × proximity weight
 *
 * Refresh: listens for 'focal-points-ready' event + 5-min auto-refresh.
 */

import { Panel } from '@/components/Panel';
import { getCSSColor } from '@/utils/theme-colors';
import { calculateCII, type CountryScore, getPreviousScores } from '@/services/country-instability';
import { h, replaceChildren, rawHtml } from '@/utils/dom-utils';

// ── Priority countries with proximity weights ──────────────────────

interface PriorityCountry {
  code: string;
  name: string;
  flag: string;
  proximityWeight: number;
  regimeType: 'democratic' | 'hybrid' | 'authoritarian' | 'military';
}

const PRIORITY_COUNTRIES: PriorityCountry[] = [
  { code: 'ID', name: 'Indonesia',        flag: '\u{1F1EE}\u{1F1E9}', proximityWeight: 1.00, regimeType: 'democratic' },
  { code: 'SG', name: 'Singapore',        flag: '\u{1F1F8}\u{1F1EC}', proximityWeight: 0.90, regimeType: 'hybrid' },
  { code: 'MY', name: 'Malaysia',         flag: '\u{1F1F2}\u{1F1FE}', proximityWeight: 0.85, regimeType: 'hybrid' },
  { code: 'PH', name: 'Philippines',      flag: '\u{1F1F5}\u{1F1ED}', proximityWeight: 0.80, regimeType: 'democratic' },
  { code: 'TH', name: 'Thailand',         flag: '\u{1F1F9}\u{1F1ED}', proximityWeight: 0.70, regimeType: 'hybrid' },
  { code: 'VN', name: 'Vietnam',          flag: '\u{1F1FB}\u{1F1F3}', proximityWeight: 0.65, regimeType: 'authoritarian' },
  { code: 'AU', name: 'Australia',        flag: '\u{1F1E6}\u{1F1FA}', proximityWeight: 0.60, regimeType: 'democratic' },
  { code: 'PG', name: 'Papua New Guinea', flag: '\u{1F1F5}\u{1F1EC}', proximityWeight: 0.55, regimeType: 'democratic' },
  { code: 'MM', name: 'Myanmar',          flag: '\u{1F1F2}\u{1F1F2}', proximityWeight: 0.50, regimeType: 'military' },
  { code: 'CN', name: 'China',            flag: '\u{1F1E8}\u{1F1F3}', proximityWeight: 0.40, regimeType: 'authoritarian' },
];

const INDONESIA_CODE = 'ID';

// ── R_geo calculation ──────────────────────────────────────────────

interface RGeoConfig {
  alpha: number;
  deviationThreshold: number;
  earlyWarningMultiplier: number;
}

interface RGeoResult {
  value: number;
  isActive: boolean;
  components: {
    alpha: number;
    ciiDeviation: number;
    proximityWeight: number;
    earlyWarningMultiplier: number;
  };
}

const DEFAULT_RGEO_CONFIG: RGeoConfig = {
  alpha: 0.15,
  deviationThreshold: 1.5,
  earlyWarningMultiplier: 1.0,
};

function computeRGeo(
  ciiScore: number,
  baselineMean: number,
  baselineStd: number,
  proximityWeight: number,
  config: RGeoConfig = DEFAULT_RGEO_CONFIG,
): RGeoResult {
  const std = Math.max(baselineStd, 0.01);
  const deviation = (ciiScore - baselineMean) / std;
  const value = config.alpha * deviation * proximityWeight * config.earlyWarningMultiplier;
  return {
    value,
    isActive: Math.abs(deviation) > config.deviationThreshold,
    components: {
      alpha: config.alpha,
      ciiDeviation: deviation,
      proximityWeight,
      earlyWarningMultiplier: config.earlyWarningMultiplier,
    },
  };
}

// ── Score history for sparklines ───────────────────────────────────

const scoreHistory = new Map<string, { time: number; score: number }[]>();
const MAX_HISTORY = 48; // ~24h at 30-min intervals

function recordScore(code: string, score: number): void {
  const list = scoreHistory.get(code) || [];
  list.push({ time: Date.now(), score });
  if (list.length > MAX_HISTORY) list.splice(0, list.length - MAX_HISTORY);
  scoreHistory.set(code, list);
}

function buildSparklineSVG(code: string, width = 80, height = 20): string {
  const list = scoreHistory.get(code);
  if (!list || list.length < 2) return '';

  const scores = list.map(h => h.score);
  const min = Math.max(0, Math.min(...scores) - 5);
  const max = Math.min(100, Math.max(...scores) + 5);
  const range = max - min || 1;

  const points = scores.map((s, i) => {
    const x = (i / (scores.length - 1)) * width;
    const y = height - ((s - min) / range) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  const last = scores[scores.length - 1]!;
  const color = last >= 60 ? '#ef4444' : last >= 30 ? '#eab308' : '#22c55e';

  return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" style="vertical-align:middle">
    <polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="${width}" cy="${height - ((last - min) / range) * height}" r="2" fill="${color}"/>
  </svg>`;
}

// ── Severity helpers ───────────────────────────────────────────────

function getScoreColor(score: number): string {
  if (score >= 80) return getCSSColor('--semantic-critical');
  if (score >= 60) return getCSSColor('--semantic-high');
  if (score >= 30) return getCSSColor('--semantic-elevated');
  return getCSSColor('--semantic-normal');
}

function getTrendArrow(change: number): { symbol: string; className: string } {
  if (change >= 3) return { symbol: `\u25B2 +${change.toFixed(1)}`, className: 'cii-trend-up' };
  if (change <= -3) return { symbol: `\u25BC ${change.toFixed(1)}`, className: 'cii-trend-down' };
  return { symbol: `\u25AC ${change >= 0 ? '+' : ''}${change.toFixed(1)}`, className: 'cii-trend-stable' };
}

function formatRegime(type: string): string {
  switch (type) {
    case 'democratic': return 'Democratic (log scale)';
    case 'hybrid': return 'Hybrid';
    case 'authoritarian': return 'Authoritarian (linear)';
    case 'military': return 'Military';
    default: return type;
  }
}

// ── Welford baseline approximation ─────────────────────────────────
// Since we don't have persistent Welford stats client-side,
// approximate baseline from previousScores + running history.

function getBaseline(code: string, currentScore: number): { mean: number; std: number } {
  const prev = getPreviousScores().get(code);
  const hist = scoreHistory.get(code);

  if (hist && hist.length >= 3) {
    const scores = hist.map(h => h.score);
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((a, s) => a + (s - mean) ** 2, 0) / scores.length;
    return { mean, std: Math.sqrt(variance) };
  }

  // Fallback: use previous score as baseline proxy
  const mean = prev ?? currentScore;
  const std = Math.abs(currentScore - mean) > 0 ? Math.abs(currentScore - mean) * 0.8 : 5;
  return { mean, std };
}

// ── Inject CSS ─────────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const style = document.createElement('style');
  style.textContent = `
/* CII Score Panel */
.cii-score-panel { font-size: 11px; line-height: 1.4; }

.cii-score-header {
  display: flex; align-items: center; gap: 6px;
  padding: 6px 0 4px; margin-bottom: 4px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.cii-score-header .cii-label { font-weight: 600; font-size: 10px; letter-spacing: 0.5px; text-transform: uppercase; color: #ccc; }
.cii-badge {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 600; letter-spacing: 0.3px;
}
.cii-badge-live { background: rgba(34,197,94,0.15); color: #22c55e; }
.cii-badge-live::before { content: ''; width: 5px; height: 5px; border-radius: 50%; background: #22c55e; animation: cii-pulse 2s infinite; }
.cii-badge-rl { background: rgba(100,100,100,0.2); color: #888; }
.cii-badge-rl.active { background: rgba(245,158,11,0.15); color: #f59e0b; }
.cii-badge-rl.critical { background: rgba(239,68,68,0.15); color: #ef4444; }

@keyframes cii-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Indonesia focus card */
.cii-focus {
  background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 8px; margin-bottom: 6px;
}
.cii-focus-top { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
.cii-focus-flag { font-size: 18px; line-height: 1; }
.cii-focus-name { font-weight: 600; font-size: 12px; color: #e0e0e0; flex: 1; }
.cii-focus-score { font-size: 20px; font-weight: 700; font-family: 'SF Mono', monospace; }
.cii-focus-delta { font-size: 11px; font-weight: 500; }

.cii-trend-up { color: #ef4444; }
.cii-trend-down { color: #22c55e; }
.cii-trend-stable { color: #888; }

.cii-bar-outer {
  height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px;
  margin: 4px 0; overflow: hidden;
}
.cii-bar-inner { height: 100%; border-radius: 2px; transition: width 0.6s ease; }

.cii-focus-meta { display: flex; gap: 8px; font-size: 10px; color: #888; margin-top: 2px; }
.cii-focus-meta span { white-space: nowrap; }

/* R_geo impact block */
.cii-rgeo {
  margin-top: 6px; padding: 5px 7px;
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.04);
  border-radius: 3px; font-size: 10px;
}
.cii-rgeo-status { display: flex; align-items: center; gap: 5px; margin-bottom: 2px; }
.cii-rgeo-label { font-weight: 600; color: #aaa; }
.cii-rgeo-value {
  font-weight: 700; font-size: 10px; padding: 0 5px; border-radius: 2px;
}
.cii-rgeo-active { background: rgba(245,158,11,0.15); color: #f59e0b; }
.cii-rgeo-nominal { background: rgba(34,197,94,0.1); color: #22c55e; }
.cii-rgeo-formula { color: #666; font-family: 'SF Mono', monospace; font-size: 9px; margin-top: 1px; }
.cii-rgeo-result { color: #ccc; font-family: 'SF Mono', monospace; font-size: 9px; }

/* Sparkline row */
.cii-spark-row { display: flex; align-items: center; gap: 6px; margin-top: 4px; }
.cii-spark-label { font-size: 9px; color: #666; text-transform: uppercase; }

/* Regional grid */
.cii-grid {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 3px;
  margin-top: 6px;
}
.cii-grid-cell {
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.04);
  border-radius: 3px; padding: 5px 6px; min-width: 0;
}
.cii-grid-cell:hover { background: rgba(255,255,255,0.05); }
.cii-cell-top { display: flex; align-items: center; gap: 3px; margin-bottom: 2px; }
.cii-cell-flag { font-size: 12px; }
.cii-cell-code { font-weight: 600; font-size: 10px; color: #ccc; }
.cii-cell-score { font-weight: 700; font-size: 11px; font-family: 'SF Mono', monospace; margin-left: auto; }
.cii-cell-delta { font-size: 9px; font-weight: 500; }
.cii-cell-bar { height: 2px; background: rgba(255,255,255,0.06); border-radius: 1px; margin-top: 2px; overflow: hidden; }
.cii-cell-bar-fill { height: 100%; border-radius: 1px; transition: width 0.6s ease; }

/* RL footer */
.cii-footer {
  margin-top: 6px; padding-top: 5px;
  border-top: 1px solid rgba(255,255,255,0.06);
  font-size: 9px; color: #666; line-height: 1.5;
}
.cii-footer-row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.cii-footer-obj {
  display: inline-block; padding: 0 4px; border-radius: 2px;
  background: rgba(255,255,255,0.04); color: #888; font-family: 'SF Mono', monospace;
}
.cii-footer-obj.active { background: rgba(34,197,94,0.1); color: #22c55e; }
  `;
  document.head.appendChild(style);
}

// ── Panel class ────────────────────────────────────────────────────

export class CiiScorePanel extends Panel {
  private scores: CountryScore[] = [];
  private rGeo: RGeoResult | null = null;
  private rGeoConfig: RGeoConfig = { ...DEFAULT_RGEO_CONFIG };
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private lastUpdate: Date | null = null;
  private focalPointsReady = false;

  constructor() {
    super({
      id: 'cii-score',
      title: 'CII Monitor',
      infoTooltip: 'Country Instability Index — tracks geopolitical risk for Indonesia and ASEAN neighbors. Deviation from baseline feeds GATRA\'s reinforcement learning reward signal (R_geo).',
    });
    injectCSS();
    this.showLoading();
    this.init();
  }

  private init(): void {
    // Listen for CII data readiness
    window.addEventListener('focal-points-ready', () => {
      this.focalPointsReady = true;
      this.refresh();
    });

    // Listen for early warning multiplier from Prediction Signals panel
    window.addEventListener('gatra-early-warning-update', ((e: CustomEvent) => {
      const { multiplier } = e.detail as { multiplier: number };
      if (typeof multiplier === 'number' && multiplier >= 1.0) {
        this.rGeoConfig = { ...this.rGeoConfig, earlyWarningMultiplier: multiplier };
        this.recomputeRGeo();
      }
    }) as EventListener);

    // Auto-refresh every 5 minutes
    this.refreshTimer = setInterval(() => this.refresh(), 5 * 60 * 1000);

    // Initial attempt after short delay (data may already be loaded)
    setTimeout(() => this.refresh(), 3000);
  }

  /** Re-compute R_geo with updated config (e.g. after early warning multiplier change). */
  private recomputeRGeo(): void {
    const idScore = this.scores.find(s => s.code === INDONESIA_CODE);
    if (!idScore) return;
    const baseline = getBaseline(INDONESIA_CODE, idScore.score);
    const idConfig = PRIORITY_COUNTRIES.find(p => p.code === INDONESIA_CODE)!;
    this.rGeo = computeRGeo(idScore.score, baseline.mean, baseline.std, idConfig.proximityWeight, this.rGeoConfig);
    this.render();
  }

  public async refresh(): Promise<void> {
    try {
      const allScores = calculateCII();
      if (allScores.length === 0 && !this.focalPointsReady) {
        // No data yet — keep loading state
        return;
      }

      this.scores = allScores;
      this.lastUpdate = new Date();

      // Record history for sparklines
      for (const s of this.scores) {
        if (PRIORITY_COUNTRIES.some(p => p.code === s.code)) {
          recordScore(s.code, s.score);
        }
      }

      // Compute R_geo for Indonesia (using current config — may include early warning multiplier)
      const idScore = this.scores.find(s => s.code === INDONESIA_CODE);
      if (idScore) {
        const baseline = getBaseline(INDONESIA_CODE, idScore.score);
        const idConfig = PRIORITY_COUNTRIES.find(p => p.code === INDONESIA_CODE)!;
        this.rGeo = computeRGeo(idScore.score, baseline.mean, baseline.std, idConfig.proximityWeight, this.rGeoConfig);
      }

      // Update badge
      const activeCount = this.scores.filter(s => s.score > 0 && PRIORITY_COUNTRIES.some(p => p.code === s.code)).length;
      this.setDataBadge('live', `${activeCount} countries`);

      this.render();
    } catch (err) {
      console.error('[CiiScorePanel] refresh error:', err);
      this.showError('CII data unavailable');
    }
  }

  private render(): void {
    const container = h('div', { className: 'cii-score-panel' });

    // 1. Header bar
    container.appendChild(this.buildHeader());

    // 2. Indonesia focus card
    const idScore = this.scores.find(s => s.code === INDONESIA_CODE);
    if (idScore) {
      container.appendChild(this.buildFocusCard(idScore));
    }

    // 3. Regional grid
    container.appendChild(this.buildRegionalGrid());

    // 4. RL footer
    container.appendChild(this.buildFooter());

    replaceChildren(this.content, container);
  }

  // ── Sub-builders ─────────────────────────────────────────────────

  private buildHeader(): HTMLElement {
    const rlBadgeClass = this.rGeo?.isActive
      ? (Math.abs(this.rGeo.components.ciiDeviation) > 3 ? 'cii-badge cii-badge-rl critical' : 'cii-badge cii-badge-rl active')
      : 'cii-badge cii-badge-rl';

    return h('div', { className: 'cii-score-header' },
      h('span', { className: 'cii-label' }, 'CII MONITOR'),
      h('span', { className: 'cii-badge cii-badge-live' }, 'LIVE'),
      h('span', { className: rlBadgeClass }, this.rGeo?.isActive ? 'GATRA RL ACTIVE' : 'GATRA RL'),
    );
  }

  private buildFocusCard(score: CountryScore): HTMLElement {
    const idConfig = PRIORITY_COUNTRIES.find(p => p.code === INDONESIA_CODE)!;
    const color = getScoreColor(score.score);
    const baseline = getBaseline(INDONESIA_CODE, score.score);
    const deviation = score.score - baseline.mean;
    const trend = getTrendArrow(deviation);

    const card = h('div', { className: 'cii-focus' });

    // Top row: flag, name, score, delta
    card.appendChild(
      h('div', { className: 'cii-focus-top' },
        h('span', { className: 'cii-focus-flag' }, idConfig.flag),
        h('span', { className: 'cii-focus-name' }, 'INDONESIA'),
        h('span', { className: 'cii-focus-score', style: `color: ${color}` }, String(score.score)),
        h('span', { className: `cii-focus-delta ${trend.className}` }, `${trend.symbol} from baseline`),
      ),
    );

    // Progress bar
    card.appendChild(
      h('div', { className: 'cii-bar-outer' },
        h('div', { className: 'cii-bar-inner', style: `width: ${score.score}%; background: ${color};` }),
      ),
    );

    // Meta: regime type, level, components
    card.appendChild(
      h('div', { className: 'cii-focus-meta' },
        h('span', null, formatRegime(idConfig.regimeType)),
        h('span', null, `U:${score.components.unrest} C:${score.components.conflict} S:${score.components.security} I:${score.components.information}`),
      ),
    );

    // Sparkline
    const sparkSvg = buildSparklineSVG(INDONESIA_CODE);
    if (sparkSvg) {
      card.appendChild(
        h('div', { className: 'cii-spark-row' },
          h('span', { className: 'cii-spark-label' }, 'TREND'),
          rawHtml(sparkSvg),
        ),
      );
    }

    // R_geo impact block
    if (this.rGeo) {
      card.appendChild(this.buildRGeoBlock(this.rGeo));
    }

    return card;
  }

  private buildRGeoBlock(rGeo: RGeoResult): HTMLElement {
    const { alpha, ciiDeviation, proximityWeight, earlyWarningMultiplier } = rGeo.components;
    const statusClass = rGeo.isActive ? 'cii-rgeo-value cii-rgeo-active' : 'cii-rgeo-value cii-rgeo-nominal';
    const statusLabel = rGeo.isActive ? 'ACTIVE' : 'NOMINAL';

    return h('div', { className: 'cii-rgeo' },
      h('div', { className: 'cii-rgeo-status' },
        h('span', { className: 'cii-rgeo-label' }, 'R_geo Impact:'),
        h('span', { className: statusClass }, statusLabel),
      ),
      h('div', { className: 'cii-rgeo-formula' },
        `\u03B1=${alpha} \u00D7 dev=${ciiDeviation.toFixed(2)} \u00D7 prox=${proximityWeight} \u00D7 ew=${earlyWarningMultiplier}`,
      ),
      h('div', { className: 'cii-rgeo-result' },
        `= ${rGeo.value.toFixed(4)} reward adjustment`,
      ),
    );
  }

  private buildRegionalGrid(): HTMLElement {
    const grid = h('div', { className: 'cii-grid' });

    // Get neighbors (exclude Indonesia — it's the focus card)
    const neighbors = PRIORITY_COUNTRIES.filter(p => p.code !== INDONESIA_CODE);

    for (const country of neighbors) {
      const score = this.scores.find(s => s.code === country.code);
      const cii = score?.score ?? 0;
      const color = getScoreColor(cii);
      const baseline = getBaseline(country.code, cii);
      const deviation = cii - baseline.mean;
      const trend = getTrendArrow(deviation);

      const cell = h('div', { className: 'cii-grid-cell' },
        h('div', { className: 'cii-cell-top' },
          h('span', { className: 'cii-cell-flag' }, country.flag),
          h('span', { className: 'cii-cell-code' }, country.code),
          h('span', { className: `cii-cell-score`, style: `color: ${color}` }, String(cii)),
        ),
        h('div', { className: `cii-cell-delta ${trend.className}` }, trend.symbol),
        h('div', { className: 'cii-cell-bar' },
          h('div', { className: 'cii-cell-bar-fill', style: `width: ${cii}%; background: ${color};` }),
        ),
      );

      grid.appendChild(cell);
    }

    return grid;
  }

  private buildFooter(): HTMLElement {
    const rlStatus = this.rGeo?.isActive ? 'Multi-objective ACTIVE' : 'Multi-objective standby';
    const lastStr = this.lastUpdate
      ? `${Math.round((Date.now() - this.lastUpdate.getTime()) / 60000)}m ago`
      : 'pending';

    return h('div', { className: 'cii-footer' },
      h('div', { className: 'cii-footer-row' },
        h('span', null, `RL STATUS: ${rlStatus}`),
      ),
      h('div', { className: 'cii-footer-row' },
        h('span', null, 'Objectives:'),
        h('span', { className: `cii-footer-obj ${this.rGeo?.isActive ? 'active' : ''}` }, 'detection_acc'),
        h('span', { className: `cii-footer-obj ${this.rGeo?.isActive ? 'active' : ''}` }, 'response_time'),
        h('span', { className: `cii-footer-obj ${this.rGeo?.isActive ? 'active' : ''}` }, 'geo_context'),
      ),
      h('div', { className: 'cii-footer-row' },
        h('span', null, `Last CII\u2192RL update: ${lastStr}`),
        h('span', null, 'Baseline: 30d Welford'),
      ),
    );
  }

  // ── Lifecycle ────────────────────────────────────────────────────

  public destroy(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    super.destroy();
  }
}
