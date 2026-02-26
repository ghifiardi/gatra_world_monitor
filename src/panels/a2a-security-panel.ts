/**
 * A2A Security Monitor Panel — monitors Agent-to-Agent protocol traffic
 * as a threat surface within the GATRA Cyber dashboard.
 *
 * Shows agent registry, trust scores, live traffic feed, threat summary,
 * and CII-aware trust policies. Integrates with CII panel for dynamic
 * policy adjustments and dispatches threat events to GATRA SOC.
 *
 * Data flow:
 *   a2a-security.ts  →  mock traffic generator  →  this panel
 *   CII panel events  →  trust policy updates   →  agent status changes
 *   A2A threats       →  gatra-a2a-threat event  →  SOC alert feed
 */

import { Panel } from '@/components/Panel';
import { h, replaceChildren } from '@/utils/dom-utils';
import {
  generateTrafficEvent,
  pushTrafficEvent,
  getAgentRegistry,
  getTrafficLog,
  getThreatSummary,
  getRegistryCounts,
  getTrustPolicyForRegion,
  getRegionCiiScores,
  updateRegionCii,
} from '@/services/a2a-security';
import type { A2aTrafficEvent } from '@/services/a2a-security';

// ── Inject CSS ─────────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const style = document.createElement('style');
  style.textContent = `
/* A2A Security Monitor Panel */
.a2a-panel { font-size: 11px; line-height: 1.4; }

.a2a-header {
  display: flex; align-items: center; gap: 6px;
  padding: 6px 0 4px; margin-bottom: 6px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.a2a-header-label { font-weight: 600; font-size: 10px; letter-spacing: 0.5px; text-transform: uppercase; color: #ccc; }
.a2a-badge {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 1px 6px; border-radius: 3px;
  font-size: 9px; font-weight: 600; letter-spacing: 0.3px;
}
.a2a-badge-active { background: rgba(34,197,94,0.15); color: #22c55e; }
.a2a-badge-active::before { content: ''; width: 5px; height: 5px; border-radius: 50%; background: #22c55e; animation: a2a-pulse 2s infinite; }
.a2a-badge-count { background: rgba(100,100,100,0.2); color: #888; }
@keyframes a2a-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Two-column layout for registry + trust */
.a2a-columns {
  display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 6px;
}

/* Registry card */
.a2a-section {
  background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 6px 8px;
}
.a2a-section-title {
  font-weight: 600; font-size: 9px; letter-spacing: 0.5px;
  text-transform: uppercase; color: #888; margin-bottom: 4px;
}
.a2a-reg-row {
  display: flex; align-items: center; gap: 4px;
  font-size: 10px; padding: 1px 0;
}
.a2a-reg-count { font-weight: 700; font-size: 12px; color: #e0e0e0; min-width: 18px; }

/* Trust score bars */
.a2a-trust-row {
  display: flex; align-items: center; gap: 4px;
  padding: 2px 0; font-size: 10px;
}
.a2a-trust-name {
  width: 100px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  color: #ccc; font-family: 'SF Mono', monospace; font-size: 9px;
}
.a2a-trust-bar-outer {
  flex: 1; height: 6px; background: rgba(255,255,255,0.06);
  border-radius: 3px; overflow: hidden;
}
.a2a-trust-bar-inner { height: 100%; border-radius: 3px; transition: width 0.6s ease; }
.a2a-trust-val {
  min-width: 22px; text-align: right;
  font-weight: 700; font-size: 10px; font-family: 'SF Mono', monospace;
}
.a2a-trust-self { background: rgba(34,197,94,0.06); border-radius: 2px; padding: 1px 2px; }
.a2a-trust-self .a2a-trust-name { color: #22c55e; font-weight: 600; }
.a2a-card-link {
  font-size: 9px; color: #3b82f6; text-decoration: none;
  font-family: 'SF Mono', monospace; display: block; padding: 3px 0 0;
}
.a2a-card-link:hover { text-decoration: underline; }

/* Card validator */
.a2a-validator {
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 6px 8px; margin-bottom: 6px;
}
.a2a-validator-row {
  display: flex; align-items: center; gap: 4px;
  font-size: 10px; padding: 2px 0;
}
.a2a-validator-name {
  flex: 1; color: #ccc; font-family: 'SF Mono', monospace; font-size: 9px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.a2a-validate-btn {
  background: rgba(59,130,246,0.15); color: #3b82f6;
  border: 1px solid rgba(59,130,246,0.3); border-radius: 3px;
  font-size: 8px; font-weight: 600; letter-spacing: 0.3px;
  padding: 1px 6px; cursor: pointer; text-transform: uppercase;
  transition: background 0.15s;
}
.a2a-validate-btn:hover { background: rgba(59,130,246,0.25); }
.a2a-validate-btn:disabled { opacity: 0.4; cursor: default; }
.a2a-validate-btn.validating { color: #eab308; border-color: rgba(234,179,8,0.3); background: rgba(234,179,8,0.1); }

.a2a-val-result {
  margin-top: 4px; padding: 4px 6px;
  background: rgba(0,0,0,0.2); border-radius: 3px;
  font-size: 9px; font-family: 'SF Mono', monospace;
  max-height: 140px; overflow-y: auto;
}
.a2a-val-result::-webkit-scrollbar { width: 3px; }
.a2a-val-result::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

.a2a-val-verdict {
  font-weight: 700; font-size: 10px; padding: 2px 0;
}
.a2a-val-verdict-valid { color: #22c55e; }
.a2a-val-verdict-valid_with_warnings { color: #eab308; }
.a2a-val-verdict-invalid { color: #ef4444; }

.a2a-val-summary {
  display: flex; gap: 8px; font-size: 9px; padding: 2px 0 4px;
  border-bottom: 1px solid rgba(255,255,255,0.04); margin-bottom: 3px;
}
.a2a-val-check {
  display: flex; align-items: flex-start; gap: 4px;
  padding: 1px 0; font-size: 9px; line-height: 1.3;
}
.a2a-val-check-icon { flex-shrink: 0; width: 12px; text-align: center; }
.a2a-val-check-msg { color: #aaa; }
.a2a-val-check-fail .a2a-val-check-msg { color: #ef4444; }
.a2a-val-check-warn .a2a-val-check-msg { color: #eab308; }
.a2a-val-check-pass .a2a-val-check-msg { color: #666; }

.a2a-val-input-row {
  display: flex; gap: 4px; margin-top: 4px;
}
.a2a-val-input {
  flex: 1; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 3px; color: #ccc; font-size: 9px; font-family: 'SF Mono', monospace;
  padding: 3px 6px; outline: none;
}
.a2a-val-input::placeholder { color: #555; }
.a2a-val-input:focus { border-color: rgba(59,130,246,0.5); }

/* Traffic feed */
.a2a-traffic {
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 6px 8px; margin-bottom: 6px;
  max-height: 200px; overflow-y: auto;
}
.a2a-traffic::-webkit-scrollbar { width: 4px; }
.a2a-traffic::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

.a2a-traffic-evt {
  padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.03);
  cursor: pointer; transition: background 0.15s;
}
.a2a-traffic-evt:hover { background: rgba(255,255,255,0.03); }
.a2a-traffic-evt:last-child { border-bottom: none; }
.a2a-traffic-top {
  display: flex; align-items: center; gap: 4px; font-size: 10px;
}
.a2a-traffic-time { color: #555; font-size: 9px; font-family: 'SF Mono', monospace; min-width: 36px; }
.a2a-traffic-route { color: #ccc; font-family: 'SF Mono', monospace; font-size: 9px; }
.a2a-traffic-arrow { color: #555; }
.a2a-traffic-skill {
  margin-left: auto; color: #888; font-size: 9px;
  font-family: 'SF Mono', monospace;
}
.a2a-traffic-detail {
  display: flex; align-items: center; gap: 6px;
  font-size: 9px; color: #666; padding-left: 40px; margin-top: 1px;
}
.a2a-verdict-clean { color: #22c55e; }
.a2a-verdict-suspicious { color: #eab308; }
.a2a-verdict-malicious { color: #ef4444; }
.a2a-verdict-blocked { color: #ef4444; }

.a2a-new-evt {
  animation: a2a-flash 1s ease-out;
}
@keyframes a2a-flash {
  0% { background: rgba(34,197,94,0.15); }
  100% { background: transparent; }
}

/* Threat summary */
.a2a-threat-grid {
  display: grid; grid-template-columns: 1fr; gap: 2px;
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 6px 8px; margin-bottom: 6px;
}
.a2a-threat-row {
  display: flex; align-items: center; gap: 6px;
  font-size: 10px; padding: 2px 0;
}
.a2a-threat-label { flex: 1; color: #aaa; }
.a2a-threat-count { min-width: 24px; text-align: right; font-weight: 700; font-family: 'SF Mono', monospace; color: #e0e0e0; }
.a2a-threat-minibar {
  width: 80px; height: 4px; background: rgba(255,255,255,0.06);
  border-radius: 2px; overflow: hidden;
}
.a2a-threat-minibar-fill { height: 100%; border-radius: 2px; }

/* CII trust policy */
.a2a-policy {
  background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
  border-radius: 4px; padding: 6px 8px;
}
.a2a-policy-row {
  display: flex; align-items: center; gap: 6px;
  font-size: 10px; padding: 2px 0;
}
.a2a-policy-country { font-weight: 600; color: #ccc; min-width: 80px; }
.a2a-policy-cii { font-family: 'SF Mono', monospace; font-weight: 600; min-width: 36px; }
.a2a-policy-level {
  padding: 0 5px; border-radius: 2px;
  font-size: 9px; font-weight: 600; letter-spacing: 0.3px;
}
.a2a-policy-standard { background: rgba(34,197,94,0.1); color: #22c55e; }
.a2a-policy-elevated { background: rgba(245,158,11,0.15); color: #f59e0b; }
.a2a-policy-critical { background: rgba(239,68,68,0.15); color: #ef4444; }
.a2a-policy-note { font-size: 9px; color: #666; padding-top: 4px; border-top: 1px solid rgba(255,255,255,0.04); margin-top: 4px; }
  `;
  document.head.appendChild(style);
}

// ── Verdict helpers ──────────────────────────────────────────────

function verdictIcon(v: string): string {
  switch (v) {
    case 'clean': return '\u2705';
    case 'suspicious': return '\u26A0\uFE0F';
    case 'malicious': return '\uD83D\uDEAB';
    case 'blocked': return '\uD83D\uDEAB';
    default: return '\u2753';
  }
}

function trustColor(score: number): string {
  if (score >= 70) return '#22c55e';
  if (score >= 40) return '#eab308';
  return '#ef4444';
}

function statusIcon(status: string): string {
  switch (status) {
    case 'verified': return '\u2705';
    case 'pending': return '\u23F3';
    case 'blocked': return '\uD83D\uDEAB';
    case 'degraded': return '\u26A0\uFE0F';
    default: return '\u2753';
  }
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// ── Panel class ──────────────────────────────────────────────────

interface ValidationResult {
  url: string;
  verdict: 'valid' | 'valid_with_warnings' | 'invalid';
  summary: { total: number; pass: number; fail: number; warn: number; info: number };
  fetchMs: number;
  card: { name: string; version: string; skillCount: number; provider: string | null } | null;
  checks: { id: string; category: string; severity: string; message: string; detail?: string }[];
}

export class A2aSecurityPanel extends Panel {
  private trafficTimer: ReturnType<typeof setInterval> | null = null;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private validationResult: ValidationResult | null = null;
  private validatingUrl: string | null = null;

  constructor() {
    super({
      id: 'a2a-security',
      title: 'A2A Security Monitor',
      infoTooltip: 'Agent-to-Agent protocol security monitor. Tracks registered external agents, trust scores, live A2A traffic, prompt injection detection, and CII-aware trust policies.',
    });
    injectCSS();
    this.showLoading();
    this.init();
  }

  private init(): void {
    // Listen for CII updates to adjust trust policies
    window.addEventListener('gatra-cii-update', ((e: CustomEvent) => {
      const { country, cii } = e.detail as { country: string; cii: number };
      if (typeof country === 'string' && typeof cii === 'number') {
        updateRegionCii(country, cii);
        this.render();
      }
    }) as EventListener);

    // Generate initial traffic backfill
    for (let i = 0; i < 15; i++) {
      const evt = generateTrafficEvent();
      evt.timestamp = Date.now() - (15 - i) * 8000; // Spread over last 2 min
      pushTrafficEvent(evt);
    }

    // Stream new traffic events every 5-15 seconds
    this.scheduleNextTraffic();

    // Full re-render every 30 seconds
    this.refreshTimer = setInterval(() => this.refresh(), 30000);

    // Initial render
    setTimeout(() => this.refresh(), 500);
  }

  private scheduleNextTraffic(): void {
    const delay = 5000 + Math.random() * 10000; // 5-15s
    this.trafficTimer = setTimeout(() => {
      const evt = generateTrafficEvent();
      pushTrafficEvent(evt);

      // Dispatch threat event if suspicious or worse
      if (evt.verdict !== 'clean') {
        window.dispatchEvent(new CustomEvent('gatra-a2a-threat', {
          detail: {
            type: evt.details.injectionDetected ? 'prompt_injection' : 'anomaly',
            agent: evt.sourceAgent,
            severity: evt.verdict === 'blocked' ? 'critical' : evt.verdict === 'suspicious' ? 'high' : 'medium',
            mitre: evt.details.mitreTechnique ?? 'T1557',
            trustDelta: evt.details.trustDelta ?? 0,
            skill: evt.skill,
            pattern: evt.details.injectionPattern,
          },
        }));
      }

      this.render();
      this.scheduleNextTraffic();
    }, delay);
  }

  public async refresh(): Promise<void> {
    try {
      const counts = getRegistryCounts();
      this.setDataBadge('live', `${counts.total} agents`);
      this.setCount(getTrafficLog().length);
      this.render();
    } catch (err) {
      console.error('[A2aSecurityPanel] refresh error:', err);
      this.showError('A2A data unavailable');
    }
  }

  private render(): void {
    const container = h('div', { className: 'a2a-panel' });

    container.appendChild(this.buildPanelHeader());
    container.appendChild(this.buildColumns());
    container.appendChild(this.buildCardValidator());
    container.appendChild(this.buildTrafficSection());
    container.appendChild(this.buildThreatSummary());
    container.appendChild(this.buildCiiPolicy());

    replaceChildren(this.content, container);
  }

  // ── Sub-builders ───────────────────────────────────────────────

  private buildPanelHeader(): HTMLElement {
    const counts = getRegistryCounts();
    const traffic = getTrafficLog();
    return h('div', { className: 'a2a-header' },
      h('span', { className: 'a2a-header-label' }, 'A2A SECURITY MONITOR'),
      h('span', { className: 'a2a-badge a2a-badge-active' }, 'ACTIVE'),
      h('span', { className: 'a2a-badge a2a-badge-count' }, `\uD83D\uDD17 ${counts.total}`),
      h('span', { className: 'a2a-badge a2a-badge-count' }, `${traffic.length} events`),
    );
  }

  private buildColumns(): HTMLElement {
    return h('div', { className: 'a2a-columns' },
      this.buildRegistryCard(),
      this.buildTrustScores(),
    );
  }

  private buildRegistryCard(): HTMLElement {
    const c = getRegistryCounts();
    return h('div', { className: 'a2a-section' },
      h('div', { className: 'a2a-section-title' }, 'AGENT REGISTRY'),
      h('div', { className: 'a2a-reg-row' },
        h('span', { className: 'a2a-reg-count' }, String(c.total)),
        h('span', null, 'Registered'),
      ),
      h('div', { className: 'a2a-reg-row' },
        h('span', { className: 'a2a-reg-count', style: 'color: #22c55e' }, String(c.verified)),
        h('span', null, `Verified ${statusIcon('verified')}`),
      ),
      h('div', { className: 'a2a-reg-row' },
        h('span', { className: 'a2a-reg-count', style: 'color: #eab308' }, String(c.pending)),
        h('span', null, `Pending ${statusIcon('pending')}`),
      ),
      h('div', { className: 'a2a-reg-row' },
        h('span', { className: 'a2a-reg-count', style: 'color: #ef4444' }, String(c.blocked + c.degraded)),
        h('span', null, `Blocked/Degraded ${statusIcon('blocked')}`),
      ),
      (() => {
        const link = h('a', {
          className: 'a2a-card-link',
          href: 'https://worldmonitor-gatra.vercel.app/.well-known/agent.json',
          target: '_blank',
          rel: 'noopener noreferrer',
        }, '\uD83D\uDCCB GATRA Agent Card \u2197');
        return link;
      })(),
    );
  }

  private buildTrustScores(): HTMLElement {
    const agents = getAgentRegistry()
      .filter(a => a.status !== 'blocked')
      .sort((a, b) => b.trustScore - a.trustScore)
      .slice(0, 6);

    const section = h('div', { className: 'a2a-section' },
      h('div', { className: 'a2a-section-title' }, 'TRUST SCORES'),
    );

    for (const agent of agents) {
      const color = trustColor(agent.trustScore);
      const isSelf = agent.cardId === 'gatra-soc';
      section.appendChild(
        h('div', { className: `a2a-trust-row${isSelf ? ' a2a-trust-self' : ''}` },
          h('span', { className: 'a2a-trust-name' }, `${isSelf ? '\u2B50 ' : ''}${agent.name}`),
          h('div', { className: 'a2a-trust-bar-outer' },
            h('div', { className: 'a2a-trust-bar-inner', style: `width: ${agent.trustScore}%; background: ${color};` }),
          ),
          h('span', { className: 'a2a-trust-val', style: `color: ${color}` }, String(agent.trustScore)),
        ),
      );
    }

    return section;
  }

  private buildCardValidator(): HTMLElement {
    const agents = getAgentRegistry();
    const section = h('div', null,
      h('div', { className: 'a2a-section-title', style: 'margin-bottom: 4px;' }, 'CARD VALIDATOR'),
    );

    const card = h('div', { className: 'a2a-validator' });

    // Show agents that have card URLs
    for (const agent of agents.slice(0, 5)) {
      const row = h('div', { className: 'a2a-validator-row' });
      row.appendChild(h('span', { className: 'a2a-validator-name' }, `${statusIcon(agent.status)} ${agent.name}`));

      const btn = h('button', {
        className: `a2a-validate-btn${this.validatingUrl === agent.url ? ' validating' : ''}`,
        disabled: this.validatingUrl !== null,
      }, this.validatingUrl === agent.url ? 'CHECKING...' : 'VALIDATE') as HTMLButtonElement;

      btn.addEventListener('click', () => this.validateCard(agent.url));
      row.appendChild(btn);
      card.appendChild(row);
    }

    // Custom URL input
    const inputRow = h('div', { className: 'a2a-val-input-row' });
    const input = h('input', {
      className: 'a2a-val-input',
      type: 'text',
      placeholder: 'https://example.com/.well-known/agent.json',
    }) as HTMLInputElement;
    const customBtn = h('button', {
      className: 'a2a-validate-btn',
      disabled: this.validatingUrl !== null,
    }, 'CHECK') as HTMLButtonElement;
    customBtn.addEventListener('click', () => {
      const url = input.value.trim();
      if (url) this.validateCard(url);
    });
    input.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter') {
        const url = input.value.trim();
        if (url) this.validateCard(url);
      }
    });
    inputRow.appendChild(input);
    inputRow.appendChild(customBtn);
    card.appendChild(inputRow);

    // Validation result
    if (this.validationResult) {
      card.appendChild(this.buildValidationResult(this.validationResult));
    }

    section.appendChild(card);
    return section;
  }

  private buildValidationResult(result: ValidationResult): HTMLElement {
    const container = h('div', { className: 'a2a-val-result' });

    // Verdict
    const verdictText = result.verdict === 'valid' ? '\u2705 VALID'
      : result.verdict === 'valid_with_warnings' ? '\u26A0\uFE0F VALID (warnings)'
      : '\u274C INVALID';
    container.appendChild(
      h('div', { className: `a2a-val-verdict a2a-val-verdict-${result.verdict}` }, verdictText),
    );

    // Card info
    if (result.card) {
      container.appendChild(
        h('div', { style: 'font-size: 9px; color: #aaa; padding: 1px 0;' },
          `${result.card.name} v${result.card.version} | ${result.card.skillCount} skills | ${result.fetchMs}ms`,
        ),
      );
    }

    // Summary counts
    const s = result.summary;
    container.appendChild(
      h('div', { className: 'a2a-val-summary' },
        h('span', { style: 'color: #22c55e;' }, `${s.pass} pass`),
        h('span', { style: 'color: #ef4444;' }, `${s.fail} fail`),
        h('span', { style: 'color: #eab308;' }, `${s.warn} warn`),
        h('span', { style: 'color: #888;' }, `${s.info} info`),
      ),
    );

    // Show failed and warning checks (skip passes to save space)
    const important = result.checks.filter(c => c.severity === 'fail' || c.severity === 'warn');
    for (const chk of important.slice(0, 12)) {
      const icon = chk.severity === 'fail' ? '\u274C' : '\u26A0\uFE0F';
      container.appendChild(
        h('div', { className: `a2a-val-check a2a-val-check-${chk.severity}` },
          h('span', { className: 'a2a-val-check-icon' }, icon),
          h('span', { className: 'a2a-val-check-msg' }, chk.message),
        ),
      );
    }

    // If all passed, show a few passes
    if (important.length === 0) {
      const passes = result.checks.filter(c => c.severity === 'pass').slice(0, 4);
      for (const chk of passes) {
        container.appendChild(
          h('div', { className: `a2a-val-check a2a-val-check-pass` },
            h('span', { className: 'a2a-val-check-icon' }, '\u2705'),
            h('span', { className: 'a2a-val-check-msg' }, chk.message),
          ),
        );
      }
    }

    return container;
  }

  private async validateCard(url: string): Promise<void> {
    if (this.validatingUrl) return;
    this.validatingUrl = url;
    this.validationResult = null;
    this.render();

    try {
      const apiUrl = `/api/a2a/validate-card?url=${encodeURIComponent(url)}`;
      const res = await fetch(apiUrl);
      if (res.ok) {
        this.validationResult = await res.json();
      } else {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        this.validationResult = {
          url,
          verdict: 'invalid',
          summary: { total: 1, pass: 0, fail: 1, warn: 0, info: 0 },
          fetchMs: 0,
          card: null,
          checks: [{ id: 'api-error', category: 'fetch', severity: 'fail', message: err.error || `Validator returned HTTP ${res.status}` }],
        };
      }
    } catch (err) {
      this.validationResult = {
        url,
        verdict: 'invalid',
        summary: { total: 1, pass: 0, fail: 1, warn: 0, info: 0 },
        fetchMs: 0,
        card: null,
        checks: [{ id: 'network-error', category: 'fetch', severity: 'fail', message: `Network error: ${String(err).slice(0, 100)}` }],
      };
    } finally {
      this.validatingUrl = null;
      this.render();
    }
  }

  private buildTrafficSection(): HTMLElement {
    const events = getTrafficLog().slice(0, 20);
    const section = h('div', null,
      h('div', { className: 'a2a-section-title', style: 'margin-bottom: 4px;' }, 'LIVE A2A TRAFFIC'),
    );

    const feed = h('div', { className: 'a2a-traffic' });

    for (let i = 0; i < events.length; i++) {
      const evt = events[i]!;
      feed.appendChild(this.buildTrafficEvent(evt, i === 0));
    }

    if (events.length === 0) {
      feed.appendChild(h('div', { style: 'color: #555; font-size: 10px; padding: 8px 0; text-align: center;' }, 'No traffic events yet...'));
    }

    section.appendChild(feed);
    return section;
  }

  private buildTrafficEvent(evt: A2aTrafficEvent, isNew: boolean): HTMLElement {
    const vClass = `a2a-verdict-${evt.verdict}`;
    const arrow = evt.direction === 'inbound' ? '\u2192' : '\u2190';

    const row = h('div', { className: `a2a-traffic-evt${isNew ? ' a2a-new-evt' : ''}` },
      h('div', { className: 'a2a-traffic-top' },
        h('span', { className: 'a2a-traffic-time' }, formatTime(evt.timestamp)),
        h('span', { className: 'a2a-traffic-route' }, evt.sourceAgent),
        h('span', { className: 'a2a-traffic-arrow' }, ` ${arrow} `),
        h('span', { className: 'a2a-traffic-route' }, evt.targetAgent),
        h('span', { className: 'a2a-traffic-skill' }, evt.skill),
      ),
      h('div', { className: 'a2a-traffic-detail' },
        h('span', { className: vClass }, `${verdictIcon(evt.verdict)} ${evt.verdict.toUpperCase()}`),
        evt.latencyMs > 0
          ? h('span', null, `latency: ${evt.latencyMs}ms`)
          : h('span', { style: 'color: #ef4444;' }, 'REJECTED'),
        evt.details.injectionPattern
          ? h('span', { style: 'color: #eab308;' }, evt.details.injectionPattern.slice(0, 40))
          : h('span'),
      ),
    );

    // Click to dispatch detail event (SOC COMMS can pick this up)
    row.addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('gatra-a2a-detail', { detail: evt }));
    });

    return row;
  }

  private buildThreatSummary(): HTMLElement {
    const summary = getThreatSummary();
    const maxVal = Math.max(
      summary.cardSpoofingAttempts,
      summary.promptInjectionsDetected,
      summary.sessionDriftAlerts,
      summary.trustDowngrades,
      summary.rateLimitTriggers,
      1,
    );

    const section = h('div', null,
      h('div', { className: 'a2a-section-title', style: 'margin-bottom: 4px;' }, `THREAT SUMMARY \u2014 ${summary.period}`),
    );

    const grid = h('div', { className: 'a2a-threat-grid' });

    const rows: [string, number, string][] = [
      ['Card Spoofing Attempts', summary.cardSpoofingAttempts, '#ef4444'],
      ['Prompt Injection Detected', summary.promptInjectionsDetected, '#f97316'],
      ['Session Drift Alerts', summary.sessionDriftAlerts, '#eab308'],
      ['Trust Downgrades', summary.trustDowngrades, '#a855f7'],
      ['Rate Limit Triggers', summary.rateLimitTriggers, '#3b82f6'],
    ];

    for (const [label, count, color] of rows) {
      const pct = Math.round((count / maxVal) * 100);
      grid.appendChild(
        h('div', { className: 'a2a-threat-row' },
          h('span', { className: 'a2a-threat-label' }, label),
          h('span', { className: 'a2a-threat-count' }, String(count)),
          h('div', { className: 'a2a-threat-minibar' },
            h('div', { className: 'a2a-threat-minibar-fill', style: `width: ${pct}%; background: ${color};` }),
          ),
        ),
      );
    }

    // Clean percentage footer
    grid.appendChild(
      h('div', { style: 'font-size: 9px; color: #666; padding-top: 3px; border-top: 1px solid rgba(255,255,255,0.04); margin-top: 3px;' },
        `Total traffic: ${summary.totalTraffic} | Clean: ${summary.cleanPercentage}%`,
      ),
    );

    section.appendChild(grid);
    return section;
  }

  private buildCiiPolicy(): HTMLElement {
    const scores = getRegionCiiScores();
    const section = h('div', null,
      h('div', { className: 'a2a-section-title', style: 'margin-bottom: 4px;' }, 'CII-AWARE TRUST POLICY'),
    );

    const card = h('div', { className: 'a2a-policy' });

    // Show key regions
    const regions: [string, string][] = [
      ['ID', 'Indonesia'],
      ['MM', 'Myanmar'],
      ['SG', 'Singapore'],
      ['US', 'United States'],
    ];

    for (const [code, name] of regions) {
      const cii = scores[code] ?? 0;
      const policy = getTrustPolicyForRegion(code);
      const levelClass = `a2a-policy-level a2a-policy-${policy.policy}`;

      card.appendChild(
        h('div', { className: 'a2a-policy-row' },
          h('span', { className: 'a2a-policy-country' }, name),
          h('span', { className: 'a2a-policy-cii', style: `color: ${cii >= 50 ? '#ef4444' : cii >= 30 ? '#eab308' : '#22c55e'}` }, cii.toFixed(1)),
          h('span', null, '\u2192'),
          h('span', { className: levelClass }, policy.policy.toUpperCase()),
        ),
      );
    }

    // Policy note
    const mmPolicy = getTrustPolicyForRegion('MM');
    const noteText = mmPolicy.policy === 'elevated' || mmPolicy.policy === 'critical'
      ? `When CII > 50: auto-reject unsigned agent cards, min trust ${mmPolicy.rules.minTrustScore}, max ${mmPolicy.rules.maxRatePerHour} req/hr`
      : 'All regions at standard trust policy';
    card.appendChild(h('div', { className: 'a2a-policy-note' }, noteText));

    section.appendChild(card);
    return section;
  }

  // ── Lifecycle ──────────────────────────────────────────────────

  public destroy(): void {
    if (this.trafficTimer) {
      clearTimeout(this.trafficTimer);
      this.trafficTimer = null;
    }
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    super.destroy();
  }
}
