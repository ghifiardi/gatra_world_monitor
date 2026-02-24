/**
 * RansomwareTrackerPanel — displays recent ransomware attacks from ransomware.live.
 *
 * Renders:
 *   1. Stats row (total victims 30d, top threat group, top targeted country)
 *   2. Top groups horizontal bar chart (top 5 groups with proportional bars)
 *   3. Recent victims feed (scrollable, max-height 350px)
 *
 * Data comes from the ransomware-tracker service which fetches from
 * ransomware.live API with a 15-minute cache and mock fallback.
 */

import { Panel } from '@/components/Panel';
import { escapeHtml } from '@/utils/sanitize';
import { fetchRansomwareData } from '@/services/ransomware-tracker';
import type { RansomwareVictim, RansomwareStats } from '@/types';

// ── Group badge color palette (dark-theme friendly) ─────────────────
const GROUP_COLORS = [
  '#ef4444', // red
  '#f97316', // orange
  '#eab308', // yellow
  '#22c55e', // green
  '#06b6d4', // cyan
  '#3b82f6', // blue
  '#8b5cf6', // violet
  '#ec4899', // pink
  '#14b8a6', // teal
  '#f43f5e', // rose
  '#a855f7', // purple
  '#84cc16', // lime
  '#6366f1', // indigo
  '#d946ef', // fuchsia
  '#fb923c', // amber
];

/** Deterministic color for a group name. */
function groupColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0;
  }
  return GROUP_COLORS[Math.abs(hash) % GROUP_COLORS.length] ?? GROUP_COLORS[0]!;
}

/** Country ISO code to flag emoji (works on most platforms). */
function countryFlag(code: string | null): string {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  const codePoints = [...upper].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...codePoints);
}

// ── Panel class ─────────────────────────────────────────────────────

export class RansomwareTrackerPanel extends Panel {
  private victims: RansomwareVictim[] = [];
  private stats: RansomwareStats | null = null;
  private loading = false;

  constructor() {
    super({
      id: 'ransomware-tracker',
      title: 'Ransomware Tracker',
      showCount: true,
      trackActivity: true,
      infoTooltip:
        'Recent ransomware victims from ransomware.live. Shows attacks discovered in the last 30 days. Data refreshes every 5 minutes.',
    });
  }

  /** Called by App on a periodic interval. */
  public async refresh(): Promise<void> {
    if (this.loading) return;
    this.loading = true;

    try {
      const { victims, stats } = await fetchRansomwareData();

      this.victims = victims;
      this.stats = stats;

      this.setCount(stats.totalVictims30d);
      this.setDataBadge('live', `${stats.totalVictims30d} victims (30d)`);
      this.render();
    } catch (err) {
      console.error('[RansomwareTrackerPanel] refresh error:', err);
      this.showError('Failed to load ransomware data');
    } finally {
      this.loading = false;
    }
  }

  // ── Rendering ─────────────────────────────────────────────────────

  private render(): void {
    const html = [
      this.renderStatsRow(),
      this.renderTopGroupsBars(),
      this.renderVictimFeed(),
    ].join('');

    this.setContent(html);
  }

  // ── Stats row ─────────────────────────────────────────────────────

  private renderStatsRow(): string {
    if (!this.stats) return '';
    const s = this.stats;

    const topGroup = s.topGroups[0];
    const topCountry = s.topCountries[0];

    const stat = (label: string, value: string | number, color?: string) =>
      `<div style="text-align:center;flex:1;min-width:70px;">
        <div style="font-size:18px;font-weight:700;${color ? `color:${color};` : 'color:var(--text-primary);'}">${escapeHtml(String(value))}</div>
        <div style="font-size:10px;opacity:0.5;text-transform:uppercase;">${escapeHtml(label)}</div>
      </div>`;

    return `<div style="display:flex;padding:10px 12px;border-bottom:1px solid var(--border-dim);gap:6px;">
      ${stat('Victims (30d)', s.totalVictims30d, s.totalVictims30d > 50 ? '#ef4444' : '#f97316')}
      ${stat('Top Group', topGroup ? `${topGroup.name} (${topGroup.count})` : 'N/A', '#ef4444')}
      ${stat('Top Country', topCountry ? `${countryFlag(topCountry.name)} ${topCountry.name}` : 'N/A')}
    </div>`;
  }

  // ── Top groups horizontal bar chart ───────────────────────────────

  private renderTopGroupsBars(): string {
    if (!this.stats || this.stats.topGroups.length === 0) return '';

    const top5 = this.stats.topGroups.slice(0, 5);
    const maxCount = top5[0]?.count ?? 1;

    const bars = top5
      .map((g) => {
        const pct = Math.max(8, Math.round((g.count / maxCount) * 100));
        const color = groupColor(g.name);
        return `<div style="display:flex;align-items:center;gap:8px;padding:3px 12px;font-size:12px;">
          <span style="width:110px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;opacity:0.85;" title="${escapeHtml(g.name)}">${escapeHtml(g.name)}</span>
          <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:3px;height:14px;overflow:hidden;">
            <div style="width:${pct}%;height:100%;background:${color};border-radius:3px;transition:width 0.3s;"></div>
          </div>
          <span style="width:30px;text-align:right;font-weight:600;font-size:11px;flex-shrink:0;">${g.count}</span>
        </div>`;
      })
      .join('');

    return `<div style="border-bottom:1px solid var(--border-dim);padding:6px 0;">
      <div style="padding:4px 12px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;">Top Threat Groups</div>
      ${bars}
    </div>`;
  }

  // ── Recent victims feed ───────────────────────────────────────────

  private renderVictimFeed(): string {
    if (this.victims.length === 0) {
      return '<div style="padding:12px;opacity:0.5;">No recent ransomware victims</div>';
    }

    const rows = this.victims.slice(0, 40).map((v) => {
      const color = groupColor(v.group);
      const ts = this.timeAgo(v.discoveredDate);
      const flag = countryFlag(v.country);
      const countryLabel = v.country ? `${flag} ${escapeHtml(v.country)}` : '';
      const sectorHtml = v.sector
        ? `<span style="background:rgba(255,255,255,0.08);font-size:9px;padding:1px 5px;border-radius:3px;opacity:0.7;">${escapeHtml(v.sector)}</span>`
        : '';

      return `<div style="padding:6px 12px;border-bottom:1px solid var(--border-dim);font-size:12px;display:flex;gap:8px;align-items:flex-start;">
        <span style="background:${color};color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;flex-shrink:0;margin-top:2px;max-width:90px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(v.group)}">${escapeHtml(v.group)}</span>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;justify-content:space-between;gap:6px;">
            <span style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(v.victimName)}</span>
            <span style="opacity:0.4;flex-shrink:0;font-size:11px;">${ts}</span>
          </div>
          <div style="display:flex;gap:6px;align-items:center;margin-top:2px;flex-wrap:wrap;">
            ${countryLabel ? `<span style="font-size:11px;opacity:0.7;">${countryLabel}</span>` : ''}
            ${sectorHtml}
          </div>
        </div>
      </div>`;
    }).join('');

    return `<div style="max-height:350px;overflow-y:auto;">
      <div style="padding:6px 12px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;border-bottom:1px solid var(--border-dim);display:flex;justify-content:space-between;align-items:center;">
        <span>Recent Victims</span>
        <span style="font-size:9px;opacity:0.4;text-transform:none;">Showing ${Math.min(this.victims.length, 40)} of ${this.victims.length}</span>
      </div>
      ${rows}
    </div>`;
  }

  // ── Helpers ───────────────────────────────────────────────────────

  private timeAgo(date: Date): string {
    const ms = Date.now() - date.getTime();
    if (ms < 60_000) return 'just now';
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
    return `${Math.floor(ms / 86_400_000)}d ago`;
  }
}
