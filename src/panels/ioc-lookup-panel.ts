/**
 * IoCLookupPanel — Interactive Indicator of Compromise investigation panel.
 *
 * Renders:
 *   1. Search bar for IP, domain, hash, or URL queries
 *   2. Recent Threats feed (ThreatFox last 24h) as default view
 *   3. Detailed lookup results with threat level, sources, tags
 *
 * Uses free abuse.ch APIs (ThreatFox, URLhaus, MalwareBazaar) via
 * the ioc-lookup service. Falls back to realistic mock data if
 * direct browser fetch fails (CORS).
 */

import { Panel } from '@/components/Panel';
import { escapeHtml } from '@/utils/sanitize';
import {
  lookupIoC,
  getRecentThreats,
  detectIoCType,
} from '@/services/ioc-lookup';
import type { IoCLookupResult, ThreatFoxEntry } from '@/types';

// ── Color mappings ───────────────────────────────────────────────────

const THREAT_LEVEL_COLORS: Record<string, string> = {
  malicious: '#ef4444',
  suspicious: '#f97316',
  clean: '#22c55e',
  unknown: '#6b7280',
};

const THREAT_LEVEL_BG: Record<string, string> = {
  malicious: 'rgba(239,68,68,0.15)',
  suspicious: 'rgba(249,115,22,0.15)',
  clean: 'rgba(34,197,94,0.15)',
  unknown: 'rgba(107,114,128,0.15)',
};

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: '#3b82f6',
  domain: '#8b5cf6',
  hash: '#ec4899',
  url: '#f59e0b',
  unknown: '#6b7280',
};

// ── Panel class ──────────────────────────────────────────────────────

export class IoCLookupPanel extends Panel {
  private recentThreats: ThreatFoxEntry[] = [];
  private currentResult: IoCLookupResult | null = null;
  private isSearching = false;
  private isLoadingFeed = false;
  private searchQuery = '';

  constructor() {
    super({
      id: 'ioc-lookup',
      title: 'IoC Lookup',
      showCount: true,
      trackActivity: true,
      infoTooltip: 'Interactive Indicator of Compromise investigation. Queries ThreatFox, URLhaus, and MalwareBazaar (abuse.ch) APIs. Results cached 5 min.',
    });
  }

  /** Called by App on refresh interval. Loads recent threats feed. */
  public async refresh(): Promise<void> {
    if (this.isLoadingFeed) return;
    this.isLoadingFeed = true;

    try {
      this.recentThreats = await getRecentThreats();
      this.setCount(this.recentThreats.length);
      this.setDataBadge('live', `${this.recentThreats.length} IoCs`);

      // Only render feed if no active search result
      if (!this.currentResult && !this.isSearching) {
        this.render();
      }
    } catch (err) {
      console.error('[IoCLookupPanel] refresh error:', err);
      if (this.recentThreats.length === 0) {
        this.showError('Failed to load recent threats');
      }
    } finally {
      this.isLoadingFeed = false;
    }
  }

  // ── Search ─────────────────────────────────────────────────────────

  private async performSearch(query: string): Promise<void> {
    const trimmed = query.trim();
    if (!trimmed || this.isSearching) return;

    this.searchQuery = trimmed;
    this.isSearching = true;
    this.currentResult = null;
    this.renderSearching();

    try {
      this.currentResult = await lookupIoC(trimmed);
      this.render();
    } catch (err) {
      console.error('[IoCLookupPanel] search error:', err);
      this.currentResult = null;
      this.render();
    } finally {
      this.isSearching = false;
    }
  }

  private clearSearch(): void {
    this.currentResult = null;
    this.searchQuery = '';
    this.render();
  }

  // ── Rendering ──────────────────────────────────────────────────────

  private render(): void {
    const html = this.currentResult
      ? this.renderSearchBar() + this.renderResult(this.currentResult)
      : this.renderSearchBar() + this.renderRecentThreats();

    // Use direct innerHTML assignment (not debounced setContent) so we can
    // attach event listeners immediately afterwards.
    this.content.innerHTML = html;
    this.attachEventListeners();
  }

  private renderSearching(): void {
    const html = this.renderSearchBar() +
      `<div style="padding:24px;text-align:center;">
        <div style="font-size:13px;opacity:0.6;margin-bottom:8px;">Searching threat databases...</div>
        <div style="font-size:11px;opacity:0.4;">ThreatFox &middot; URLhaus &middot; MalwareBazaar</div>
      </div>`;
    this.content.innerHTML = html;
    this.attachEventListeners();
  }

  private attachEventListeners(): void {
    // Search input
    const input = this.content.querySelector<HTMLInputElement>('#ioc-search-input');
    const btn = this.content.querySelector<HTMLButtonElement>('#ioc-search-btn');
    const badge = this.content.querySelector<HTMLSpanElement>('#ioc-type-badge');

    if (input) {
      // Restore query text
      if (this.searchQuery) {
        input.value = this.searchQuery;
      }

      // Live IoC type detection
      input.addEventListener('input', () => {
        const val = input.value.trim();
        const detected = val ? detectIoCType(val) : 'unknown';
        if (badge) {
          badge.textContent = detected === 'unknown' ? '' : detected.toUpperCase();
          badge.style.display = detected === 'unknown' ? 'none' : 'inline-block';
          badge.style.background = IOC_TYPE_COLORS[detected] ?? IOC_TYPE_COLORS['unknown'] ?? '#6b7280';
        }
      });

      // Enter key
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          void this.performSearch(input.value);
        }
      });
    }

    if (btn && input) {
      btn.addEventListener('click', () => {
        void this.performSearch(input.value);
      });
    }

    // Back to feed link
    const backLink = this.content.querySelector<HTMLAnchorElement>('#ioc-back-to-feed');
    if (backLink) {
      backLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.clearSearch();
      });
    }

    // Related IoC links
    this.content.querySelectorAll<HTMLAnchorElement>('.ioc-related-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const ioc = link.dataset.ioc;
        if (ioc) {
          void this.performSearch(ioc);
        }
      });
    });
  }

  // ── Search bar ─────────────────────────────────────────────────────

  private renderSearchBar(): string {
    const detectedType = this.searchQuery ? detectIoCType(this.searchQuery) : 'unknown';
    const showBadge = this.searchQuery && detectedType !== 'unknown';

    return `<div style="padding:8px 12px;border-bottom:1px solid var(--border-dim);display:flex;align-items:center;gap:6px;">
      <div style="position:relative;flex:1;display:flex;align-items:center;">
        <input
          id="ioc-search-input"
          type="text"
          placeholder="Search IP, domain, hash, or URL..."
          value="${escapeHtml(this.searchQuery)}"
          style="
            width:100%;
            padding:6px 10px;
            padding-right:${showBadge ? '60px' : '10px'};
            background:var(--bg-secondary, #1a1a2e);
            border:1px solid var(--border-dim, #333);
            border-radius:4px;
            color:var(--text-primary, #e0e0e0);
            font-family:'JetBrains Mono','Fira Code',monospace;
            font-size:12px;
            outline:none;
          "
        />
        <span
          id="ioc-type-badge"
          style="
            position:absolute;
            right:8px;
            top:50%;
            transform:translateY(-50%);
            font-size:9px;
            font-weight:700;
            color:#fff;
            padding:1px 5px;
            border-radius:3px;
            display:${showBadge ? 'inline-block' : 'none'};
            background:${IOC_TYPE_COLORS[detectedType] || IOC_TYPE_COLORS['unknown']};
          "
        >${showBadge ? detectedType.toUpperCase() : ''}</span>
      </div>
      <button
        id="ioc-search-btn"
        style="
          padding:6px 12px;
          background:var(--accent-color, #3b82f6);
          color:#fff;
          border:none;
          border-radius:4px;
          font-size:11px;
          font-weight:600;
          cursor:pointer;
          white-space:nowrap;
        "
      >Search</button>
    </div>`;
  }

  // ── Recent Threats feed ────────────────────────────────────────────

  private renderRecentThreats(): string {
    if (this.recentThreats.length === 0) {
      return `<div style="padding:24px;text-align:center;opacity:0.5;font-size:12px;">
        Loading recent threats...
      </div>`;
    }

    const rows = this.recentThreats.slice(0, 15).map((entry) => {
      const truncatedIoc = entry.ioc.length > 42
        ? entry.ioc.slice(0, 39) + '...'
        : entry.ioc;
      const timeStr = this.timeAgo(entry.firstSeen);
      const confColor = entry.confidence >= 80 ? '#ef4444'
        : entry.confidence >= 50 ? '#f97316'
        : '#eab308';

      return `<div style="padding:5px 12px;border-bottom:1px solid var(--border-dim);font-size:12px;display:flex;gap:6px;align-items:flex-start;">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
            <span style="font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px;color:var(--text-primary, #e0e0e0);" title="${escapeHtml(entry.ioc)}">${escapeHtml(truncatedIoc)}</span>
            <span style="background:#8b5cf6;color:#fff;font-size:8px;font-weight:700;padding:0 4px;border-radius:2px;flex-shrink:0;">${escapeHtml(entry.malware)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;margin-top:2px;">
            <span style="opacity:0.5;font-size:10px;">${escapeHtml(entry.threatType)}</span>
            <span style="color:${confColor};font-size:10px;font-weight:600;">${entry.confidence}%</span>
            ${entry.tags.length > 0 ? entry.tags.slice(0, 2).map(t =>
              `<span style="background:rgba(139,92,246,0.15);color:#a78bfa;font-size:9px;padding:0 3px;border-radius:2px;">${escapeHtml(t)}</span>`
            ).join('') : ''}
            <span style="opacity:0.35;font-size:10px;margin-left:auto;flex-shrink:0;">${timeStr}</span>
          </div>
        </div>
      </div>`;
    }).join('');

    return `<div>
      <div style="padding:6px 12px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;border-bottom:1px solid var(--border-dim);display:flex;justify-content:space-between;align-items:center;">
        <span>Recent Threats (24h)</span>
        <span style="opacity:0.6;text-transform:none;letter-spacing:0;">${this.recentThreats.length} IoCs</span>
      </div>
      <div style="max-height:420px;overflow-y:auto;">${rows}</div>
    </div>`;
  }

  // ── Lookup result view ─────────────────────────────────────────────

  private renderResult(result: IoCLookupResult): string {
    return [
      this.renderVerdictBanner(result),
      this.renderSourceResults(result),
      this.renderTags(result),
      this.renderMalwareInfo(result),
      this.renderRelatedIocs(result),
      this.renderBackLink(),
    ].join('');
  }

  private renderVerdictBanner(result: IoCLookupResult): string {
    const color = THREAT_LEVEL_COLORS[result.threatLevel] || '#6b7280';
    const bg = THREAT_LEVEL_BG[result.threatLevel] || 'rgba(107,114,128,0.15)';
    const typeColor = IOC_TYPE_COLORS[result.type] || IOC_TYPE_COLORS['unknown'];
    const icon = result.threatLevel === 'malicious' ? '&#9888;'
      : result.threatLevel === 'suspicious' ? '&#9888;'
      : result.threatLevel === 'clean' ? '&#10003;'
      : '&#63;';

    return `<div style="padding:12px;background:${bg};border-bottom:1px solid var(--border-dim);">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:18px;color:${color};">${icon}</span>
        <span style="font-size:15px;font-weight:700;color:${color};text-transform:uppercase;letter-spacing:0.5px;">${result.threatLevel}</span>
        <span style="margin-left:auto;background:rgba(255,255,255,0.1);color:var(--text-primary, #e0e0e0);font-size:11px;padding:2px 8px;border-radius:3px;">
          Confidence: <strong style="color:${color};">${result.confidence}%</strong>
        </span>
      </div>
      <div style="display:flex;align-items:center;gap:6px;">
        <span style="font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;word-break:break-all;color:var(--text-primary, #e0e0e0);">${escapeHtml(result.query)}</span>
        <span style="background:${typeColor};color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;flex-shrink:0;">${result.type.toUpperCase()}</span>
      </div>
    </div>`;
  }

  private renderSourceResults(result: IoCLookupResult): string {
    if (result.sources.length === 0) return '';

    const rows = result.sources.map((src) => {
      const isHit = src.verdict !== 'not found';
      const dotColor = isHit ? '#ef4444' : '#22c55e';

      return `<div style="padding:6px 12px;border-bottom:1px solid var(--border-dim);font-size:12px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="width:6px;height:6px;border-radius:50%;background:${dotColor};display:inline-block;flex-shrink:0;"></span>
          <span style="font-weight:600;">${escapeHtml(src.name)}</span>
          <span style="opacity:0.6;font-size:11px;">${escapeHtml(src.verdict)}</span>
          ${src.url ? `<a href="${escapeHtml(src.url)}" target="_blank" rel="noopener" style="margin-left:auto;color:#3b82f6;font-size:10px;text-decoration:none;flex-shrink:0;">View &rarr;</a>` : ''}
        </div>
        <div style="opacity:0.5;font-size:11px;margin-top:2px;padding-left:12px;">${escapeHtml(src.details)}</div>
      </div>`;
    }).join('');

    return `<div>
      <div style="padding:6px 12px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;border-bottom:1px solid var(--border-dim);">Source Results</div>
      ${rows}
    </div>`;
  }

  private renderTags(result: IoCLookupResult): string {
    if (result.tags.length === 0) return '';

    const badges = result.tags.map(tag =>
      `<span style="display:inline-block;background:rgba(139,92,246,0.15);color:#a78bfa;font-size:10px;padding:2px 6px;border-radius:3px;margin:2px;">${escapeHtml(tag)}</span>`
    ).join('');

    return `<div style="padding:8px 12px;border-bottom:1px solid var(--border-dim);">
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;margin-bottom:4px;">Tags</div>
      <div style="display:flex;flex-wrap:wrap;gap:2px;">${badges}</div>
    </div>`;
  }

  private renderMalwareInfo(result: IoCLookupResult): string {
    if (!result.malwareFamily && !result.firstSeen && !result.lastSeen) return '';

    const items: string[] = [];
    if (result.malwareFamily) {
      items.push(`<div style="display:flex;gap:8px;align-items:center;">
        <span style="opacity:0.5;font-size:11px;min-width:70px;">Family</span>
        <span style="font-weight:600;color:#ec4899;font-size:12px;">${escapeHtml(result.malwareFamily)}</span>
      </div>`);
    }
    if (result.firstSeen) {
      items.push(`<div style="display:flex;gap:8px;align-items:center;">
        <span style="opacity:0.5;font-size:11px;min-width:70px;">First Seen</span>
        <span style="font-size:12px;">${this.formatDate(result.firstSeen)}</span>
      </div>`);
    }
    if (result.lastSeen) {
      items.push(`<div style="display:flex;gap:8px;align-items:center;">
        <span style="opacity:0.5;font-size:11px;min-width:70px;">Last Seen</span>
        <span style="font-size:12px;">${this.formatDate(result.lastSeen)}</span>
      </div>`);
    }

    return `<div style="padding:8px 12px;border-bottom:1px solid var(--border-dim);display:flex;flex-direction:column;gap:4px;">
      ${items.join('')}
    </div>`;
  }

  private renderRelatedIocs(result: IoCLookupResult): string {
    if (result.relatedIocs.length === 0) return '';

    const rows = result.relatedIocs.map(ioc =>
      `<a href="#" class="ioc-related-link" data-ioc="${escapeHtml(ioc)}" style="
        display:block;
        padding:3px 12px;
        font-family:'JetBrains Mono','Fira Code',monospace;
        font-size:11px;
        color:#3b82f6;
        text-decoration:none;
        cursor:pointer;
      ">${escapeHtml(ioc)}</a>`
    ).join('');

    return `<div style="border-bottom:1px solid var(--border-dim);">
      <div style="padding:6px 12px;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.5;border-bottom:1px solid var(--border-dim);">Related IoCs</div>
      ${rows}
    </div>`;
  }

  private renderBackLink(): string {
    return `<div style="padding:8px 12px;">
      <a href="#" id="ioc-back-to-feed" style="color:#3b82f6;font-size:11px;text-decoration:none;">&larr; Back to recent threats feed</a>
    </div>`;
  }

  // ── Helpers ────────────────────────────────────────────────────────

  private timeAgo(date: Date): string {
    const ms = Date.now() - date.getTime();
    if (ms < 60_000) return 'just now';
    if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
    if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
    return `${Math.floor(ms / 86_400_000)}d ago`;
  }

  private formatDate(date: Date): string {
    return date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }
}
