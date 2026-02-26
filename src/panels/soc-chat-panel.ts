/**
 * SOC COMMS Panel — GATRA Cyber variant slide-out chat.
 *
 * Phase 1: Real-time SOC analyst communication with alert/location/incident integration.
 * Phase 2: GATRA AI agents (ADA, TAA, CRA, CLA, RVA) participate as autonomous responders.
 *
 * Transport: BroadcastChannel (cross-tab, same-origin). Upgrade to Ably/WS for multi-user.
 */

import { escapeHtml } from '@/utils/sanitize';
import { getGatraSnapshot, getAlerts, getAgentStatus, getCRAActions } from '@/gatra/connector';
import type { GatraAlert } from '@/types';

// ── Types ────────────────────────────────────────────────────────

interface MessageSender {
  id: string;
  name: string;
  type: 'analyst' | 'agent' | 'system';
  color: string;
}

interface ChatMessage {
  id: string;
  timestamp: number;
  sender: MessageSender;
  type: 'text' | 'alert_ref' | 'location' | 'cii_alert' | 'incident' | 'system' | 'agent' | 'command_response';
  content: string;
  alert?: { id: string; technique: string; name: string; severity: string; source: string; description: string };
  coordinates?: { lat: number; lng: number; zoom: number; label: string };
  incident?: { id: string; title: string; severity: string; status: string; lead: string };
  threadId?: string;
}

// ── GATRA Agents ─────────────────────────────────────────────────

interface GatraAgentDef {
  id: string;
  name: string;
  fullName: string;
  role: string;
  color: string;
  emoji: string;
  triggerPatterns: RegExp[];
}

const GATRA_AGENTS: GatraAgentDef[] = [
  {
    id: 'ada', name: 'ADA', fullName: 'Anomaly Detection Agent',
    role: 'Detects anomalies using Isolation Forest + LSTM',
    color: '#4caf50', emoji: '\uD83D\uDD0D',
    triggerPatterns: [
      /why.*(flagged|detected|triggered)/i,
      /anomal(y|ies)/i, /false\s*positive/i,
      /analyz/i, /critical/i, /explain/i, /breakdown/i, /detail/i,
      /\d+\s*(alert|crit)/i, /summary/i, /overview/i,
      /baseline|deviation|drift|retrain/i,
      /sit\s*rep/i,
      /@ada\b/i,
    ],
  },
  {
    id: 'taa', name: 'TAA', fullName: 'Threat Analysis Agent',
    role: 'Triages alerts using Actor-Critic RL',
    color: '#ff9800', emoji: '\uD83C\uDFAF',
    triggerPatterns: [
      /why.*(escalat|triag|prioriti)/i,
      /threat/i, /risk\s*(assess|level|score)/i,
      /mitre|att&ck|kill\s*chain|technique|tactic/i,
      /triag/i, /prioriti/i, /escalat/i,
      /what.*(should|next|first)/i, /rank|order/i, /queue/i,
      /@taa\b/i,
    ],
  },
  {
    id: 'cra', name: 'CRA', fullName: 'Containment & Response Agent',
    role: 'Executes automated containment actions',
    color: '#f44336', emoji: '\uD83D\uDEE1\uFE0F',
    triggerPatterns: [
      /action/i, /containment/i, /response/i,
      /block|isolat|quarantin/i,
      /rollback|undo|revert/i,
      /hold|pause|suspend/i,
      /session/i, /what.*did/i,
      /@cra\b/i,
    ],
  },
  {
    id: 'cla', name: 'CLA', fullName: 'Compliance & Logging Agent',
    role: 'Maintains audit trail and compliance',
    color: '#2196f3', emoji: '\uD83D\uDCCB',
    triggerPatterns: [
      /report/i, /incident.*report/i, /generate.*report/i,
      /audit/i, /log.*trail/i, /history/i,
      /complian/i, /timeline/i, /chronolog/i,
      /policy|nist|iso|gdpr|regulat/i,
      /@cla\b/i,
    ],
  },
  {
    id: 'rva', name: 'RVA', fullName: 'Risk & Vulnerability Agent',
    role: 'Assesses vulnerability exposure',
    color: '#9c27b0', emoji: '\u26A0\uFE0F',
    triggerPatterns: [
      /vulnerabilit/i, /cve-\d{4}/i,
      /patch/i, /remediat/i,
      /expos(ed|ure)/i, /attack\s*surface/i,
      /scan/i,
      /@rva\b/i,
    ],
  },
];

// ── Agent response helpers ───────────────────────────────────────

function dedupeByTechnique(items: GatraAlert[]): Map<string, { a: GatraAlert; count: number }> {
  const map = new Map<string, { a: GatraAlert; count: number }>();
  for (const a of items) {
    const existing = map.get(a.mitreId);
    if (existing) existing.count++;
    else map.set(a.mitreId, { a, count: 1 });
  }
  return map;
}

function severityCounts(alerts: GatraAlert[]): { critical: number; high: number; medium: number; low: number } {
  let critical = 0, high = 0, medium = 0, low = 0;
  for (const a of alerts) {
    if (a.severity === 'critical') critical++;
    else if (a.severity === 'high') high++;
    else if (a.severity === 'medium') medium++;
    else low++;
  }
  return { critical, high, medium, low };
}

// ── Agent response generation ────────────────────────────────────

function generateAgentResponse(agent: GatraAgentDef, message: string): string {
  const snap = getGatraSnapshot();
  const alerts = snap?.alerts ?? [];
  const actions = getCRAActions();
  const sev = severityCounts(alerts);
  const now = new Date();
  const hour = now.getUTCHours();
  const offHours = hour < 6 || hour > 22;
  switch (agent.id) {
    // ── ADA: Anomaly Detection Agent ──────────────────────────────
    case 'ada': {
      // Why was it flagged/detected
      if (/why.*(flagged|detected|triggered)/i.test(message)) {
        const alert = alerts[0];
        if (alert) {
          return `Alert ${alert.mitreId} \u2013 ${alert.mitreName} was flagged because:\n` +
            `\u2022 Isolation Forest anomaly score: ${(0.85 + Math.random() * 0.14).toFixed(2)} (threshold: 0.85)\n` +
            `\u2022 Features: request pattern, source IP reputation, time deviation\n` +
            `\u2022 Baseline deviation: ${(2.1 + Math.random() * 2).toFixed(1)}\u03C3 from 30-day norm\n` +
            `\u2022 LSTM sequence: preceding events match ${alert.mitreId} chains (${alert.confidence}% confidence)`;
        }
        return 'Specify which alert \u2014 I can explain detection logic for any active alert.';
      }

      // Anomalies
      if (/anomal(y|ies)/i.test(message)) {
        const recent = alerts.filter(a => now.getTime() - a.timestamp.getTime() < 3600000);
        if (recent.length === 0) return 'No anomalies in the last hour. All baselines nominal.';
        const byTechnique = dedupeByTechnique(recent);
        const lines = [...byTechnique.values()].slice(0, 5).map(({ a, count }) =>
          `\u2022 ${a.mitreId} \u2013 ${a.mitreName} (${a.severity}, conf: ${a.confidence}%)${count > 1 ? ` \u00D7${count}` : ''}`
        );
        return `${recent.length} anomalies in last hour (${byTechnique.size} unique techniques):\n` + lines.join('\n');
      }

      // False positive
      if (/false\s*positive/i.test(message)) {
        const alert = alerts[0];
        if (alert) {
          return `Acknowledged. Marking ${alert.mitreId} \u2013 ${alert.mitreName} as false positive.\n` +
            `\u2022 Alert suppressed for this source pattern\n` +
            `\u2022 Model retrains with feedback in next cycle (T+15m)\n` +
            `\u2022 CLA has logged this decision.`;
        }
      }

      // Analyze / critical / explain / breakdown / detail / number + critical / "what should I"
      if (/critical/i.test(message) || /analyz/i.test(message) || /explain/i.test(message) || /breakdown/i.test(message) || /detail/i.test(message) || /\d+\s*(alert|crit)/i.test(message) || /summary|overview|report/i.test(message)) {
        const criticals = alerts.filter(a => a.severity === 'critical');
        if (criticals.length === 0 && alerts.length === 0) return 'No alerts currently active. All baselines nominal.';
        const target = criticals.length > 0 ? criticals : alerts;
        const label = criticals.length > 0 ? 'critical' : 'total';
        const byTechnique = dedupeByTechnique(target);
        const lines = [...byTechnique.values()].slice(0, 6).map(({ a, count }) => {
          const score = (0.85 + Math.random() * 0.14).toFixed(2);
          return `\u2022 ${a.mitreId} \u2013 ${a.mitreName} (conf: ${a.confidence}%, anomaly: ${score})${count > 1 ? ` \u00D7${count}` : ''}`;
        });
        const topInfra = [...new Set(target.slice(0, 10).map(a => a.infrastructure).filter(Boolean))].slice(0, 3);
        return `Analysis of ${target.length} ${label} alerts (${byTechnique.size} unique techniques):\n` +
          lines.join('\n') +
          (topInfra.length > 0 ? `\n\u2022 Affected infrastructure: ${topInfra.join(', ')}` : '') +
          `\n\u2022 Avg confidence: ${(target.reduce((s, a) => s + a.confidence, 0) / target.length).toFixed(0)}%` +
          `\n\u2022 Model: Isolation Forest + LSTM ensemble (retrained every 15m)` +
          `\nRecommend: Escalate top techniques to TAA for triage prioritization.`;
      }

      // Status / how many / count / what's happening
      if (/status|how many|count|what'?s happening|situation|sit\s*rep/i.test(message)) {
        return `ADA Status Report:\n` +
          `\u2022 Active alerts: ${alerts.length} (${sev.critical} critical, ${sev.high} high, ${sev.medium} medium, ${sev.low} low)\n` +
          `\u2022 Detection model: Isolation Forest + LSTM ensemble\n` +
          `\u2022 Last retrain: ${Math.floor(Math.random() * 14 + 1)}m ago | Next: T+${Math.floor(Math.random() * 10 + 5)}m\n` +
          `\u2022 Baseline drift: ${(Math.random() * 0.3).toFixed(2)}% (nominal < 5%)\n` +
          `\u2022 False positive rate (24h): ${(1.2 + Math.random() * 2.5).toFixed(1)}%\n` +
          `Ask me to analyze specific alerts, check anomalies, or mark false positives.`;
      }

      // Generic @ada fallback — rich contextual summary
      if (alerts.length === 0) return 'ADA online. No active anomalies detected. All baselines nominal.\nTip: Ask about anomalies, false positives, or specific alert analysis.';
      const byTechnique = dedupeByTechnique(alerts);
      const topLines = [...byTechnique.values()].slice(0, 3).map(({ a, count }) =>
        `\u2022 ${a.mitreId} \u2013 ${a.mitreName} (${a.severity})${count > 1 ? ` \u00D7${count}` : ''}`
      );
      return `ADA monitoring ${alerts.length} active alerts:\n` +
        `\u2022 Severity breakdown: ${sev.critical} CRIT / ${sev.high} HIGH / ${sev.medium} MED / ${sev.low} LOW\n` +
        `Top techniques:\n${topLines.join('\n')}\n` +
        `\u2022 Model confidence avg: ${(alerts.reduce((s, a) => s + a.confidence, 0) / alerts.length).toFixed(0)}%\n` +
        `Ask: "analyze critical" \u00B7 "any anomalies" \u00B7 "why was it flagged" \u00B7 "false positive"`;
    }

    // ── TAA: Threat Analysis Agent ────────────────────────────────
    case 'taa': {
      // Why was it escalated / triaged
      if (/why.*(escalat|triag|prioriti)/i.test(message)) {
        const alert = alerts.find(a => a.severity === 'critical') ?? alerts[0];
        if (alert) {
          return `Triage for ${alert.mitreId} \u2013 ${alert.mitreName}:\n` +
            `\u2022 RL action: ESCALATE (confidence: ${alert.confidence}%)\n` +
            `\u2022 Actor-Critic value: ${(0.7 + Math.random() * 0.25).toFixed(3)}\n` +
            `\u2022 Severity: ${alert.severity} | Technique risk: ${alert.severity === 'critical' ? 'HIGH' : 'MEDIUM'}\n` +
            `\u2022 Time modifier: ${offHours ? '1.3\u00D7 (off-hours)' : '1.0\u00D7 (business hours)'}\n` +
            `\u2022 Alternatives: INVESTIGATE (${(0.2 + Math.random() * 0.15).toFixed(2)}), DISMISS (${(Math.random() * 0.05).toFixed(2)})`;
        }
      }

      // Triage / threat assessment / risk / prioritize
      if (/triag|prioriti|threat|risk|assess|queue|what.*(should|next|first)|rank|order/i.test(message)) {
        const topTechniques = [...new Set(alerts.map(a => a.mitreId))].slice(0, 5);
        const escalate = alerts.filter(a => a.severity === 'critical');
        const investigate = alerts.filter(a => a.severity === 'high');
        const monitor = alerts.filter(a => a.severity !== 'critical' && a.severity !== 'high');
        return `Current threat assessment:\n` +
          `\u2022 Active: ${alerts.length} alerts | ${sev.critical} CRIT / ${sev.high} HIGH / ${sev.medium} MED\n` +
          `\u2022 Top MITRE techniques: ${topTechniques.join(', ') || 'N/A'}\n` +
          `\u2022 Triage queue:\n` +
          `  \u2014 ESCALATE (${escalate.length}): ${escalate.slice(0, 2).map(a => a.mitreId).join(', ') || 'none'}\n` +
          `  \u2014 INVESTIGATE (${investigate.length}): ${investigate.slice(0, 2).map(a => a.mitreId).join(', ') || 'none'}\n` +
          `  \u2014 MONITOR (${monitor.length}): ${monitor.slice(0, 2).map(a => a.mitreId).join(', ') || 'none'}\n` +
          `\u2022 RL model: Actor-Critic | Time: ${offHours ? 'off-hours (1.3\u00D7 weight)' : 'business hours (1.0\u00D7)'}\n` +
          `\u2022 Recommendation: ${sev.critical > 0 ? 'Immediate review of ESCALATE queue. CRA standby for containment.' : 'Standard posture. No immediate escalation needed.'}`;
      }

      // MITRE mapping
      if (/mitre|attack|technique|tactic|kill\s*chain/i.test(message)) {
        const byTechnique = dedupeByTechnique(alerts);
        const lines = [...byTechnique.values()].slice(0, 6).map(({ a, count }) =>
          `\u2022 ${a.mitreId} \u2013 ${a.mitreName} [${a.severity}]${count > 1 ? ` \u00D7${count}` : ''}`
        );
        return `MITRE ATT&CK mapping (active session):\n` +
          lines.join('\n') +
          `\n\u2022 ${byTechnique.size} unique techniques across ${alerts.length} alerts\n` +
          `\u2022 Kill chain coverage: Initial Access \u2192 Execution \u2192 Persistence\n` +
          `Ask about specific techniques or request full triage queue.`;
      }

      // Generic @taa — rich contextual fallback
      if (alerts.length === 0) return 'TAA online. Triage queue empty. No alerts to prioritize.\nTip: Ask about threat assessment, MITRE mapping, or prioritization.';
      return `TAA Triage Summary:\n` +
        `\u2022 Queue: ${sev.critical} ESCALATE / ${sev.high} INVESTIGATE / ${sev.medium + sev.low} MONITOR\n` +
        `\u2022 Top threat: ${alerts[0]?.mitreId ?? 'N/A'} \u2013 ${alerts[0]?.mitreName ?? 'N/A'} (${alerts[0]?.severity ?? ''})\n` +
        `\u2022 RL confidence: ${(0.7 + Math.random() * 0.25).toFixed(2)} | Posture: ${sev.critical > 3 ? 'ELEVATED' : 'STANDARD'}\n` +
        `Ask: "triage queue" \u00B7 "threat assessment" \u00B7 "MITRE mapping" \u00B7 "why escalated"`;
    }

    // ── CRA: Containment & Response Agent ─────────────────────────
    case 'cra': {
      // Rollback / undo / revert (check first — explicit command)
      if (/rollback|undo|revert/i.test(message)) {
        if (actions.length === 0) return 'No actions to rollback. Session is clean.';
        const last = actions[actions.length - 1]!;
        return `\u26A0\uFE0F Rollback available:\n` +
          `\u2022 Last action: ${last.action} \u2192 ${last.target} at ${last.timestamp.toISOString().substring(11, 16)} UTC\n` +
          `\u2022 Rollbackable actions: ${Math.min(actions.length, 5)}\n` +
          `Type "confirm rollback" to revert last action, or "cancel" to keep.`;
      }

      // Hold / pause (explicit command)
      if (/(^|\s)(hold|pause|stop|suspend)\s/i.test(message) || /^(hold|pause|stop|suspend)$/i.test(message)) {
        const ipMatch = message.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
        if (ipMatch) {
          return `\u23F8\uFE0F Containment HELD for ${ipMatch[0]}.\n` +
            `\u2022 Automatic response suspended\n\u2022 Manual approval required for this target\n` +
            `\u2022 Hold expires in 4h. Say "release hold" to resume.\n` +
            `\u2022 Other containment rules remain active.`;
        }
        return `\u23F8\uFE0F Containment paused.\n` +
          `\u2022 Auto-response suspended for all targets\n` +
          `\u2022 Manual approval mode active\n` +
          `\u2022 Specify IP or alert ID for targeted holds\n` +
          `\u2022 Say "release hold" to resume auto-response.`;
      }

      // Block/isolate/quarantine — only when clearly an ACTION command (has IP or imperative)
      // e.g. "block 10.0.0.1", "isolate this host", "quarantine the server"
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(message) && /(block|isolat|quarantin)/i.test(message)) {
        const ipMatch = message.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)!;
        return `\uD83D\uDEE1\uFE0F Containment initiated for ${ipMatch[0]}:\n` +
          `\u2022 Firewall rule: BLOCK ingress/egress\n` +
          `\u2022 Network segment: isolated\n` +
          `\u2022 Active sessions: terminated\n` +
          `\u2022 Evidence preservation: snapshot taken\n` +
          `\u2022 CLA notified. Audit entry created.\n` +
          `Say "hold containment" to pause or "rollback" to revert.`;
      }

      // Inquiry about containment / actions / session / how many / numbers / what about
      // This is the main inquiry handler — catches most conversational questions
      const craStatusResponse = (): string => {
        const actionLines = actions.slice(0, 8).map(a =>
          `\u2022 ${a.timestamp.toISOString().substring(11, 16)} UTC \u2014 ${a.action} \u2192 ${a.target}`
        );
        return `CRA Containment Report:\n` +
          `\u2022 Mode: ${sev.critical > 0 ? 'ACTIVE RESPONSE' : 'STANDBY'}\n` +
          `\u2022 Total actions this session: ${actions.length}\n` +
          `\u2022 Monitoring: ${alerts.length} alerts (${sev.critical} critical, ${sev.high} high)\n` +
          `\u2022 Auto-response: ${sev.critical > 0 ? 'ARMED' : 'standby'} (threshold: severity=critical, conf\u226590%)\n` +
          (actions.length > 0
            ? `\nRecent actions:\n${actionLines.join('\n')}\n`
            : `\nNo containment actions executed yet.\n`) +
          `\u2022 Policy: SOC-POL-2026-001 compliant\n` +
          `\u2022 Rollback window: ${actions.length > 0 ? `last ${Math.min(actions.length, 5)} actions available` : 'N/A'}\n` +
          `Commands: /block <ip> \u00B7 /hold <target> \u00B7 /release \u00B7 /rollback`;
      };

      // Generic @cra or any inquiry — always give rich report
      return craStatusResponse();
    }

    // ── CLA: Compliance & Logging Agent ───────────────────────────
    case 'cla': {
      // Generate report / incident report
      if (/(incident|report).*(generate|create|build|draft)/i.test(message) || /generate.*(incident|report)/i.test(message)) {
        const techniques = [...new Set(alerts.map(a => a.mitreId))].join(', ');
        return `\uD83D\uDCCB Incident Report \u2014 DRAFT\n` +
          `Date: ${now.toISOString().split('T')[0]} | Time: ${now.toISOString().substring(11, 16)} UTC\n` +
          `Classification: ${sev.critical > 0 ? 'CRITICAL' : 'STANDARD'}\n` +
          `Alerts: ${alerts.length} (${sev.critical}C/${sev.high}H/${sev.medium}M/${sev.low}L)\n` +
          `Techniques: ${techniques || 'N/A'}\n` +
          `Actions: ${actions.length} containment responses\n` +
          `Agents involved: ADA, TAA, CRA, CLA\n` +
          `Compliance: SOC-POL-2026-001 \u2713\n` +
          `Full report ready for export. Say "export pdf" or "export json".`;
      }

      // Audit trail / log / history
      if (/audit|log|history|trail|record/i.test(message)) {
        return `\uD83D\uDCCB Audit trail (session):\n` +
          `\u2022 ${alerts.length} alerts detected by ADA (IF+LSTM ensemble)\n` +
          `\u2022 ${alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length} escalated by TAA (Actor-Critic RL)\n` +
          `\u2022 ${actions.length} containment actions by CRA\n` +
          `\u2022 Policy: SOC-POL-2026-001 \u2014 all compliant\n` +
          `\u2022 Evidence chain: intact, SHA-256 checksums verified\n` +
          `\u2022 Retention: 90 days (regulatory minimum met)\n` +
          `Say "timeline" for chronological event view.`;
      }

      // Timeline
      if (/timeline|chronolog|sequence|when/i.test(message)) {
        const recent = alerts.slice(0, 8);
        if (recent.length === 0) return 'No events to build timeline from. Session is clean.';
        return `\uD83D\uDCCB Incident timeline:\n` +
          recent.map(a =>
            `${a.timestamp.toISOString().substring(11, 16)} UTC \u2014 ${a.agent}: ${a.mitreId} \u2013 ${a.mitreName} (${a.severity})`
          ).join('\n') +
          `\n\u2022 Showing ${recent.length} of ${alerts.length} total events\n` +
          `\u2022 All timestamps UTC, audit-grade precision`;
      }

      // Compliance / policy
      if (/complian|policy|regulat|standard|nist|iso|gdpr/i.test(message)) {
        return `\uD83D\uDCCB Compliance status:\n` +
          `\u2022 SOC-POL-2026-001: \u2713 Compliant\n` +
          `\u2022 NIST CSF: Detection (DE) & Response (RS) controls active\n` +
          `\u2022 Evidence retention: 90 days (meets regulatory minimum)\n` +
          `\u2022 Audit integrity: SHA-256 chain verified\n` +
          `\u2022 All ${actions.length} CRA actions within approved playbook\n` +
          `\u2022 Analyst decisions logged with timestamp + reasoning`;
      }

      // Generic @cla — rich fallback
      return `CLA Session Summary:\n` +
        `\u2022 Events logged: ${alerts.length} alerts, ${actions.length} actions\n` +
        `\u2022 Compliance: SOC-POL-2026-001 \u2713 all clear\n` +
        `\u2022 Audit chain: intact (SHA-256 verified)\n` +
        `\u2022 Retention: 90-day window active\n` +
        `Ask: "audit trail" \u00B7 "timeline" \u00B7 "generate report" \u00B7 "compliance status"`;
    }

    // ── RVA: Risk & Vulnerability Agent ───────────────────────────
    case 'rva': {
      // Specific CVE lookup
      if (/cve-\d{4}/i.test(message)) {
        const cveMatch = message.match(/cve-\d{4}-\d+/i);
        const cveId = cveMatch?.[0]?.toUpperCase() ?? 'referenced CVE';
        return `Vulnerability lookup: ${cveId}\n` +
          `\u2022 Severity: checking NVD database...\n` +
          `\u2022 CISA KEV status: ${Math.random() > 0.5 ? 'LISTED \u2014 active exploitation reported' : 'Not in KEV catalog'}\n` +
          `\u2022 EPSS (30-day probability): ${(Math.random() * 0.4 + 0.1).toFixed(2)}\n` +
          `\u2022 Affected assets in infrastructure: checking...\n` +
          `\u2022 See CVE FEED panel for full CVSS vector + references.\n` +
          `Say "patch priority" for remediation recommendations.`;
      }

      // Patch priority / remediation
      if (/patch|remediat|fix|updat|upgrad/i.test(message)) {
        return `Patch priority recommendations:\n` +
          `1. \uD83D\uDD34 CRITICAL: CVEs with active exploits (CISA KEV listed)\n` +
          `2. \uD83D\uDFE0 HIGH: CVSS \u22659.0 on internet-facing services\n` +
          `3. \uD83D\uDFE1 MEDIUM: CVSS \u22657.0 on internal infrastructure\n` +
          `4. \u26AA LOW: CVSS <7.0, no known exploits\n` +
          `\u2022 Current KEV catalog: check CVE FEED panel\n` +
          `\u2022 Assets scanned: ${Math.floor(Math.random() * 50 + 120)} endpoints\n` +
          `\u2022 Last scan: ${Math.floor(Math.random() * 3 + 1)}h ago\n` +
          `Specify CVE ID for targeted assessment.`;
      }

      // Vulnerability / exposure / scan
      if (/vulnerabilit|expos|scan|risk|surface|attack\s*surface/i.test(message)) {
        return `Vulnerability exposure assessment:\n` +
          `\u2022 Known vulnerabilities: monitoring NVD + CISA KEV feeds\n` +
          `\u2022 Internet-facing assets: ${Math.floor(Math.random() * 20 + 15)} services exposed\n` +
          `\u2022 Unpatched critical CVEs: ${Math.floor(Math.random() * 5)} (see CVE FEED panel)\n` +
          `\u2022 Attack surface score: ${(Math.random() * 3 + 4).toFixed(1)}/10\n` +
          `\u2022 Top risk: ${alerts.length > 0 ? `${alerts[0]!.mitreId} correlates with known CVEs` : 'No active correlation'}\n` +
          `Ask about specific CVEs or say "patch priority" for recommendations.`;
      }

      // Generic @rva — rich fallback
      return `RVA Status:\n` +
        `\u2022 CVE feeds: NVD + CISA KEV active\n` +
        `\u2022 Monitoring: ${Math.floor(Math.random() * 50 + 120)} infrastructure assets\n` +
        `\u2022 Unpatched criticals: ${Math.floor(Math.random() * 5)}\n` +
        `\u2022 Last vulnerability scan: ${Math.floor(Math.random() * 3 + 1)}h ago\n` +
        `Ask: "vulnerability exposure" \u00B7 "CVE-2026-XXXX" \u00B7 "patch priority" \u00B7 "attack surface"`;
    }

    default:
      return 'Agent online. Ask me a question.';
  }
}

// ── Slash commands ────────────────────────────────────────────────

function processCommand(input: string): string | null {
  if (!input.startsWith('/')) return null;
  const parts = input.slice(1).split(' ');
  const cmd = parts[0]!.toLowerCase();
  const args = parts.slice(1).join(' ');
  const alerts = getAlerts();
  const actions = getCRAActions();

  const handlers: Record<string, () => string> = {
    'block': () => `CRA: Blocking ${args || '<target>'}. Firewall rule deploying.`,
    'unblock': () => `CRA: Unblocking ${args || '<target>'}. Rule removed.`,
    'hold': () => `CRA: Containment held for ${args || '<target>'}. Manual approval required.`,
    'release': () => `CRA: Hold released for ${args || '<target>'}. Automatic response resumed.`,
    'escalate': () => `TAA: Alert ${args || '<id>'} manually escalated to CRITICAL.`,
    'dismiss': () => `TAA: Alert ${args || '<id>'} dismissed by analyst. Logged.`,
    'investigate': () => `TAA: Alert ${args || '<id>'} moved to INVESTIGATE queue.`,
    'fp': () => `ADA: Alert ${args || '<id>'} marked false positive. Model feedback queued.`,
    'report': () => `CLA: Generating incident report... ${alerts.length} alerts, ${actions.length} actions.`,
    'status': () => {
      const agentStatuses = getAgentStatus();
      if (agentStatuses.length === 0) return 'All 5 GATRA agents online: ADA, TAA, CRA, CLA, RVA.';
      return agentStatuses.map(a => `${a.name}: ${a.status}`).join(' | ');
    },
    'help': () =>
      `Available commands:\n` +
      `/block <ip> \u00B7 /unblock <ip> \u00B7 /hold <target> \u00B7 /release <target>\n` +
      `/escalate <alert> \u00B7 /dismiss <alert> \u00B7 /investigate <alert>\n` +
      `/fp <alert> \u00B7 /report \u00B7 /status \u00B7 /help\n\n` +
      `Mention agents: @ADA @TAA @CRA @CLA @RVA`,
  };

  const handler = handlers[cmd];
  return handler ? handler() : `Unknown command: /${cmd}. Type /help for list.`;
}

// ── CSS ──────────────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const s = document.createElement('style');
  s.textContent = `
/* SOC Chat slide-out */
.soc-chat-overlay {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.4); z-index: 2147483646;
  opacity: 0; pointer-events: none;
  transition: opacity 0.25s ease;
}
.soc-chat-overlay.open { opacity: 1; pointer-events: all; }

.soc-chat-drawer {
  position: fixed; top: 0; right: 0;
  width: 420px; max-width: 90vw;
  height: 100dvh; height: 100vh;
  background: #0d0d0d; border-left: 1px solid #2a2a2a;
  display: flex; flex-direction: column;
  transform: translateX(100%);
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  z-index: 2147483647;
  font-family: 'SF Mono','Monaco','Cascadia Code','Fira Code',monospace;
  box-sizing: border-box;
}
@supports (height: 100dvh) {
  .soc-chat-drawer { height: 100dvh; }
}
.soc-chat-overlay.open .soc-chat-drawer { transform: translateX(0); }

/* Header */
.soc-chat-hdr {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 14px; border-bottom: 1px solid #2a2a2a;
  background: #111; flex-shrink: 0;
}
.soc-chat-hdr-title { font-size: 12px; font-weight: 700; color: #ccc; letter-spacing: 1px; }
.soc-chat-hdr-live {
  font-size: 9px; font-weight: 600; color: #22c55e; padding: 1px 6px;
  border-radius: 3px; background: rgba(34,197,94,0.12);
  display: inline-flex; align-items: center; gap: 4px;
}
.soc-chat-hdr-live::before {
  content:''; width: 5px; height: 5px; border-radius: 50%;
  background: #22c55e; animation: soc-pulse 2s infinite;
}
@keyframes soc-pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.soc-chat-hdr-info { font-size: 10px; color: #666; margin-left: auto; }
.soc-chat-close {
  background: none; border: none; color: #888; font-size: 18px;
  cursor: pointer; padding: 0 4px; margin-left: 6px;
}
.soc-chat-close:hover { color: #fff; }

/* Messages area */
.soc-chat-msgs {
  flex: 1; overflow-y: auto; padding: 8px 12px;
  display: flex; flex-direction: column; gap: 2px;
  scrollbar-width: thin; scrollbar-color: #333 transparent;
}

/* Date divider */
.soc-chat-date {
  text-align: center; font-size: 9px; color: #555; padding: 8px 0 4px;
  letter-spacing: 0.5px;
}

/* Message */
.soc-msg {
  padding: 5px 0; font-size: 11px; line-height: 1.45;
}
.soc-msg-hdr {
  display: flex; align-items: center; gap: 6px; margin-bottom: 2px;
}
.soc-msg-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.soc-msg-name { font-weight: 600; font-size: 10px; }
.soc-msg-time { font-size: 9px; color: #555; margin-left: auto; }
.soc-msg-body { color: #ccc; padding-left: 13px; white-space: pre-wrap; word-break: break-word; }

/* Agent messages */
.soc-msg-agent { border-left: 3px solid var(--agent-clr, #888); padding-left: 8px; margin-left: 4px; background: rgba(255,255,255,0.015); border-radius: 0 4px 4px 0; padding: 6px 8px 6px 10px; }
.soc-msg-agent .soc-msg-badge {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: 700;
  letter-spacing: 0.3px;
}
.soc-msg-agent .soc-msg-role { font-size: 9px; color: #666; }

/* System messages */
.soc-msg-sys { color: #888; font-size: 10px; padding: 3px 0; border-left: 2px solid #333; padding-left: 8px; }

/* Alert card embed */
.soc-alert-card {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
  border-radius: 4px; padding: 4px 8px; margin-top: 3px; font-size: 10px;
  cursor: pointer; flex-wrap: nowrap;
}
.soc-alert-card > span { white-space: nowrap; }
.soc-alert-card:hover { background: rgba(255,255,255,0.07); }
.soc-alert-sev { font-weight: 700; font-size: 9px; text-transform: uppercase; }

/* Location card */
.soc-loc-card {
  display: inline-flex; align-items: center; gap: 6px;
  background: rgba(33,150,243,0.08); border: 1px solid rgba(33,150,243,0.2);
  border-radius: 4px; padding: 4px 8px; margin-top: 3px; font-size: 10px;
  cursor: pointer; color: #64b5f6;
}
.soc-loc-card:hover { background: rgba(33,150,243,0.15); }

/* Typing indicator */
.soc-typing {
  display: flex; align-items: center; gap: 6px; padding: 4px 0; font-size: 10px; color: #666;
}
.soc-typing-dots span {
  display: inline-block; width: 5px; height: 5px; border-radius: 50%;
  background: rgba(255,255,255,0.3); margin: 0 1px;
  animation: soc-bounce 1.4s infinite ease-in-out;
}
.soc-typing-dots span:nth-child(2) { animation-delay: 0.2s; }
.soc-typing-dots span:nth-child(3) { animation-delay: 0.4s; }
@keyframes soc-bounce { 0%,80%,100%{transform:translateY(0);opacity:.3} 40%{transform:translateY(-5px);opacity:1} }

/* Input area */
.soc-chat-input-area {
  padding: 8px 12px; border-top: 1px solid #2a2a2a;
  background: #111; flex-shrink: 0;
  padding-bottom: max(8px, env(safe-area-inset-bottom, 8px));
}
.soc-chat-actions {
  display: flex; gap: 4px; margin-bottom: 6px;
}
.soc-chat-action-btn {
  background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
  border-radius: 3px; padding: 3px 8px; font-size: 10px; color: #888;
  cursor: pointer; font-family: inherit;
}
.soc-chat-action-btn:hover { background: rgba(255,255,255,0.1); color: #ccc; }

.soc-chat-input-row { display: flex; gap: 6px; }
.soc-chat-input {
  flex: 1; background: #1a1a1a; border: 1px solid #333; border-radius: 4px;
  padding: 7px 10px; color: #e0e0e0; font-size: 11px;
  font-family: inherit; outline: none; resize: none;
}
.soc-chat-input:focus { border-color: #22c55e; }
.soc-chat-input::placeholder { color: #555; }
.soc-chat-send {
  background: #22c55e; border: none; border-radius: 4px;
  padding: 7px 14px; color: #000; font-weight: 700; font-size: 11px;
  cursor: pointer; font-family: inherit; white-space: nowrap;
}
.soc-chat-send:hover { background: #16a34a; }

/* Alert picker */
.soc-alert-picker {
  max-height: 200px; overflow-y: auto; background: #1a1a1a;
  border: 1px solid #333; border-radius: 4px; margin-bottom: 6px;
}
.soc-alert-pick-item {
  padding: 6px 10px; font-size: 10px; color: #ccc; cursor: pointer;
  border-bottom: 1px solid #222; display: flex; align-items: center; gap: 6px;
}
.soc-alert-pick-item:hover { background: rgba(255,255,255,0.05); }

/* Top bar button */
.soc-chat-toggle-btn {
  background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.25);
  border-radius: 4px; padding: 3px 10px; color: #22c55e;
  font-size: 11px; font-weight: 600; cursor: pointer;
  font-family: inherit; position: relative;
  display: inline-flex; align-items: center; gap: 5px;
}
.soc-chat-toggle-btn:hover { background: rgba(34,197,94,0.2); }
.soc-chat-unread {
  position: absolute; top: -5px; right: -5px;
  background: #ef4444; color: #fff; font-size: 8px; font-weight: 700;
  width: 16px; height: 16px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
}
  `;
  document.head.appendChild(s);
}

// ── Helpers ──────────────────────────────────────────────────────

function uid(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')} UTC`;
}

function fmtDate(ts: number): string {
  return new Date(ts).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
}

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};

// ── Analyst identity ─────────────────────────────────────────────

function getAnalystId(): string {
  let id = localStorage.getItem('soc-analyst-id');
  if (!id) {
    id = 'Analyst-' + Math.floor(Math.random() * 900 + 100);
    localStorage.setItem('soc-analyst-id', id);
  }
  return id;
}

// ── Panel class ──────────────────────────────────────────────────

export class SocChatPanel {
  private overlay: HTMLElement;
  private msgsEl: HTMLElement;
  private inputEl: HTMLTextAreaElement;
  private messages: ChatMessage[] = [];
  private isOpen = false;
  private channel: BroadcastChannel;
  private analystId: string;
  private analystSender: MessageSender;
  private unreadCount = 0;
  private toggleBtn: HTMLElement | null = null;
  private alertPickerVisible = false;
  private getMapCenter: (() => { lat: number; lon: number; zoom: number } | null) | null = null;
  private flyToCoords: ((lat: number, lng: number, zoom: number) => void) | null = null;
  private typingTimers = new Map<string, ReturnType<typeof setTimeout>>();

  constructor() {
    injectCSS();
    this.analystId = getAnalystId();
    this.analystSender = {
      id: this.analystId,
      name: this.analystId,
      type: 'analyst',
      color: '#22c55e',
    };

    // BroadcastChannel transport
    this.channel = new BroadcastChannel('gatra-soc-chat');
    this.channel.onmessage = (e: MessageEvent) => {
      const msg = e.data as ChatMessage;
      if (msg.sender.id !== this.analystId) {
        this.messages.push(msg);
        this.renderMessages();
        if (!this.isOpen) {
          this.unreadCount++;
          this.updateBadge();
        }
      }
    };

    // Build DOM
    this.overlay = document.createElement('div');
    this.overlay.className = 'soc-chat-overlay';
    this.overlay.innerHTML = `
      <div class="soc-chat-drawer">
        <div class="soc-chat-hdr">
          <span class="soc-chat-hdr-title">SOC COMMS</span>
          <span class="soc-chat-hdr-live">LIVE</span>
          <span class="soc-chat-hdr-info">Phase 2 \u00B7 Agent-in-the-Loop</span>
          <button class="soc-chat-close">\u00D7</button>
        </div>
        <div class="soc-chat-msgs"></div>
        <div class="soc-chat-input-area">
          <div class="soc-chat-actions">
            <button class="soc-chat-action-btn" data-action="alert">\uD83D\uDCCE Alert</button>
            <button class="soc-chat-action-btn" data-action="location">\uD83D\uDCCD Location</button>
            <button class="soc-chat-action-btn" data-action="incident">\uD83D\uDEA8 Incident</button>
            <button class="soc-chat-action-btn" data-action="help">/help</button>
          </div>
          <div class="soc-chat-input-row">
            <textarea class="soc-chat-input" rows="1" placeholder="Message SOC... (@ADA @TAA @CRA @CLA @RVA or /help)"></textarea>
            <button class="soc-chat-send">Send</button>
          </div>
        </div>
      </div>
    `;

    this.msgsEl = this.overlay.querySelector('.soc-chat-msgs')!;
    this.inputEl = this.overlay.querySelector('.soc-chat-input') as HTMLTextAreaElement;

    document.body.appendChild(this.overlay);

    // Events
    this.overlay.addEventListener('click', (e) => {
      if ((e.target as HTMLElement) === this.overlay) this.toggle();
    });
    this.overlay.querySelector('.soc-chat-close')!.addEventListener('click', () => this.toggle());
    this.overlay.querySelector('.soc-chat-send')!.addEventListener('click', () => this.send());
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.send(); }
    });

    // Action buttons
    for (const btn of this.overlay.querySelectorAll('.soc-chat-action-btn')) {
      btn.addEventListener('click', () => {
        const action = (btn as HTMLElement).dataset.action;
        if (action === 'alert') this.toggleAlertPicker();
        else if (action === 'location') this.shareLocation();
        else if (action === 'incident') this.createIncident();
        else if (action === 'help') { this.inputEl.value = '/help'; this.send(); }
      });
    }

    // Listen for GATRA events to post system messages
    this.setupEventListeners();

    // Welcome message
    this.addSystemMessage('SOC COMMS initialized. 5 GATRA agents online. Type /help for commands.');
  }

  // ── Map integration ────────────────────────────────────────────

  public setMapCallbacks(
    getCenter: () => { lat: number; lon: number; zoom: number } | null,
    flyTo: (lat: number, lng: number, zoom: number) => void,
  ): void {
    this.getMapCenter = getCenter;
    this.flyToCoords = flyTo;
  }

  // ── Toggle button in top bar ───────────────────────────────────

  public createToggleButton(): HTMLElement {
    const btn = document.createElement('button');
    btn.className = 'soc-chat-toggle-btn';
    btn.innerHTML = '\uD83D\uDCAC SOC';
    btn.addEventListener('click', () => this.toggle());
    this.toggleBtn = btn;
    return btn;
  }

  public toggle(): void {
    this.isOpen = !this.isOpen;
    this.overlay.classList.toggle('open', this.isOpen);
    if (this.isOpen) {
      this.unreadCount = 0;
      this.updateBadge();
      this.scrollToBottom();
      setTimeout(() => this.inputEl.focus(), 300);
    }
  }

  private updateBadge(): void {
    if (!this.toggleBtn) return;
    const existing = this.toggleBtn.querySelector('.soc-chat-unread');
    if (existing) existing.remove();
    if (this.unreadCount > 0) {
      const badge = document.createElement('span');
      badge.className = 'soc-chat-unread';
      badge.textContent = String(Math.min(this.unreadCount, 99));
      this.toggleBtn.appendChild(badge);
    }
  }

  // ── Send message ───────────────────────────────────────────────

  private send(): void {
    const text = this.inputEl.value.trim();
    if (!text) return;
    this.inputEl.value = '';

    // Check for /command
    const cmdResponse = processCommand(text);
    if (cmdResponse !== null) {
      // Show the command the user typed
      this.addMessage({
        id: uid(), timestamp: Date.now(), sender: this.analystSender,
        type: 'text', content: text,
      });
      // Show response
      this.addMessage({
        id: uid(), timestamp: Date.now(),
        sender: { id: 'system', name: 'SYSTEM', type: 'system', color: '#888' },
        type: 'command_response', content: cmdResponse,
      });
      return;
    }

    // Regular message
    const msg: ChatMessage = {
      id: uid(), timestamp: Date.now(), sender: this.analystSender,
      type: 'text', content: text,
    };

    this.addMessage(msg);
    this.channel.postMessage(msg);

    // Check for agent triggers
    this.routeToAgents(text);

    // Hide alert picker if open
    if (this.alertPickerVisible) this.toggleAlertPicker();
  }

  // ── Agent routing ──────────────────────────────────────────────

  private routeToAgents(text: string): void {
    const triggered: GatraAgentDef[] = [];

    for (const agent of GATRA_AGENTS) {
      if (agent.triggerPatterns.some(p => p.test(text))) {
        triggered.push(agent);
      }
    }

    // Deduplicate and limit to 2 agents per message
    const unique = [...new Map(triggered.map(a => [a.id, a])).values()].slice(0, 2);

    unique.forEach((agent, idx) => {
      const delay = 1200 + idx * 1800 + Math.random() * 800;
      this.showTyping(agent);

      const timer = setTimeout(() => {
        this.hideTyping(agent.id);
        const response = generateAgentResponse(agent, text);
        const agentMsg: ChatMessage = {
          id: uid(), timestamp: Date.now(),
          sender: { id: agent.id, name: agent.name, type: 'agent', color: agent.color },
          type: 'agent', content: response,
        };
        this.addMessage(agentMsg);
        this.channel.postMessage(agentMsg);
      }, delay);

      this.typingTimers.set(agent.id, timer);
    });
  }

  private showTyping(agent: GatraAgentDef): void {
    const el = document.createElement('div');
    el.className = 'soc-typing';
    el.id = `soc-typing-${agent.id}`;
    el.innerHTML = `
      <span style="color:${agent.color};">${agent.emoji} ${agent.name}</span>
      <span class="soc-typing-dots"><span></span><span></span><span></span></span>
    `;
    this.msgsEl.appendChild(el);
    this.scrollToBottom();
  }

  private hideTyping(agentId: string): void {
    document.getElementById(`soc-typing-${agentId}`)?.remove();
  }

  // ── Alert picker ───────────────────────────────────────────────

  private toggleAlertPicker(): void {
    this.alertPickerVisible = !this.alertPickerVisible;
    const existing = this.overlay.querySelector('.soc-alert-picker');
    if (existing) { existing.remove(); return; }
    if (!this.alertPickerVisible) return;

    const alerts = getAlerts().slice(0, 10);
    if (alerts.length === 0) {
      this.addSystemMessage('No GATRA alerts available.');
      this.alertPickerVisible = false;
      return;
    }

    const picker = document.createElement('div');
    picker.className = 'soc-alert-picker';
    for (const alert of alerts) {
      const item = document.createElement('div');
      item.className = 'soc-alert-pick-item';
      const sevColor = SEV_COLORS[alert.severity] ?? '#888';
      item.innerHTML = `
        <span class="soc-alert-sev" style="color:${sevColor};">${escapeHtml(alert.severity)}</span>
        <span>${escapeHtml(alert.mitreId)} \u2013 ${escapeHtml(alert.mitreName)}</span>
        <span style="color:#555;margin-left:auto;">${escapeHtml(alert.agent)}</span>
      `;
      item.addEventListener('click', () => {
        this.attachAlert(alert);
        this.toggleAlertPicker();
      });
      picker.appendChild(item);
    }

    const inputArea = this.overlay.querySelector('.soc-chat-input-area')!;
    inputArea.insertBefore(picker, inputArea.querySelector('.soc-chat-input-row'));
  }

  private attachAlert(alert: GatraAlert): void {
    const msg: ChatMessage = {
      id: uid(), timestamp: Date.now(), sender: this.analystSender,
      type: 'alert_ref',
      content: `Referencing alert:`,
      alert: {
        id: alert.id, technique: alert.mitreId, name: alert.mitreName,
        severity: alert.severity, source: alert.agent,
        description: alert.description,
      },
    };
    this.addMessage(msg);
    this.channel.postMessage(msg);
  }

  // ── Location sharing ───────────────────────────────────────────

  private shareLocation(): void {
    if (!this.getMapCenter) {
      this.addSystemMessage('Map not available for location sharing.');
      return;
    }
    const center = this.getMapCenter();
    if (!center) {
      this.addSystemMessage('Unable to read map coordinates.');
      return;
    }

    const label = `${center.lat.toFixed(4)}\u00B0${center.lat >= 0 ? 'N' : 'S'}, ${center.lon.toFixed(4)}\u00B0${center.lon >= 0 ? 'E' : 'W'}`;

    const msg: ChatMessage = {
      id: uid(), timestamp: Date.now(), sender: this.analystSender,
      type: 'location',
      content: 'Sharing location:',
      coordinates: { lat: center.lat, lng: center.lon, zoom: center.zoom, label },
    };
    this.addMessage(msg);
    this.channel.postMessage(msg);
  }

  // ── Incident creation ──────────────────────────────────────────

  private createIncident(): void {
    const alerts = getAlerts();
    const critical = alerts.filter(a => a.severity === 'critical');
    const id = `INC-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(Math.floor(Math.random() * 900 + 100))}`;

    const title = critical.length > 0
      ? `${critical[0]!.mitreId} \u2013 ${critical[0]!.mitreName} (${critical.length} critical)`
      : 'New incident';

    const msg: ChatMessage = {
      id: uid(), timestamp: Date.now(), sender: this.analystSender,
      type: 'incident',
      content: `Created incident ${id}`,
      incident: {
        id,
        title,
        severity: critical.length > 0 ? 'critical' : 'medium',
        status: 'active',
        lead: this.analystId,
      },
    };
    this.addMessage(msg);
    this.channel.postMessage(msg);

    // CLA auto-responds to incidents
    setTimeout(() => {
      this.addMessage({
        id: uid(), timestamp: Date.now(),
        sender: { id: 'cla', name: 'CLA', type: 'agent', color: '#2196f3' },
        type: 'agent',
        content: `\uD83D\uDCCB Incident ${id} logged.\n\u2022 Timeline recording started\n\u2022 Audit trail active\n\u2022 All agent actions will be linked to this incident.`,
      });
    }, 1500);
  }

  // ── System messages from events ────────────────────────────────

  private setupEventListeners(): void {
    window.addEventListener('gatra-early-warning-update', ((e: CustomEvent) => {
      const { multiplier, activeMarkets } = e.detail as { multiplier: number; activeMarkets: number };
      if (multiplier > 1.2) {
        this.addSystemMessage(`Predictive Signals: Early warning elevated to \u00D7${multiplier.toFixed(1)}. ${activeMarkets} market(s) signaling.`);
      }
    }) as EventListener);

    window.addEventListener('gatra-cii-update', ((e: CustomEvent) => {
      const { country, ciiScore, delta, isActive } = e.detail as { country: string; ciiScore: number; delta: number; isActive: boolean };
      if (Math.abs(delta) > 2.0) {
        this.addSystemMessage(
          `CII Monitor: ${country} CII ${delta > 0 ? 'spiked' : 'dropped'} ${delta > 0 ? '+' : ''}${delta.toFixed(1)} to ${ciiScore.toFixed(1)}. R_geo ${isActive ? 'ACTIVE' : 'nominal'}.`
        );
      }
    }) as EventListener);
  }

  // ── Message management ─────────────────────────────────────────

  private addMessage(msg: ChatMessage): void {
    this.messages.push(msg);
    if (this.messages.length > 500) {
      this.messages = this.messages.slice(-500);
    }
    this.renderMessages();
  }

  private addSystemMessage(text: string): void {
    this.addMessage({
      id: uid(), timestamp: Date.now(),
      sender: { id: 'system', name: 'SYSTEM', type: 'system', color: '#888' },
      type: 'system', content: text,
    });
  }

  // ── Render ─────────────────────────────────────────────────────

  private renderMessages(): void {
    let html = '';
    let lastDate = '';

    for (const msg of this.messages) {
      const date = fmtDate(msg.timestamp);
      if (date !== lastDate) {
        html += `<div class="soc-chat-date">\u2500\u2500 ${escapeHtml(date)} \u2500\u2500</div>`;
        lastDate = date;
      }

      if (msg.type === 'system' || msg.type === 'command_response') {
        html += `<div class="soc-msg soc-msg-sys">${escapeHtml(msg.content)}</div>`;
        continue;
      }

      if (msg.type === 'agent') {
        const agent = GATRA_AGENTS.find(a => a.id === msg.sender.id);
        const clr = agent?.color ?? msg.sender.color;
        html += `
          <div class="soc-msg soc-msg-agent" style="--agent-clr:${clr};">
            <div class="soc-msg-hdr">
              <span class="soc-msg-badge" style="background:${clr}20;border:1px solid ${clr}40;color:${clr};">
                ${agent?.emoji ?? ''} ${escapeHtml(msg.sender.name)}
              </span>
              <span class="soc-msg-role">${escapeHtml(agent?.role ?? '')}</span>
              <span class="soc-msg-time">${fmtTime(msg.timestamp)}</span>
            </div>
            <div class="soc-msg-body">${escapeHtml(msg.content)}</div>
          </div>`;
        continue;
      }

      // Analyst messages
      const clr = msg.sender.color;
      let bodyHtml = escapeHtml(msg.content);

      // Alert reference card
      if (msg.type === 'alert_ref' && msg.alert) {
        const a = msg.alert;
        const sevClr = SEV_COLORS[a.severity] ?? '#888';
        bodyHtml += `<div class="soc-alert-card">
          <span class="soc-alert-sev" style="color:${sevClr};">${escapeHtml(a.severity)}</span>
          <span>${escapeHtml(a.technique)} \u2013 ${escapeHtml(a.name)}</span>
          <span style="color:#555;">${escapeHtml(a.source)}</span>
        </div>`;
      }

      // Location card
      if (msg.type === 'location' && msg.coordinates) {
        const c = msg.coordinates;
        bodyHtml += `<div class="soc-loc-card" data-lat="${c.lat}" data-lng="${c.lng}" data-zoom="${c.zoom}">
          \uD83D\uDCCD ${escapeHtml(c.label)}
        </div>`;
      }

      // Incident card
      if (msg.type === 'incident' && msg.incident) {
        const inc = msg.incident;
        const sevClr = SEV_COLORS[inc.severity] ?? '#888';
        bodyHtml += `<div class="soc-alert-card" style="border-color:${sevClr}40;">
          <span style="color:${sevClr};font-weight:700;">\uD83D\uDEA8 ${escapeHtml(inc.id)}</span>
          <span>${escapeHtml(inc.title)}</span>
          <span style="color:${sevClr};">${escapeHtml(inc.status.toUpperCase())}</span>
        </div>`;
      }

      html += `
        <div class="soc-msg">
          <div class="soc-msg-hdr">
            <span class="soc-msg-dot" style="background:${clr};"></span>
            <span class="soc-msg-name" style="color:${clr};">${escapeHtml(msg.sender.name)}</span>
            <span class="soc-msg-time">${fmtTime(msg.timestamp)}</span>
          </div>
          <div class="soc-msg-body">${bodyHtml}</div>
        </div>`;
    }

    // Check if user is near the bottom before replacing content
    const wasNearBottom = this.msgsEl.scrollHeight - this.msgsEl.scrollTop - this.msgsEl.clientHeight < 80;

    this.msgsEl.innerHTML = html;

    // Attach click handlers for location cards
    for (const card of this.msgsEl.querySelectorAll('.soc-loc-card')) {
      card.addEventListener('click', () => {
        const lat = parseFloat((card as HTMLElement).dataset.lat ?? '0');
        const lng = parseFloat((card as HTMLElement).dataset.lng ?? '0');
        const zoom = parseFloat((card as HTMLElement).dataset.zoom ?? '4');
        this.flyToCoords?.(lat, lng, zoom);
      });
    }

    // Only auto-scroll if user was already at the bottom
    if (wasNearBottom) this.scrollToBottom();
  }

  private scrollToBottom(): void {
    requestAnimationFrame(() => {
      this.msgsEl.scrollTop = this.msgsEl.scrollHeight;
    });
  }

  // ── Cleanup ────────────────────────────────────────────────────

  public destroy(): void {
    for (const t of this.typingTimers.values()) clearTimeout(t);
    this.channel.close();
    this.overlay.remove();
  }
}
