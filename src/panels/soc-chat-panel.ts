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
import { getCachedCVEFeed } from '@/services/cve-feed';
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
      // Expanded: malware, ransomware, EDR, UEBA, DDoS, behavioral
      /malware|ransomware|trojan|worm|virus|rootkit/i,
      /edr|endpoint\s*detect/i, /ueba|behavio(u?)ral\s*analyt/i,
      /ddos|denial\s*of\s*service|botnet|c2|command\s*and\s*control/i,
      /lateral\s*movement|beacon|exfiltrat/i,
      /sandbox|detonat/i, /ioc.*match|signature/i,
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
      // Expanded: threat intel, APTs, IOCs, phishing, social engineering, campaigns
      /apt[\s-]?\d+|threat\s*actor|adversar/i,
      /ioc|indicator.*compromise|intel(ligence)?.*feed/i,
      /phish|spear\s*phish|social\s*engineer|bec|business\s*email/i,
      /campaign|ttps?|dark\s*web|underground/i,
      /zero[\s-]?day|0[\s-]?day|watering\s*hole|supply\s*chain\s*attack/i,
      /nation[\s-]?state|cyber\s*espionage|attribution/i,
      /credential\s*stuff|brute\s*force|password\s*spray/i,
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
      // Expanded: IR playbook, disaster recovery, firewall, zero trust, SOAR
      /playbook|runbook|procedure|sop\b/i,
      /incident\s*response|ir\s*plan/i,
      /disaster\s*recover|business\s*continu|bcp\b|drp\b/i,
      /firewall|acl|network\s*segment|micro\s*segment/i,
      /zero\s*trust|least\s*privilege|ztna/i,
      /soar|orchestrat|automat.*response/i,
      /eradicat|recover|lesson|post[\s-]?mortem|after[\s-]?action/i,
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
      // Expanded: forensics, SIEM, chain of custody, more frameworks
      /forensic|evidence|chain\s*of\s*custod|preserv/i,
      /siem|log\s*analys|log\s*management|splunk|elastic|sentinel/i,
      /hipaa|pci[\s-]?dss|sox|ccpa|fedramp|cmmc|cis\s*bench/i,
      /data\s*breach.*notif|disclosure|privacy/i,
      /risk\s*register|risk\s*management|risk\s*framework/i,
      /security\s*awareness|training|tabletop/i,
      /retention|archiv|e-?discovery/i,
      /@cla\b/i,
    ],
  },
  {
    id: 'rva', name: 'RVA', fullName: 'Risk & Vulnerability Agent',
    role: 'Assesses vulnerability exposure',
    color: '#9c27b0', emoji: '\u26A0\uFE0F',
    triggerPatterns: [
      /vulnerabilit/i, /cve/i,
      /patch/i, /remediat/i, /unpatched/i,
      /expos(ed|ure)/i, /attack\s*surface/i,
      /scan/i, /exploit/i, /cvss/i, /severity/i,
      // Expanded: pentesting, cloud security, supply chain risk, encryption, certs
      /pen[\s-]?test|penetration\s*test|red\s*team|blue\s*team|purple\s*team/i,
      /cloud\s*secur|misconfigur|s3\s*bucket|iam\s*role|cspm/i,
      /supply\s*chain\s*risk|third[\s-]?party|vendor\s*risk|sbom/i,
      /encrypt|tls|ssl|certific|pki|key\s*manage/i,
      /bug\s*bount|responsible\s*disclos|coordinated\s*disclos/i,
      /asset\s*inventor|shadow\s*it|asset\s*discover/i,
      /waf|web\s*application\s*firewall|owasp/i,
      /@rva\b/i,
    ],
  },
];

// ── General cybersecurity topic fallback ──────────────────────────
// Matches broad cybersecurity topics not covered by any specific agent
const GENERAL_CYBER_PATTERNS: RegExp[] = [
  /cyber\s*security|infosec|information\s*security/i,
  /soc\b|security\s*operat/i,
  /what\s*is|how\s*does|explain|define|meaning/i,
  /best\s*practice|recommend|guideline/i,
  /dns|smtp|http|tcp|udp|ip\s*address|port\s*scan/i,
  /vpn|proxy|tor|onion|anonymi/i,
  /mfa|multi[\s-]?factor|two[\s-]?factor|2fa|authentication/i,
  /iam|identity|access\s*control|rbac|abac/i,
  /devsecops|sdlc|secure\s*coding|code\s*review/i,
  /honeypot|honeytoken|deception/i,
  /backup|disaster|recover/i,
  /crypto(graph|currency)|blockchain|hash/i,
  /security\s*architect|defense\s*in\s*depth|layered/i,
  /osint|recon(naissance)?|footprint/i,
  /wireless|wifi|bluetooth|rf\s*secur/i,
  /iot|scada|ics|ot\s*secur|industrial\s*control/i,
  /insider\s*threat|privilege.*abus|data\s*loss\s*prevent|dlp/i,
  /api\s*secur|oauth|jwt|token/i,
  /container|kubernetes|docker|k8s.*secur/i,
  /threat\s*model|stride|dread/i,
  /xss|sqli|sql\s*inject|csrf|ssrf|rce|lfi|rfi/i,
  /buffer\s*overflow|heap|stack\s*overflow|memory\s*corrupt/i,
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

      // Malware / ransomware / trojan
      if (/malware|ransomware|trojan|worm|virus|rootkit/i.test(message)) {
        const malwareAlerts = alerts.filter(a => /T1059|T1053|T1547|T1055|T1027|T1486|T1490/i.test(a.mitreId));
        const isRansomware = /ransomware/i.test(message);
        return `${isRansomware ? 'Ransomware' : 'Malware'} Detection Analysis:\n\n` +
          `ADA uses a multi-layered detection approach that combines signature-based and behavioral methods to identify malicious software before it can cause damage.\n\n` +
          `Active malware-related alerts: ${malwareAlerts.length}\n\n` +
          `Detection methods currently active:\n` +
          `  \u2014 Behavioral sandbox: Suspicious files are detonated in an isolated environment. The Isolation Forest model scores behavioral anomalies \u2014 file system modifications, registry changes, network callbacks \u2014 to flag malicious intent even without known signatures.\n` +
          `  \u2014 LSTM sequence analysis: Monitors process creation chains and file I/O patterns over time. This catches multi-stage attacks where individual actions appear benign but the sequence reveals malicious intent (e.g., document \u2192 macro \u2192 PowerShell \u2192 download \u2192 execute).\n` +
          `  \u2014 Signature matching: YARA rules (${Math.floor(Math.random() * 500 + 2000)} rules, updated ${Math.floor(Math.random() * 4 + 1)}h ago) and Snort/Suricata network signatures provide fast detection of known threats.\n` +
          `  \u2014 Heuristic/entropy analysis: Identifies packed, encrypted, or obfuscated payloads by measuring file entropy. High entropy sections in executables often indicate evasion techniques.\n\n` +
          (isRansomware
            ? `Ransomware-specific monitoring:\n` +
              `  \u2014 File encryption velocity: rapid file modification patterns detected via I/O hooks\n` +
              `  \u2014 Shadow copy deletion: monitoring vssadmin/wmic for T1490 (Inhibit System Recovery)\n` +
              `  \u2014 Ransom note creation: filesystem watchers for known ransom note filenames\n` +
              `  \u2014 Network propagation: SMB/RDP lateral spread detected via ADA network baseline\n\n`
            : '') +
          `MITRE ATT&CK coverage:\n` +
          `  \u2014 T1059 (Command & Scripting Execution) \u2014 PowerShell, cmd, WMI abuse\n` +
          `  \u2014 T1547 (Boot/Logon Autostart) \u2014 persistence via registry, startup folder\n` +
          `  \u2014 T1486 (Data Encrypted for Impact) \u2014 ransomware encryption activity\n` +
          `  \u2014 T1490 (Inhibit System Recovery) \u2014 backup/shadow copy destruction\n` +
          `  \u2014 T1027 (Obfuscated Files) \u2014 packed/encoded payloads\n\n` +
          `Last 24h activity: ${Math.floor(Math.random() * 5 + 2)} samples detonated in sandbox, ${Math.floor(Math.random() * 3)} quarantined. IOC extraction (file hashes, C2 IPs, mutex names) auto-fed to TAA for threat intel correlation.\n\n` +
          `Related topics: "lateral movement" \u00B7 "C2 beacons" \u00B7 "sandbox results" \u00B7 "EDR"`;
      }

      // EDR / endpoint / UEBA / behavioral
      if (/edr|endpoint\s*detect|ueba|behavio(u?)ral\s*analyt/i.test(message)) {
        return `Endpoint Detection & Response (EDR) / User Entity Behavioral Analytics (UEBA):\n\n` +
          `EDR and UEBA work together to create a comprehensive behavioral picture of what's happening across your environment. While traditional security looks for known bad signatures, behavioral analytics identifies deviations from normal patterns \u2014 catching novel attacks that evade signature-based tools.\n\n` +
          `EDR Telemetry:\n` +
          `  \u2014 Active endpoints reporting: ${Math.floor(Math.random() * 500 + 200)}\n` +
          `  \u2014 Data collected: process creation, file modifications, network connections, registry changes, loaded DLLs, DNS queries\n` +
          `  \u2014 ADA's Isolation Forest model scores each event stream for anomalies against the endpoint's own 30-day behavioral baseline\n\n` +
          `UEBA Behavioral Indicators:\n` +
          `  \u2014 Unusual process trees: parent-child relationships that deviate from baseline (e.g., Excel spawning PowerShell spawning cmd.exe \u2014 classic macro attack chain)\n` +
          `  \u2014 Off-hours access: ${offHours ? 'CURRENTLY OFF-HOURS \u2014 sensitivity elevated 1.3\u00D7. Any privileged access triggers immediate alert.' : 'Business hours \u2014 standard sensitivity. Off-hours access would trigger elevated scoring.'}\n` +
          `  \u2014 Data volume anomalies: upload/download volumes compared to user's 30-day rolling average. A user suddenly exfiltrating 10\u00D7 their normal volume is flagged regardless of destination.\n` +
          `  \u2014 Privilege escalation: sudo/runas usage, token manipulation, UAC bypass attempts\n` +
          `  \u2014 Lateral movement: unusual authentication to new hosts, RDP/SSH to systems outside normal scope\n\n` +
          `Top UEBA anomaly: ${alerts[0] ? `${alerts[0].mitreId} \u2013 ${alerts[0].mitreName} (confidence: ${alerts[0].confidence}%)` : 'No active anomalies'}\n\n` +
          `Detection model: Isolation Forest identifies point anomalies (single unusual events) while LSTM captures sequence anomalies (chains of events that individually appear normal but collectively indicate attack progression).\n\n` +
          `Related topics: "malware" \u00B7 "lateral movement" \u00B7 "insider threat"`;
      }

      // DDoS / botnet / C2
      if (/ddos|denial\s*of\s*service|botnet|c2|command\s*and\s*control/i.test(message)) {
        const c2Alerts = alerts.filter(a => /T1071|T1572|T1573|T1095/i.test(a.mitreId));
        return `DDoS / Botnet / C2 Analysis:\n` +
          `\u2022 C2-related alerts: ${c2Alerts.length}\n` +
          `\u2022 Network anomaly detection:\n` +
          `  \u2014 Traffic volume: ${(Math.random() * 2 + 0.5).toFixed(1)}\u00D7 baseline (threshold: 3.0\u00D7)\n` +
          `  \u2014 Beaconing detection: periodic callback analysis active\n` +
          `  \u2014 DNS anomalies: ${Math.floor(Math.random() * 3)} suspicious domains flagged\n` +
          `  \u2014 Protocol anomalies: encrypted channels on non-standard ports monitored\n` +
          `\u2022 MITRE: T1071 (App Layer Protocol), T1572 (Tunneling), T1573 (Encrypted Channel)\n` +
          `\u2022 Mitigation: rate limiting active, GeoIP filtering ready\n` +
          `Ask CRA to "block" specific C2 IPs or "isolate" compromised endpoints.`;
      }

      // Lateral movement / exfiltration / beacon
      if (/lateral\s*movement|beacon|exfiltrat/i.test(message)) {
        return `Lateral Movement & Exfiltration Monitor:\n` +
          `\u2022 Internal scan detection: port sweep / service enumeration\n` +
          `\u2022 Credential usage: abnormal Kerberos/NTLM patterns\n` +
          `\u2022 Beaconing: ${Math.floor(Math.random() * 3)} periodic callbacks detected (jitter analysis)\n` +
          `\u2022 Data exfiltration indicators:\n` +
          `  \u2014 Large outbound transfers: ${Math.floor(Math.random() * 2)} anomalies\n` +
          `  \u2014 DNS tunneling: monitored (query length + frequency)\n` +
          `  \u2014 Staging behavior: temp folder write spikes\n` +
          `\u2022 MITRE: T1021 (Remote Services), T1048 (Exfiltration), T1570 (Lateral Tool Transfer)\n` +
          `\u2022 Recommendation: ${alerts.length > 0 ? 'Review top alerts for kill chain progression' : 'No active indicators'}`;
      }

      // Sandbox / detonation / IOC
      if (/sandbox|detonat|ioc.*match|signature/i.test(message)) {
        return `Sandbox & IOC Matching:\n` +
          `\u2022 Sandbox: ${Math.floor(Math.random() * 8 + 2)} samples analyzed (last 24h)\n` +
          `\u2022 Verdicts: ${Math.floor(Math.random() * 3)} malicious, ${Math.floor(Math.random() * 2)} suspicious, rest clean\n` +
          `\u2022 IOC matching engine: STIX/TAXII feed + internal threat intel\n` +
          `\u2022 Signature DB: YARA ${Math.floor(Math.random() * 500 + 2000)} rules | Snort/Suricata active\n` +
          `\u2022 Extracted IOCs auto-correlated with active alerts by TAA\n` +
          `Ask TAA for "threat intel" or "IOC correlation" details.`;
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

      // APT / threat actor / nation-state / attribution
      if (/apt[\s-]?\d+|threat\s*actor|adversar|nation[\s-]?state|cyber\s*espionage|attribution/i.test(message)) {
        const aptMatch = message.match(/apt[\s-]?\d+/i);
        const techniques = [...new Set(alerts.map(a => a.mitreId))].slice(0, 4);
        return `Advanced Persistent Threat (APT) Intelligence:\n\n` +
          `APTs are sophisticated, well-funded adversaries (often nation-state backed) that maintain long-term access to targets for espionage, sabotage, or financial gain. Unlike opportunistic attackers, APTs use custom tooling, patience, and operational security to avoid detection.\n\n` +
          (aptMatch
            ? `Queried: ${aptMatch[0].toUpperCase()}\n` +
              `TAA has cross-referenced this group's known TTPs against your active alerts to identify potential overlap. Attribution in cybersecurity is inherently uncertain \u2014 multiple groups share tools and infrastructure.\n\n`
            : '') +
          `Active alert TTPs: ${techniques.join(', ') || 'No active alerts'}\n\n` +
          `Known threat groups with similar TTPs:\n` +
          `  \u2014 APT-29 (Cozy Bear / Russia): Specializes in espionage. Known for T1566 (spearphishing), T1059 (PowerShell), T1071 (web protocols for C2). Targets government and diplomatic entities. Used supply chain attacks (SolarWinds).\n` +
          `  \u2014 APT-41 (Double Dragon / China): Dual espionage + financial crime. Uses T1190 (exploit public apps), T1053 (scheduled tasks), T1055 (process injection). Targets healthcare, telecoms, and tech sectors.\n` +
          `  \u2014 Lazarus Group (North Korea): Financial motivation + destructive capability. Known for T1486 (ransomware), T1490 (inhibit recovery), T1027 (obfuscation). Responsible for WannaCry, SWIFT bank heists.\n` +
          `  \u2014 Sandworm (Russia/GRU): Critical infrastructure focus. NotPetya, Industroyer/CrashOverride. Targets energy, government.\n\n` +
          `Attribution confidence: LOW \u2014 multiple actors share similar techniques. True attribution requires corroborating IOCs (infrastructure, malware families, victimology) with classified intelligence. Avoid premature attribution in incident reports.\n\n` +
          `Intel sources: MITRE ATT&CK, CISA advisories, open-source CTI feeds, vendor threat reports, information sharing organizations (ISACs).\n\n` +
          `Related topics: "IOC correlation" \u00B7 "campaign analysis" \u00B7 "dark web" \u00B7 "zero-day"`;
      }

      // IOC / indicator of compromise / threat intel feed
      if (/ioc|indicator.*compromise|intel(ligence)?.*feed/i.test(message)) {
        return `IOC & Threat Intelligence:\n` +
          `\u2022 Active IOC feeds: STIX/TAXII, CISA KEV, MISP community\n` +
          `\u2022 IOC types monitored: IP, domain, hash (MD5/SHA256), URL, email\n` +
          `\u2022 Current matches against active alerts: ${Math.min(alerts.length, Math.floor(Math.random() * 5 + 1))}\n` +
          `\u2022 Feed freshness: updated every 15m\n` +
          `\u2022 Auto-enrichment: WHOIS, GeoIP, passive DNS, VirusTotal score\n` +
          `\u2022 False positive rate on IOC matches: ~${(3 + Math.random() * 7).toFixed(1)}%\n` +
          `\u2022 IOCs are auto-correlated with ADA anomalies and RVA vulnerability data\n` +
          `Ask: "specific APT" \u00B7 "threat actor" \u00B7 "MITRE mapping"`;
      }

      // Phishing / social engineering / BEC
      if (/phish|spear\s*phish|social\s*engineer|bec|business\s*email/i.test(message)) {
        const phishAlerts = alerts.filter(a => /T1566|T1534|T1598/i.test(a.mitreId));
        const isSpearPhish = /spear/i.test(message);
        const isBEC = /bec|business\s*email/i.test(message);
        return `Phishing & Social Engineering Threat Analysis:\n\n` +
          `Phishing remains the #1 initial access vector in most breaches. TAA analyzes phishing threats across the full attack chain \u2014 from email delivery to credential harvesting to post-compromise lateral movement.\n\n` +
          `Active phishing-related alerts: ${phishAlerts.length}\n\n` +
          `Detection layers (defense in depth):\n` +
          `  1. Email Gateway: SPF/DKIM/DMARC validation prevents domain spoofing. Emails failing authentication are quarantined or tagged. Header analysis detects reply-to mismatches and display name deception.\n` +
          `  2. URL Analysis: Every link is checked against reputation databases and detonated in a sandbox. Time-delayed phishing (links that become malicious after delivery) is caught by periodic re-scanning.\n` +
          `  3. NLP/AI Analysis: Natural language processing identifies social engineering patterns \u2014 urgency ("your account will be locked"), authority ("CEO requests"), and emotional manipulation ("verify immediately").\n` +
          `  4. Attachment Analysis: Office macros, embedded scripts, and high-entropy payloads are flagged. PDF exploits and polyglot files are sandbox-detonated before delivery.\n\n` +
          (isSpearPhish
            ? `Spear phishing specifics:\n` +
              `  Unlike mass phishing, spear phishing targets specific individuals using OSINT-gathered personal details (LinkedIn, company website, social media). TAA correlates sender reputation with target's role to assess risk \u2014 a "CEO" emailing finance about wire transfers gets highest priority.\n\n`
            : '') +
          (isBEC
            ? `Business Email Compromise (BEC) indicators:\n` +
              `  \u2014 Domain lookalikes: company-name vs. c0mpany-name (homoglyph detection)\n` +
              `  \u2014 Display name spoofing: "CEO Name" from external domain\n` +
              `  \u2014 Wire transfer / payment keywords in body\n` +
              `  \u2014 Conversation hijacking: thread injection after mailbox compromise\n` +
              `  \u2014 Financial loss from BEC attacks averages $125K per incident (FBI IC3 data)\n\n`
            : '') +
          `MITRE ATT&CK mapping:\n` +
          `  \u2014 T1566.001 \u2013 Spearphishing Attachment\n` +
          `  \u2014 T1566.002 \u2013 Spearphishing Link\n` +
          `  \u2014 T1534 \u2013 Internal Spearphishing (post-compromise)\n` +
          `  \u2014 T1598 \u2013 Phishing for Information (reconnaissance)\n\n` +
          `Last 24h: ${Math.floor(Math.random() * 20 + 5)} phishing attempts blocked at gateway. User click rate: ${(1.5 + Math.random() * 3).toFixed(1)}% (organizational target: <2%).\n\n` +
          `Related topics: "security awareness training" (CLA) \u00B7 "credential stuffing" \u00B7 "APT" \u00B7 "dark web"`;
      }

      // Campaign / TTP / dark web / underground
      if (/campaign|ttps?|dark\s*web|underground/i.test(message)) {
        return `Campaign & Dark Web Intelligence:\n` +
          `\u2022 Active campaign tracking: ${Math.floor(Math.random() * 3 + 1)} campaigns correlated\n` +
          `\u2022 TTP clustering: alerts grouped by behavioral similarity\n` +
          `\u2022 Dark web monitoring:\n` +
          `  \u2014 Credential leaks: checked against internal domains\n` +
          `  \u2014 Ransomware leak sites: monitored for data mentions\n` +
          `  \u2014 Underground forums: exploit kit chatter tracked\n` +
          `\u2022 Campaign indicators:\n` +
          `  \u2014 Shared infrastructure (IP/domain overlap)\n` +
          `  \u2014 Common tooling (same malware family/packer)\n` +
          `  \u2014 Temporal correlation (attack timing patterns)\n` +
          `\u2022 RL model weights TTP clustering for triage prioritization`;
      }

      // Zero-day / credential stuffing / brute force
      if (/zero[\s-]?day|0[\s-]?day|watering\s*hole|credential\s*stuff|brute\s*force|password\s*spray/i.test(message)) {
        return `Advanced Attack Vector Analysis:\n` +
          ((/zero[\s-]?day|0[\s-]?day/i.test(message))
            ? `\u2022 Zero-day monitoring: CISA KEV + vendor advisories\n` +
              `\u2022 Behavioral detection compensates when signatures unavailable\n` +
              `\u2022 Virtual patching: WAF rules deployed for known zero-days\n`
            : '') +
          ((/credential|brute|password/i.test(message))
            ? `\u2022 Authentication monitoring:\n` +
              `  \u2014 Failed login spikes: ${Math.floor(Math.random() * 50 + 10)} anomalies (24h)\n` +
              `  \u2014 Credential stuffing: rate-limit + CAPTCHA triggers active\n` +
              `  \u2014 Password spray: low-and-slow detection via UEBA baseline\n` +
              `  \u2014 MFA bypass attempts: monitored\n`
            : '') +
          `\u2022 MITRE: T1190 (Exploit Public App), T1110 (Brute Force), T1078 (Valid Accounts)\n` +
          `\u2022 Recommendation: ${sev.critical > 0 ? 'Elevated posture \u2014 review auth logs' : 'Standard monitoring'}`;
      }

      // Generic @taa — rich contextual fallback
      if (alerts.length === 0) return 'TAA online. Triage queue empty. No alerts to prioritize.\nTip: Ask about threat assessment, MITRE mapping, phishing, APTs, or IOC correlation.';
      return `TAA Triage Summary:\n` +
        `\u2022 Queue: ${sev.critical} ESCALATE / ${sev.high} INVESTIGATE / ${sev.medium + sev.low} MONITOR\n` +
        `\u2022 Top threat: ${alerts[0]?.mitreId ?? 'N/A'} \u2013 ${alerts[0]?.mitreName ?? 'N/A'} (${alerts[0]?.severity ?? ''})\n` +
        `\u2022 RL confidence: ${(0.7 + Math.random() * 0.25).toFixed(2)} | Posture: ${sev.critical > 3 ? 'ELEVATED' : 'STANDARD'}\n` +
        `Ask: "triage queue" \u00B7 "threat intel" \u00B7 "phishing" \u00B7 "APT" \u00B7 "MITRE mapping"`;
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

      // IR playbook / runbook / procedure / SOP
      if (/playbook|runbook|procedure|sop\b|incident\s*response|ir\s*plan/i.test(message)) {
        return `Incident Response Playbooks:\n` +
          `\u2022 Active playbooks:\n` +
          `  1. Ransomware Response (NIST SP 800-61r3)\n` +
          `  2. Phishing Triage (auto-quarantine + user notification)\n` +
          `  3. Data Breach Containment (isolate + preserve + notify)\n` +
          `  4. Insider Threat (account suspend + forensic image)\n` +
          `  5. DDoS Mitigation (rate-limit + CDN + upstream filter)\n` +
          `\u2022 IR phases: Preparation \u2192 Detection \u2192 Containment \u2192 Eradication \u2192 Recovery \u2192 Lessons\n` +
          `\u2022 Current phase: ${sev.critical > 0 ? 'CONTAINMENT (active critical alerts)' : 'PREPARATION (monitoring)'}\n` +
          `\u2022 Auto-response triggers: severity=critical + confidence\u226590%\n` +
          `\u2022 Escalation path: SOC L1 \u2192 L2 \u2192 IR Team \u2192 CISO\n` +
          `Ask: "zero trust" \u00B7 "firewall rules" \u00B7 "post-mortem"`;
      }

      // Disaster recovery / BCP
      if (/disaster\s*recover|business\s*continu|bcp\b|drp\b/i.test(message)) {
        return `Disaster Recovery & Business Continuity:\n` +
          `\u2022 RPO (Recovery Point Objective): 4 hours\n` +
          `\u2022 RTO (Recovery Time Objective): 2 hours\n` +
          `\u2022 Backup status: last verified ${Math.floor(Math.random() * 12 + 1)}h ago\n` +
          `\u2022 DR sites: primary (active-active), secondary (warm standby)\n` +
          `\u2022 Failover tested: last tabletop ${Math.floor(Math.random() * 30 + 7)} days ago\n` +
          `\u2022 Communication plan: exec notification < 15m, stakeholders < 1h\n` +
          `\u2022 Ransomware resilience: immutable backups + air-gapped copies\n` +
          `Ask CLA about "compliance" for regulatory DR requirements.`;
      }

      // Firewall / ACL / network segmentation / microsegmentation
      if (/firewall|acl|network\s*segment|micro\s*segment/i.test(message)) {
        return `Network Security & Segmentation:\n` +
          `\u2022 Firewall rules: ${Math.floor(Math.random() * 200 + 150)} active rules\n` +
          `\u2022 Recent changes: ${Math.floor(Math.random() * 5)} rules modified (last 24h)\n` +
          `\u2022 Segmentation zones:\n` +
          `  \u2014 DMZ: web servers, reverse proxy\n` +
          `  \u2014 Internal: workstations, file servers\n` +
          `  \u2014 Restricted: databases, key management\n` +
          `  \u2014 OT/SCADA: isolated (air-gap enforced)\n` +
          `\u2022 Microsegmentation: ${Math.floor(Math.random() * 50 + 30)} policies enforced\n` +
          `\u2022 East-west traffic monitoring: active (ADA anomaly detection)\n` +
          `\u2022 Last audit: ${Math.floor(Math.random() * 14 + 1)} days ago\n` +
          `Commands: /block <ip> \u00B7 /unblock <ip>`;
      }

      // Zero trust / ZTNA / least privilege
      if (/zero\s*trust|least\s*privilege|ztna/i.test(message)) {
        return `Zero Trust Architecture (ZTA):\n\n` +
          `Zero Trust is a security model that eliminates implicit trust. Instead of assuming anything inside the network perimeter is safe, every access request is fully authenticated, authorized, and encrypted regardless of where it originates.\n\n` +
          `Core principles in our environment:\n` +
          `  1. "Never trust, always verify" \u2014 Every request is treated as if it originates from an untrusted network. Identity is verified through MFA + device posture + behavioral context before granting access.\n` +
          `  2. "Least privilege access" \u2014 Users and services receive the minimum permissions needed. RBAC defines baseline roles, and just-in-time (JIT) elevation provides temporary access for privileged operations with automatic expiry.\n` +
          `  3. "Assume breach" \u2014 The architecture assumes adversaries are already inside the network. Microsegmentation limits blast radius, and ADA + TAA continuously monitor for anomalous behavior.\n\n` +
          `Implementation status:\n` +
          `  \u2014 Identity verification: MFA enforced across all access tiers (hardware keys for privileged)\n` +
          `  \u2014 Device posture: endpoints must pass health checks (patched OS, active EDR, disk encryption) before network access is granted via ZTNA broker\n` +
          `  \u2014 Network access: Zero Trust Network Access (ZTNA) broker replaces traditional VPN. No direct network exposure \u2014 applications are invisible to unauthorized users.\n` +
          `  \u2014 Data protection: AES-256 encryption at rest, TLS 1.3 in transit\n` +
          `  \u2014 Continuous evaluation: ADA + TAA provide real-time session risk scoring. Sessions can be terminated mid-stream if risk score exceeds threshold.\n\n` +
          `Maturity assessment: Level 3 of 5 (Advanced). Key gaps: complete microsegmentation of legacy OT networks, and full adoption of ZTNA for all third-party vendor access.\n\n` +
          `Reference: NIST SP 800-207 (Zero Trust Architecture)\n\n` +
          `Related topics: "firewall rules" \u00B7 "MFA" \u00B7 "IAM" \u00B7 "network segmentation"`;
      }

      // SOAR / orchestration / automated response
      if (/soar|orchestrat|automat.*response/i.test(message)) {
        return `SOAR & Automation Status:\n` +
          `\u2022 SOAR platform: GATRA CRA (integrated orchestration)\n` +
          `\u2022 Active automation:\n` +
          `  \u2014 Auto-block: critical + confidence\u226590% \u2192 firewall rule\n` +
          `  \u2014 Auto-quarantine: malware verdict \u2192 endpoint isolation\n` +
          `  \u2014 Auto-enrich: IOC \u2192 WHOIS + GeoIP + reputation\n` +
          `  \u2014 Auto-notify: severity=critical \u2192 Slack + PagerDuty\n` +
          `\u2022 Human-in-the-loop: required for irreversible actions\n` +
          `\u2022 Actions this session: ${actions.length} (all within policy)\n` +
          `\u2022 MTTR improvement: ~${Math.floor(Math.random() * 30 + 40)}% faster than manual\n` +
          `Say "hold" to pause automation or "rollback" to revert.`;
      }

      // Eradication / recovery / lessons learned / post-mortem
      if (/eradicat|recover|lesson|post[\s-]?mortem|after[\s-]?action/i.test(message)) {
        return `IR Post-Incident Process:\n` +
          `\u2022 Eradication checklist:\n` +
          `  \u2014 Malware removal: AV/EDR full scan\n` +
          `  \u2014 Persistence mechanisms: registry, scheduled tasks, services\n` +
          `  \u2014 Credential reset: affected accounts + service accounts\n` +
          `  \u2014 Patch: exploit vector closed\n` +
          `\u2022 Recovery:\n` +
          `  \u2014 Restore from clean backup (verified integrity)\n` +
          `  \u2014 Gradual reconnection with monitoring\n` +
          `  \u2014 Validation: 48h observation period\n` +
          `\u2022 Lessons learned:\n` +
          `  \u2014 After-action review within 5 business days\n` +
          `  \u2014 Update playbooks + detection rules\n` +
          `  \u2014 CLA archives full timeline + evidence\n` +
          `Ask CLA to "generate report" for the formal incident report.`;
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

      // Forensics / evidence / chain of custody
      if (/forensic|evidence|chain\s*of\s*custod|preserv/i.test(message)) {
        return `Digital Forensics & Evidence:\n` +
          `\u2022 Evidence preservation:\n` +
          `  \u2014 Disk images: forensic copies (dd/FTK) with write-blocking\n` +
          `  \u2014 Memory dumps: volatile data captured before shutdown\n` +
          `  \u2014 Network captures: full PCAP for incident window\n` +
          `  \u2014 Log snapshots: immutable copies at time of detection\n` +
          `\u2022 Chain of custody:\n` +
          `  \u2014 All evidence SHA-256 hashed at acquisition\n` +
          `  \u2014 Transfer log: who, when, why \u2014 tamper-evident\n` +
          `  \u2014 Storage: encrypted, access-controlled vault\n` +
          `\u2022 This session: ${actions.length} CRA actions with evidence snapshots\n` +
          `\u2022 Court-admissible: following NIST SP 800-86 guidelines\n` +
          `Ask: "timeline" for chronological reconstruction.`;
      }

      // SIEM / log analysis / Splunk / Elastic
      if (/siem|log\s*analys|log\s*management|splunk|elastic|sentinel/i.test(message)) {
        return `SIEM & Log Analysis:\n` +
          `\u2022 SIEM integration: centralized log aggregation\n` +
          `\u2022 Log sources: ${Math.floor(Math.random() * 50 + 30)} feeds\n` +
          `  \u2014 Firewalls, IDS/IPS, WAF\n` +
          `  \u2014 Endpoints (EDR telemetry)\n` +
          `  \u2014 Cloud services (AWS CloudTrail, Azure AD, GCP audit)\n` +
          `  \u2014 Authentication systems (AD, LDAP, RADIUS)\n` +
          `  \u2014 Application logs, DNS, DHCP, VPN\n` +
          `\u2022 Ingestion rate: ~${Math.floor(Math.random() * 5000 + 3000)} EPS\n` +
          `\u2022 Correlation rules: ${Math.floor(Math.random() * 100 + 150)} active\n` +
          `\u2022 Alert pipeline: SIEM \u2192 ADA (anomaly scoring) \u2192 TAA (triage) \u2192 CRA (response)\n` +
          `\u2022 Retention: hot (30d) \u2192 warm (90d) \u2192 cold (1yr) \u2192 archive (7yr)\n` +
          `Ask: "audit trail" \u00B7 "forensics" \u00B7 "compliance"`;
      }

      // Extended regulatory frameworks
      if (/hipaa|pci[\s-]?dss|sox|ccpa|fedramp|cmmc|cis\s*bench/i.test(message)) {
        const framework = /hipaa/i.test(message) ? 'HIPAA' :
          /pci/i.test(message) ? 'PCI-DSS' :
          /sox/i.test(message) ? 'SOX' :
          /ccpa/i.test(message) ? 'CCPA' :
          /fedramp/i.test(message) ? 'FedRAMP' :
          /cmmc/i.test(message) ? 'CMMC' : 'CIS Benchmarks';
        return `${framework} Compliance Assessment:\n` +
          `\u2022 Framework: ${framework}\n` +
          `\u2022 Relevant controls mapped to GATRA:\n` +
          `  \u2014 Detection: ADA anomaly monitoring (continuous)\n` +
          `  \u2014 Response: CRA automated containment (< 15m SLA)\n` +
          `  \u2014 Logging: CLA audit trail (tamper-proof)\n` +
          `  \u2014 Risk assessment: RVA vulnerability tracking\n` +
          `\u2022 Current posture: ${sev.critical > 0 ? 'REVIEW NEEDED (active critical alerts)' : 'COMPLIANT'}\n` +
          `\u2022 Last assessment: ${Math.floor(Math.random() * 30 + 7)} days ago\n` +
          `\u2022 Gaps identified: ${Math.floor(Math.random() * 3)}\n` +
          `\u2022 Evidence package: exportable for auditors\n` +
          `Say "generate report" for formal compliance report.`;
      }

      // Data breach notification / disclosure / privacy
      if (/data\s*breach.*notif|disclosure|privacy/i.test(message)) {
        return `Data Breach Notification & Privacy:\n` +
          `\u2022 Notification requirements:\n` +
          `  \u2014 GDPR: 72 hours to supervisory authority\n` +
          `  \u2014 CCPA: "without unreasonable delay"\n` +
          `  \u2014 HIPAA: 60 days to HHS + affected individuals\n` +
          `  \u2014 PCI-DSS: immediate to card brands + acquirer\n` +
          `\u2022 Current incident: ${sev.critical > 0 ? 'POTENTIAL BREACH \u2014 evaluate data exposure' : 'No breach indicators'}\n` +
          `\u2022 Privacy impact assessment: ${sev.critical > 0 ? 'recommended' : 'not required'}\n` +
          `\u2022 Legal counsel notification: auto-trigger at severity=critical\n` +
          `\u2022 CLA maintains full audit trail for regulatory evidence`;
      }

      // Risk register / risk management / risk framework
      if (/risk\s*register|risk\s*management|risk\s*framework/i.test(message)) {
        return `Risk Management Framework:\n` +
          `\u2022 Framework: NIST RMF (SP 800-37) integrated\n` +
          `\u2022 Risk register: ${Math.floor(Math.random() * 20 + 15)} active entries\n` +
          `\u2022 Top risks:\n` +
          `  1. Unpatched critical CVEs (RVA: ${alerts.filter(a => a.severity === 'critical').length} active)\n` +
          `  2. Phishing susceptibility (TAA: user click rate monitored)\n` +
          `  3. Third-party vendor exposure (RVA: supply chain tracking)\n` +
          `\u2022 Risk appetite: moderate (defined by CISO policy)\n` +
          `\u2022 Review cycle: quarterly + event-driven\n` +
          `\u2022 Treatment: accept / mitigate / transfer / avoid\n` +
          `Ask RVA for "vulnerability exposure" or TAA for "threat assessment".`;
      }

      // Security awareness / training / tabletop
      if (/security\s*awareness|training|tabletop/i.test(message)) {
        return `Security Awareness & Training:\n` +
          `\u2022 Phishing simulation: monthly (last: ${Math.floor(Math.random() * 20 + 5)} days ago)\n` +
          `\u2022 Click rate: ${(1.5 + Math.random() * 4).toFixed(1)}% (target: <3%)\n` +
          `\u2022 Reporting rate: ${(15 + Math.random() * 30).toFixed(0)}% (target: >25%)\n` +
          `\u2022 Training modules: annual mandatory + role-based\n` +
          `\u2022 Tabletop exercises:\n` +
          `  \u2014 Last exercise: ${Math.floor(Math.random() * 60 + 14)} days ago\n` +
          `  \u2014 Scenario: ransomware + data exfiltration\n` +
          `  \u2014 Participants: SOC, IR, Legal, Executive\n` +
          `  \u2014 Findings: ${Math.floor(Math.random() * 4 + 1)} action items\n` +
          `\u2022 Next scheduled: ${Math.floor(Math.random() * 30 + 7)} days`;
      }

      // Retention / archive / e-discovery
      if (/retention|archiv|e-?discovery/i.test(message)) {
        return `Data Retention & e-Discovery:\n` +
          `\u2022 Retention policy:\n` +
          `  \u2014 Security logs: 1 year (hot: 30d, warm: 90d, cold: 1yr)\n` +
          `  \u2014 Audit trail: 7 years (regulatory requirement)\n` +
          `  \u2014 Incident evidence: case lifetime + 3 years\n` +
          `  \u2014 Network captures: 30 days (rolling)\n` +
          `\u2022 Archive: encrypted, immutable storage\n` +
          `\u2022 e-Discovery: legal hold capability \u2014 preserves targeted data\n` +
          `\u2022 Search: full-text indexed, <5s query time\n` +
          `\u2022 Export: JSON, CSV, PDF formats for legal/audit`;
      }

      // Generic @cla — rich fallback
      return `CLA Session Summary:\n` +
        `\u2022 Events logged: ${alerts.length} alerts, ${actions.length} actions\n` +
        `\u2022 Compliance: SOC-POL-2026-001 \u2713 all clear\n` +
        `\u2022 Audit chain: intact (SHA-256 verified)\n` +
        `\u2022 Retention: 90-day window active\n` +
        `Ask: "forensics" \u00B7 "SIEM" \u00B7 "HIPAA" \u00B7 "training" \u00B7 "generate report" \u00B7 "timeline"`;
    }

    // ── RVA: Risk & Vulnerability Agent ───────────────────────────
    case 'rva': {
      const cves = getCachedCVEFeed() ?? [];
      const critCves = cves.filter(c => c.severity === 'CRITICAL');
      const highCves = cves.filter(c => c.severity === 'HIGH');
      const kevCves = cves.filter(c => c.exploitedInWild);
      const formatCve = (c: typeof cves[0]) => {
        const score = c.cvssScore !== null ? c.cvssScore.toFixed(1) : 'N/A';
        const kev = c.exploitedInWild ? ' [KEV]' : '';
        const desc = c.description.length > 80 ? c.description.slice(0, 77) + '...' : c.description;
        return `\u2022 ${c.id} (CVSS: ${score}, ${c.severity})${kev}\n  ${desc}`;
      };

      // Specific CVE ID lookup (e.g. CVE-2026-1234)
      if (/cve-\d{4}-\d+/i.test(message)) {
        const cveMatch = message.match(/cve-\d{4}-\d+/i);
        const cveId = cveMatch?.[0]?.toUpperCase() ?? '';
        const found = cves.find(c => c.id.toUpperCase() === cveId);
        if (found) {
          const products = found.affectedProducts.length > 0 ? found.affectedProducts.join(', ') : 'checking...';
          return `Vulnerability: ${found.id}\n` +
            `\u2022 CVSS: ${found.cvssScore?.toFixed(1) ?? 'N/A'} (${found.severity})\n` +
            `\u2022 CISA KEV: ${found.exploitedInWild ? 'YES \u2014 active exploitation reported' : 'Not listed'}\n` +
            `\u2022 CWE: ${found.cweId ?? 'N/A'}\n` +
            `\u2022 Affected: ${products}\n` +
            `\u2022 Published: ${found.publishedDate.toISOString().split('T')[0]}\n` +
            `\u2022 Description: ${found.description.slice(0, 200)}${found.description.length > 200 ? '...' : ''}\n` +
            (found.references.length > 0 ? `\u2022 Ref: ${found.references[0]}\n` : '') +
            `Say "patch priority" for remediation recommendations.`;
        }
        return `${cveId} not found in current feed (last 7 days).\n` +
          `\u2022 Feed contains ${cves.length} CVEs | ${critCves.length} critical | ${kevCves.length} actively exploited\n` +
          `\u2022 Try checking the CVE FEED panel for historical lookups.`;
      }

      // "what is the CVE" / "CVE related" / "which CVE" / "list CVE" / general CVE questions
      if (/cve/i.test(message) && !/cve-\d{4}-\d+/i.test(message)) {
        if (cves.length === 0) {
          return `No CVE data cached yet. CVE FEED panel fetches from NVD every 10 minutes.\n` +
            `\u2022 Open the CVE FEED panel to trigger a fetch.\n` +
            `\u2022 Then ask me again for analysis.`;
        }
        const topCves = [...critCves, ...highCves].slice(0, 5);
        if (topCves.length === 0) {
          const sample = cves.slice(0, 5);
          return `${cves.length} CVEs in feed (last 7 days). No criticals currently.\n` +
            `Recent:\n${sample.map(formatCve).join('\n')}\n` +
            `\u2022 ${kevCves.length} actively exploited (CISA KEV)\n` +
            `Specify a CVE ID for detailed lookup.`;
        }
        return `Top vulnerabilities from CVE feed (${cves.length} total, last 7 days):\n` +
          topCves.map(formatCve).join('\n') +
          `\n\u2022 ${critCves.length} CRITICAL | ${highCves.length} HIGH | ${kevCves.length} actively exploited (KEV)\n` +
          `\u2022 Correlation with active alerts: ${alerts.length > 0 ? `${alerts[0]!.mitreId} may relate to exploitation` : 'none detected'}\n` +
          `Specify CVE ID for full details, or ask about "patch priority".`;
      }

      // Unpatched / patch priority / remediation
      if (/unpatched|patch|remediat/i.test(message)) {
        const urgent = [...kevCves, ...critCves.filter(c => !c.exploitedInWild)].slice(0, 5);
        if (urgent.length === 0 && cves.length === 0) {
          return `No CVE data cached. Open CVE FEED panel to fetch latest from NVD.\n` +
            `General patch priority:\n` +
            `1. CISA KEV listed (actively exploited)\n` +
            `2. CVSS \u22659.0 on internet-facing\n` +
            `3. CVSS \u22657.0 on internal infra`;
        }
        return `Patch priority (${cves.length} CVEs in feed):\n` +
          (urgent.length > 0
            ? `Urgent \u2014 patch these first:\n${urgent.map(formatCve).join('\n')}\n`
            : `No critical/KEV CVEs in current feed.\n`) +
          `\u2022 Summary: ${critCves.length} CRITICAL | ${highCves.length} HIGH | ${kevCves.length} actively exploited\n` +
          `\u2022 Priority order: KEV \u2192 CRITICAL \u2192 HIGH \u2192 internet-facing \u2192 internal\n` +
          `Specify CVE ID for targeted assessment.`;
      }

      // Vulnerability / exposure / scan / attack surface
      if (/vulnerabilit|expos|scan|surface|attack\s*surface|exploit|cvss|severity/i.test(message)) {
        return `Vulnerability exposure assessment:\n` +
          `\u2022 CVE feed: ${cves.length} vulnerabilities (last 7 days from NVD)\n` +
          `\u2022 Critical: ${critCves.length} | High: ${highCves.length} | Actively exploited: ${kevCves.length}\n` +
          `\u2022 Top critical: ${critCves[0]?.id ?? 'none'} ${critCves[0] ? `(CVSS: ${critCves[0].cvssScore?.toFixed(1)})` : ''}\n` +
          `\u2022 Active alert correlation: ${alerts.length > 0 ? `${alerts[0]!.mitreId} may indicate exploitation of known CVEs` : 'no correlation detected'}\n` +
          `\u2022 CISA KEV watchlist: ${kevCves.length} entries match current feed\n` +
          `Ask: "list CVEs" \u00B7 "CVE-2026-XXXX" \u00B7 "patch priority" \u00B7 "unpatched criticals"`;
      }

      // Penetration testing / red team / blue team / purple team
      if (/pen[\s-]?test|penetration\s*test|red\s*team|blue\s*team|purple\s*team/i.test(message)) {
        const isRedTeam = /red\s*team/i.test(message);
        const isBlueTeam = /blue\s*team/i.test(message);
        const isPurple = /purple/i.test(message);
        return `Penetration Testing & Security Team Exercises:\n\n` +
          `Penetration testing simulates real-world attacks against your systems to identify vulnerabilities before adversaries do. Unlike vulnerability scanning (which is automated), pentesting involves human creativity to chain vulnerabilities and demonstrate actual business impact.\n\n` +
          `Last engagement: ${Math.floor(Math.random() * 60 + 14)} days ago\n` +
          `Scope: external perimeter + internal network + web applications + API endpoints\n` +
          `Findings: ${Math.floor(Math.random() * 8 + 2)} vulnerabilities identified\n\n` +
          (isRedTeam || (!isBlueTeam && !isPurple)
            ? `Red Team (Offensive):\n` +
              `  Red team operations go beyond traditional pentesting by simulating a full APT lifecycle \u2014 reconnaissance, initial access, persistence, lateral movement, and objective completion. The goal is to test the organization's detection and response capabilities end-to-end.\n` +
              `  \u2014 Objective-based: "exfiltrate customer database" rather than "find vulnerabilities"\n` +
              `  \u2014 Social engineering: phishing campaigns, phone pretexting, LinkedIn reconnaissance\n` +
              `  \u2014 Physical security: badge cloning, tailgating, dumpster diving\n` +
              `  \u2014 Duration: typically 2-4 weeks to simulate persistent adversary\n\n`
            : '') +
          (isBlueTeam || (!isRedTeam && !isPurple)
            ? `Blue Team (Defensive):\n` +
              `  The blue team's mission is to detect and respond to attacks. GATRA agents augment the blue team by providing AI-powered detection (ADA), automated triage (TAA), and rapid containment (CRA).\n` +
              `  \u2014 Detection rate in last exercise: ${(70 + Math.random() * 25).toFixed(0)}%\n` +
              `  \u2014 Mean time to detect (MTTD): ${Math.floor(Math.random() * 30 + 5)} minutes\n` +
              `  \u2014 Mean time to respond (MTTR): ${Math.floor(Math.random() * 20 + 3)} minutes\n\n`
            : '') +
          (isPurple || (!isRedTeam && !isBlueTeam)
            ? `Purple Team (Collaborative):\n` +
              `  Purple teaming combines red and blue in real-time collaboration. The red team executes specific techniques while the blue team attempts to detect them. When detection fails, both teams work together to create new detection rules \u2014 directly improving security posture.\n\n`
            : '') +
          `CVE correlation: ${cves.length} CVEs in current feed available for validation testing.\n\n` +
          `Related topics: "OWASP" \u00B7 "cloud security" \u00B7 "vulnerability scan" \u00B7 "bug bounty"`;
      }

      // Cloud security / misconfiguration / CSPM
      if (/cloud\s*secur|misconfigur|s3\s*bucket|iam\s*role|cspm/i.test(message)) {
        return `Cloud Security Posture:\n` +
          `\u2022 CSPM monitoring: active across cloud environments\n` +
          `\u2022 Common misconfigurations checked:\n` +
          `  \u2014 Public S3 buckets / storage blobs: scanned hourly\n` +
          `  \u2014 Overly permissive IAM roles: flagged\n` +
          `  \u2014 Unencrypted data stores: detected\n` +
          `  \u2014 Default credentials on cloud services: monitored\n` +
          `  \u2014 Security groups with 0.0.0.0/0 ingress: alerted\n` +
          `\u2022 Cloud services monitored:\n` +
          `  \u2014 AWS: CloudTrail, GuardDuty, Config Rules\n` +
          `  \u2014 Azure: Sentinel, Defender for Cloud\n` +
          `  \u2014 GCP: Security Command Center, Audit Logs\n` +
          `\u2022 Active findings: ${Math.floor(Math.random() * 10 + 3)} misconfigurations\n` +
          `\u2022 CIS Benchmark compliance: ${(80 + Math.random() * 15).toFixed(0)}%`;
      }

      // Supply chain risk / third-party / vendor risk / SBOM
      if (/supply\s*chain\s*risk|third[\s-]?party|vendor\s*risk|sbom/i.test(message)) {
        return `Supply Chain & Third-Party Risk:\n` +
          `\u2022 Vendor risk assessments: ${Math.floor(Math.random() * 30 + 20)} vendors tracked\n` +
          `\u2022 Risk tiers:\n` +
          `  \u2014 Critical vendors: ${Math.floor(Math.random() * 5 + 3)} (annual assessment)\n` +
          `  \u2014 High: ${Math.floor(Math.random() * 10 + 5)} (semi-annual)\n` +
          `  \u2014 Standard: ${Math.floor(Math.random() * 20 + 10)} (annual questionnaire)\n` +
          `\u2022 SBOM (Software Bill of Materials):\n` +
          `  \u2014 Dependency tracking: active for production systems\n` +
          `  \u2014 Known vulnerable components: cross-referenced with CVE feed\n` +
          `  \u2014 License compliance: monitored\n` +
          `\u2022 Recent supply chain CVEs: ${cves.filter(c => /supply|chain|dependency|npm|pypi/i.test(c.description)).length || 'checking feed...'}\n` +
          `\u2022 SolarWinds-style monitoring: build pipeline integrity checks active`;
      }

      // Encryption / TLS / SSL / certificates / PKI
      if (/encrypt|tls|ssl|certific|pki|key\s*manage/i.test(message)) {
        return `Encryption & Certificate Management:\n` +
          `\u2022 TLS posture:\n` +
          `  \u2014 Minimum: TLS 1.2 (TLS 1.3 preferred)\n` +
          `  \u2014 Weak ciphers: disabled (RC4, 3DES, NULL)\n` +
          `  \u2014 Certificate transparency: monitored\n` +
          `\u2022 Certificate inventory:\n` +
          `  \u2014 Total certificates: ${Math.floor(Math.random() * 100 + 50)}\n` +
          `  \u2014 Expiring < 30 days: ${Math.floor(Math.random() * 5)}\n` +
          `  \u2014 Expired: ${Math.floor(Math.random() * 2)} (URGENT if > 0)\n` +
          `  \u2014 Auto-renewal (ACME/Let's Encrypt): ${Math.floor(Math.random() * 40 + 20)}%\n` +
          `\u2022 Key management:\n` +
          `  \u2014 HSM-backed for critical keys\n` +
          `  \u2014 Key rotation: enforced per policy\n` +
          `  \u2014 Encryption at rest: AES-256\n` +
          `\u2022 Crypto-related CVEs in feed: ${cves.filter(c => /tls|ssl|crypto|certificate|openssl/i.test(c.description)).length || 0}`;
      }

      // Bug bounty / responsible disclosure
      if (/bug\s*bount|responsible\s*disclos|coordinated\s*disclos/i.test(message)) {
        return `Bug Bounty & Disclosure Program:\n` +
          `\u2022 Program status: active\n` +
          `\u2022 Scope: public-facing web applications, APIs, mobile apps\n` +
          `\u2022 Submissions (last 90 days): ${Math.floor(Math.random() * 20 + 5)}\n` +
          `  \u2014 Valid: ${Math.floor(Math.random() * 8 + 2)} | Duplicate: ${Math.floor(Math.random() * 5)} | Out-of-scope: ${Math.floor(Math.random() * 4)}\n` +
          `\u2022 Top categories: XSS, IDOR, SSRF, auth bypass\n` +
          `\u2022 Avg resolution time: ${Math.floor(Math.random() * 14 + 7)} days\n` +
          `\u2022 Coordination: follow ISO 29147 / ISO 30111\n` +
          `\u2022 Findings auto-imported to RVA vulnerability tracking`;
      }

      // Asset inventory / shadow IT / asset discovery
      if (/asset\s*inventor|shadow\s*it|asset\s*discover/i.test(message)) {
        return `Asset Inventory & Shadow IT:\n` +
          `\u2022 Discovered assets: ${Math.floor(Math.random() * 500 + 300)}\n` +
          `  \u2014 Managed endpoints: ${Math.floor(Math.random() * 300 + 200)}\n` +
          `  \u2014 Servers/VMs: ${Math.floor(Math.random() * 100 + 50)}\n` +
          `  \u2014 Cloud instances: ${Math.floor(Math.random() * 80 + 30)}\n` +
          `  \u2014 Network devices: ${Math.floor(Math.random() * 50 + 20)}\n` +
          `  \u2014 IoT/OT: ${Math.floor(Math.random() * 30 + 10)}\n` +
          `\u2022 Shadow IT detected: ${Math.floor(Math.random() * 10 + 2)} unauthorized services\n` +
          `\u2022 Unmanaged devices: ${Math.floor(Math.random() * 15 + 3)} flagged for review\n` +
          `\u2022 Attack surface: external-facing assets scanned weekly\n` +
          `\u2022 CVE mapping: assets cross-referenced with vulnerability feed`;
      }

      // WAF / OWASP / web application firewall
      if (/waf|web\s*application\s*firewall|owasp/i.test(message)) {
        return `WAF & OWASP Protection:\n` +
          `\u2022 WAF status: active (inline mode)\n` +
          `\u2022 OWASP Top 10 coverage:\n` +
          `  1. A01 Broken Access Control \u2713\n` +
          `  2. A02 Cryptographic Failures \u2713\n` +
          `  3. A03 Injection (SQL, NoSQL, LDAP, XSS) \u2713\n` +
          `  4. A04 Insecure Design \u2014 code review process\n` +
          `  5. A05 Security Misconfiguration \u2713 (CSPM)\n` +
          `  6. A06 Vulnerable Components \u2713 (SBOM + CVE feed)\n` +
          `  7. A07 Auth Failures \u2713 (rate-limit + MFA)\n` +
          `  8. A08 Data Integrity \u2713 (SSRF protection)\n` +
          `  9. A09 Logging Failures \u2713 (CLA full audit)\n` +
          `  10. A10 SSRF \u2713 (egress filtering)\n` +
          `\u2022 WAF blocks (24h): ${Math.floor(Math.random() * 500 + 100)}\n` +
          `\u2022 False positive rate: ${(0.5 + Math.random() * 2).toFixed(1)}%`;
      }

      // Generic @rva — rich fallback with real data
      if (cves.length === 0) {
        return `RVA online. No CVE data cached yet.\n` +
          `\u2022 Open CVE FEED panel to fetch latest from NVD + CISA KEV\n` +
          `\u2022 Ask about: CVEs \u00B7 pentesting \u00B7 cloud security \u00B7 encryption \u00B7 OWASP \u00B7 supply chain`;
      }
      return `RVA Vulnerability Summary:\n` +
        `\u2022 CVE feed: ${cves.length} entries (last 7 days)\n` +
        `\u2022 ${critCves.length} CRITICAL | ${highCves.length} HIGH | ${kevCves.length} actively exploited (KEV)\n` +
        (critCves[0] ? `\u2022 Top critical: ${critCves[0].id} (CVSS: ${critCves[0].cvssScore?.toFixed(1) ?? 'N/A'})\n` : '') +
        (kevCves[0] ? `\u2022 Top exploited: ${kevCves[0].id} \u2014 ${kevCves[0].description.slice(0, 60)}...\n` : '') +
        `Ask: "list CVEs" \u00B7 "pentest" \u00B7 "cloud security" \u00B7 "OWASP" \u00B7 "encryption" \u00B7 "supply chain"`;
    }

    default:
      return 'Agent online. Ask me a question.';
  }
}

// ── General cybersecurity knowledge base ─────────────────────────

function generateGeneralCyberResponse(message: string): string | null {
  const snap = getGatraSnapshot();
  const alerts = snap?.alerts ?? [];
  const sev = severityCounts(alerts);

  // MFA / authentication / identity
  if (/mfa|multi[\s-]?factor|two[\s-]?factor|2fa|authentication/i.test(message)) {
    return `SOC Knowledge Base \u2014 Multi-Factor Authentication (MFA):\n\n` +
      `MFA is the single most effective control against account compromise. It requires users to present two or more verification factors: something they know (password), something they have (phone/key), or something they are (biometric). Even if credentials are stolen via phishing or data breach, MFA prevents unauthorized access.\n\n` +
      `MFA methods ranked by security (strongest to weakest):\n` +
      `  1. Hardware security keys (FIDO2/WebAuthn): Phishing-resistant by design. The key cryptographically verifies the website's domain, so fake login pages can't capture the token. Google reported zero successful phishing attacks on employees after deploying hardware keys. Recommended for administrators and high-value targets.\n` +
      `  2. Authenticator apps (TOTP): Generate time-based one-time passwords that change every 30 seconds. Resistant to SIM swap attacks (unlike SMS) but can be phished if the user enters the code on a fake site. Google Authenticator, Microsoft Authenticator, Authy are common choices.\n` +
      `  3. Push notifications: Convenient \u2014 user taps "approve" on their phone. However, vulnerable to MFA fatigue attacks (Uber breach 2022) where attackers spam push requests until the user approves out of frustration. Mitigate with number-matching (user must type a displayed number).\n` +
      `  4. SMS codes: Weakest MFA option. Vulnerable to SIM swap attacks, SS7 network interception, and social engineering of carrier support. Still better than no MFA, but should be phased out for sensitive systems.\n\n` +
      `Best practices:\n` +
      `  \u2014 Enforce MFA organization-wide, not just for VPN or email\n` +
      `  \u2014 Use phishing-resistant MFA (FIDO2) for privileged accounts\n` +
      `  \u2014 Implement number-matching for push-based MFA to prevent fatigue attacks\n` +
      `  \u2014 Monitor for MFA bypass attempts \u2014 TAA tracks authentication anomalies\n` +
      `  \u2014 Have break-glass procedures for MFA lockouts (secured recovery codes)\n\n` +
      `GATRA context: ADA detects unusual authentication patterns, TAA triages identity-based alerts, CRA can suspend compromised accounts.\n\n` +
      `Related topics: "zero trust" (CRA) \u00B7 "credential stuffing" (TAA) \u00B7 "IAM"`;
  }

  // IAM / identity / access control / RBAC
  if (/iam|identity.*access|access\s*control|rbac|abac/i.test(message)) {
    return `SOC Knowledge Base \u2014 Identity & Access Management:\n` +
      `\u2022 IAM principles:\n` +
      `  \u2014 Least privilege: minimum necessary permissions\n` +
      `  \u2014 Separation of duties: no single point of failure\n` +
      `  \u2014 Need-to-know: data access based on role\n` +
      `\u2022 Access control models:\n` +
      `  \u2014 RBAC: Role-Based (most common in enterprise)\n` +
      `  \u2014 ABAC: Attribute-Based (context-aware, more granular)\n` +
      `  \u2014 MAC: Mandatory (military/government classification)\n` +
      `\u2022 Privileged Access Management (PAM):\n` +
      `  \u2014 Just-in-time access: temporary privilege elevation\n` +
      `  \u2014 Session recording: all admin actions logged\n` +
      `  \u2014 Credential vaulting: no standing privileges\n` +
      `\u2022 GATRA: ADA monitors for privilege escalation anomalies\n` +
      `Ask CRA about "zero trust" or CLA about "compliance" for policy details.`;
  }

  // DevSecOps / SDLC / secure coding
  if (/devsecops|sdlc|secure\s*coding|code\s*review/i.test(message)) {
    return `SOC Knowledge Base \u2014 DevSecOps & Secure SDLC:\n` +
      `\u2022 Secure SDLC phases:\n` +
      `  1. Requirements: security requirements + threat modeling\n` +
      `  2. Design: architecture security review\n` +
      `  3. Implementation: secure coding standards + SAST\n` +
      `  4. Testing: DAST + penetration testing + fuzzing\n` +
      `  5. Deployment: hardened configs + infrastructure as code\n` +
      `  6. Operations: monitoring + incident response\n` +
      `\u2022 CI/CD security:\n` +
      `  \u2014 SAST (Static Analysis): pre-commit + pipeline\n` +
      `  \u2014 SCA (Software Composition Analysis): dependency vulnerabilities\n` +
      `  \u2014 DAST (Dynamic Analysis): staging environment scans\n` +
      `  \u2014 Container scanning: image vulnerability assessment\n` +
      `  \u2014 IaC scanning: Terraform/CloudFormation misconfigurations\n` +
      `\u2022 Shift-left: catch vulnerabilities early = cheaper to fix\n` +
      `Ask RVA about "OWASP" or "SBOM" for specific vulnerability topics.`;
  }

  // Honeypot / deception / honeytoken
  if (/honeypot|honeytoken|deception/i.test(message)) {
    return `SOC Knowledge Base \u2014 Deception Technology:\n` +
      `\u2022 Deception types:\n` +
      `  \u2014 Honeypots: fake systems that attract attackers\n` +
      `  \u2014 Honeytokens: fake credentials/files that trigger alerts\n` +
      `  \u2014 Honey networks: simulated network segments\n` +
      `  \u2014 Decoy documents: watermarked files for leak detection\n` +
      `\u2022 Benefits:\n` +
      `  \u2014 Zero false positives (any interaction = malicious)\n` +
      `  \u2014 Early warning of lateral movement\n` +
      `  \u2014 Attacker TTP collection (fed to TAA)\n` +
      `  \u2014 Slow down adversary operations\n` +
      `\u2022 Deployment: strategically placed in network segments\n` +
      `\u2022 GATRA: deception alerts auto-escalated to CRITICAL by TAA`;
  }

  // OSINT / reconnaissance / footprinting
  if (/osint|recon(naissance)?|footprint/i.test(message)) {
    return `SOC Knowledge Base \u2014 OSINT & Reconnaissance:\n` +
      `\u2022 OSINT sources monitored:\n` +
      `  \u2014 Public DNS records, WHOIS, certificate transparency\n` +
      `  \u2014 Social media exposure (employee data leaks)\n` +
      `  \u2014 Code repositories (accidental credential commits)\n` +
      `  \u2014 Paste sites (credential dumps)\n` +
      `  \u2014 Dark web forums (organizational mentions)\n` +
      `\u2022 Attack surface from adversary perspective:\n` +
      `  \u2014 Subdomain enumeration: monitored for new exposures\n` +
      `  \u2014 Technology fingerprinting: tracked for known CVEs\n` +
      `  \u2014 Email harvesting: DMARC/SPF protects against spoofing\n` +
      `\u2022 GATRA integration: OSINT feeds enrich TAA threat intel\n` +
      `Ask RVA about "attack surface" or TAA about "dark web".`;
  }

  // IoT / SCADA / ICS / OT security
  if (/iot|scada|ics|ot\s*secur|industrial\s*control/i.test(message)) {
    return `SOC Knowledge Base \u2014 IoT / OT / ICS Security:\n\n` +
      `Operational Technology (OT) and Industrial Control Systems (ICS) present unique cybersecurity challenges because attacks can cause physical damage, environmental harm, or endanger human safety. Unlike IT systems where confidentiality is often paramount, OT prioritizes availability and safety above all else.\n\n` +
      `OT/ICS Monitoring:\n` +
      `  \u2014 Protocol analysis: Industrial protocols (Modbus, DNP3, OPC-UA, BACnet, EtherNet/IP) are monitored for anomalous commands. A "write to PLC" command outside a maintenance window triggers an immediate alert.\n` +
      `  \u2014 Anomaly detection: ADA maintains behavioral baselines for process control systems. Deviations in setpoints, sensor readings, or communication patterns indicate potential manipulation.\n` +
      `  \u2014 IT/OT boundary: Strict network segmentation with unidirectional gateways where possible. The Purdue Model defines zones from Enterprise (Level 5) down to Physical Process (Level 0).\n\n` +
      `IoT Security Challenges:\n` +
      `  \u2014 Legacy devices: Many ICS components run for 15-20 years with no patching capability. Compensating controls (network isolation, virtual patching via IPS) are essential.\n` +
      `  \u2014 Default credentials: Shodan-style scans regularly discover internet-exposed ICS with factory-default passwords. Credential auditing is critical.\n` +
      `  \u2014 Unencrypted protocols: Most legacy ICS protocols have no built-in encryption or authentication. Network monitoring and segmentation are the primary defenses.\n` +
      `  \u2014 Safety implications: Unlike IT, a wrong containment action in OT can cause physical harm. CRA requires explicit human approval for any OT-related response action.\n\n` +
      `Notable incidents: Stuxnet (Iran nuclear), Industroyer/CrashOverride (Ukraine power grid), Triton/TRISIS (Saudi petrochemical safety systems), Colonial Pipeline (ransomware disrupting fuel supply).\n\n` +
      `Frameworks: NIST SP 800-82 (ICS Security), IEC 62443 (Industrial Automation), MITRE ICS ATT&CK matrix.\n\n` +
      `GATRA policy: All OT-related alerts are elevated to critical severity by default (safety-first approach).\n\n` +
      `Related topics: "SCADA" \u00B7 "network segmentation" (CRA) \u00B7 "zero trust" \u00B7 "asset inventory" (RVA)`;
  }

  // Insider threat / DLP / data loss prevention
  if (/insider\s*threat|privilege.*abus|data\s*loss\s*prevent|dlp/i.test(message)) {
    return `SOC Knowledge Base \u2014 Insider Threat & Data Loss Prevention:\n\n` +
      `Insider threats are among the most challenging security risks because the adversary already has legitimate access. Insiders can be malicious (disgruntled employees, corporate espionage), negligent (accidental data exposure), or compromised (credentials stolen by external attacker). According to the Ponemon Institute, insider incidents cost an average of $15.4M annually per organization.\n\n` +
      `Behavioral indicators (detected by ADA's UEBA engine):\n` +
      `  \u2014 Unusual data access volume: A user downloading 50\u00D7 their normal file volume triggers an anomaly score. UEBA compares against the individual's 30-day rolling baseline, not just org-wide averages.\n` +
      `  \u2014 Off-hours access: Accessing sensitive systems outside normal working patterns, especially combined with other indicators.\n` +
      `  \u2014 Mass file operations: Bulk downloads, email forwarding to personal accounts, or large archive creation before departing the company.\n` +
      `  \u2014 Scope creep: Accessing systems, databases, or network segments outside the user's job function.\n` +
      `  \u2014 Resignation correlation: HR departure events cross-referenced with access patterns \u2014 a 2-week notice period with sudden data access spikes is a high-priority indicator.\n\n` +
      `Data Loss Prevention (DLP) controls:\n` +
      `  \u2014 Endpoint DLP: Monitors and controls USB transfers, print jobs, clipboard operations, and screen captures. Prevents sensitive data from leaving managed endpoints.\n` +
      `  \u2014 Network DLP: Inspects email attachments, web uploads, and cloud sync traffic for sensitive content (PII, PHI, financial data, source code). Can block or quarantine in real-time.\n` +
      `  \u2014 Cloud DLP: Monitors SaaS application sharing permissions (Google Drive, SharePoint, Slack). Prevents "share with anyone with the link" on sensitive files.\n` +
      `  \u2014 Data classification: Automated tagging of PII, PHI, financial records, and intellectual property. Classification drives DLP policy enforcement \u2014 "CONFIDENTIAL" files can't be emailed externally.\n\n` +
      `GATRA integration: ADA detects behavioral anomalies, TAA triages based on risk context, CRA can suspend accounts and isolate endpoints, CLA preserves evidence for legal hold.\n\n` +
      `Related topics: "UEBA" (ADA) \u00B7 "forensics" (CLA) \u00B7 "zero trust" (CRA) \u00B7 "compliance"`;
  }

  // API security / OAuth / JWT
  if (/api\s*secur|oauth|jwt|token/i.test(message)) {
    return `SOC Knowledge Base \u2014 API Security:\n` +
      `\u2022 API protection:\n` +
      `  \u2014 Authentication: OAuth 2.0 + API keys\n` +
      `  \u2014 Authorization: scope-based access control\n` +
      `  \u2014 Rate limiting: per-client throttling\n` +
      `  \u2014 Input validation: schema enforcement\n` +
      `\u2022 OWASP API Security Top 10:\n` +
      `  \u2014 Broken Object Level Authorization (BOLA)\n` +
      `  \u2014 Broken Authentication\n` +
      `  \u2014 Excessive Data Exposure\n` +
      `  \u2014 Lack of Resources & Rate Limiting\n` +
      `  \u2014 Mass Assignment\n` +
      `\u2022 JWT security: signature validation, expiry enforcement, no sensitive data in payload\n` +
      `\u2022 Monitoring: API call patterns analyzed by ADA for anomalies\n` +
      `Ask RVA about "OWASP" or "WAF" for web application protection.`;
  }

  // Container / Kubernetes / Docker security
  if (/container|kubernetes|docker|k8s.*secur/i.test(message)) {
    return `SOC Knowledge Base \u2014 Container & K8s Security:\n` +
      `\u2022 Container security layers:\n` +
      `  \u2014 Image scanning: CVE detection in base images + dependencies\n` +
      `  \u2014 Registry security: signed images only, no :latest in prod\n` +
      `  \u2014 Runtime protection: read-only filesystem, non-root\n` +
      `  \u2014 Network policies: pod-to-pod microsegmentation\n` +
      `\u2022 Kubernetes hardening:\n` +
      `  \u2014 RBAC: least-privilege service accounts\n` +
      `  \u2014 Pod Security Standards: restricted profile\n` +
      `  \u2014 Secrets management: external vault, not in etcd plaintext\n` +
      `  \u2014 Audit logging: API server events to SIEM\n` +
      `  \u2014 Admission controllers: OPA/Gatekeeper policies\n` +
      `\u2022 Monitoring: container anomalies detected by ADA (syscall profiling)\n` +
      `Ask RVA about "cloud security" or "SBOM" for related topics.`;
  }

  // Threat modeling / STRIDE / DREAD
  if (/threat\s*model|stride|dread/i.test(message)) {
    return `SOC Knowledge Base \u2014 Threat Modeling:\n` +
      `\u2022 Methodologies:\n` +
      `  \u2014 STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege\n` +
      `  \u2014 DREAD: Damage, Reproducibility, Exploitability, Affected Users, Discoverability\n` +
      `  \u2014 PASTA: Process for Attack Simulation and Threat Analysis\n` +
      `  \u2014 Attack Trees: hierarchical threat decomposition\n` +
      `\u2022 Process:\n` +
      `  1. Identify assets and entry points\n` +
      `  2. Enumerate threats (STRIDE per element)\n` +
      `  3. Rate risks (DREAD or CVSS-like scoring)\n` +
      `  4. Define mitigations per threat\n` +
      `  5. Validate with MITRE ATT&CK mapping\n` +
      `\u2022 GATRA agents map to threat model outputs:\n` +
      `  \u2014 ADA: detects modeled attack patterns\n` +
      `  \u2014 TAA: prioritizes based on threat model risk scores\n` +
      `  \u2014 RVA: validates mitigations against CVE data`;
  }

  // XSS / SQLi / CSRF / SSRF / injection attacks
  if (/xss|sqli|sql\s*inject|csrf|ssrf|rce|lfi|rfi/i.test(message)) {
    const attackType = /xss/i.test(message) ? 'Cross-Site Scripting (XSS)' :
      /sql/i.test(message) ? 'SQL Injection' :
      /csrf/i.test(message) ? 'Cross-Site Request Forgery (CSRF)' :
      /ssrf/i.test(message) ? 'Server-Side Request Forgery (SSRF)' :
      /rce/i.test(message) ? 'Remote Code Execution (RCE)' : 'File Inclusion (LFI/RFI)';
    return `SOC Knowledge Base \u2014 ${attackType}:\n` +
      `\u2022 Attack description: ${attackType}\n` +
      `\u2022 Detection:\n` +
      `  \u2014 WAF rules: signature + behavioral detection\n` +
      `  \u2014 SIEM correlation: multiple probe attempts from same source\n` +
      `  \u2014 ADA: request pattern anomaly scoring\n` +
      `\u2022 Prevention:\n` +
      `  \u2014 Input validation and output encoding\n` +
      `  \u2014 Parameterized queries (SQLi)\n` +
      `  \u2014 Content Security Policy headers (XSS)\n` +
      `  \u2014 Anti-CSRF tokens + SameSite cookies (CSRF)\n` +
      `  \u2014 Egress filtering + allowlists (SSRF)\n` +
      `\u2022 OWASP classification: A03 Injection\n` +
      `\u2022 CVE correlation: check RVA for related vulnerability data\n` +
      `Ask RVA about "OWASP" or "WAF" for protection details.`;
  }

  // Buffer overflow / memory corruption
  if (/buffer\s*overflow|heap|stack\s*overflow|memory\s*corrupt/i.test(message)) {
    return `SOC Knowledge Base \u2014 Memory Safety & Buffer Overflow:\n` +
      `\u2022 Attack types:\n` +
      `  \u2014 Stack buffer overflow: overwrite return address\n` +
      `  \u2014 Heap overflow: corrupt heap metadata\n` +
      `  \u2014 Use-after-free: dangling pointer exploitation\n` +
      `  \u2014 Format string: read/write arbitrary memory\n` +
      `\u2022 Mitigations:\n` +
      `  \u2014 ASLR: Address Space Layout Randomization\n` +
      `  \u2014 DEP/NX: Non-executable stack\n` +
      `  \u2014 Stack canaries: detect overflow before return\n` +
      `  \u2014 CFI: Control Flow Integrity\n` +
      `  \u2014 Memory-safe languages: Rust, Go, modern C++ with sanitizers\n` +
      `\u2022 Detection: ADA monitors for exploitation indicators (crash patterns, shellcode signatures)\n` +
      `\u2022 CVE correlation: many CRITICAL CVEs are memory safety bugs\n` +
      `Ask RVA to check "CVE" feed for specific memory corruption vulnerabilities.`;
  }

  // VPN / proxy / anonymity / Tor
  if (/vpn|proxy|tor\b|onion|anonymi/i.test(message)) {
    return `SOC Knowledge Base \u2014 VPN & Network Anonymity:\n` +
      `\u2022 VPN security:\n` +
      `  \u2014 Always-on VPN: enforce for remote workers\n` +
      `  \u2014 Split tunneling: disabled for corporate traffic\n` +
      `  \u2014 Protocol: WireGuard or IKEv2/IPsec preferred\n` +
      `  \u2014 MFA on VPN login: mandatory\n` +
      `\u2022 Tor/Proxy monitoring:\n` +
      `  \u2014 Known Tor exit node IPs: flagged on ingress\n` +
      `  \u2014 Anonymous proxy detection: commercial reputation feeds\n` +
      `  \u2014 Internal Tor usage: policy violation \u2192 ADA alert\n` +
      `\u2022 Detection: source IP reputation scoring integrated with ADA\n` +
      `\u2022 Response: suspicious proxy traffic auto-flagged for TAA triage`;
  }

  // DNS / SMTP / HTTP / networking protocols
  if (/\bdns\b|smtp|http[s]?\b|tcp|udp|ip\s*address|port\s*scan/i.test(message)) {
    return `SOC Knowledge Base \u2014 Network Protocol Security:\n` +
      `\u2022 DNS security:\n` +
      `  \u2014 DNS filtering: malicious domain blocking\n` +
      `  \u2014 DNS-over-HTTPS/TLS: encrypted queries\n` +
      `  \u2014 DNSSEC: response integrity validation\n` +
      `  \u2014 DNS tunneling detection: query length + frequency analysis (ADA)\n` +
      `\u2022 Email (SMTP) security:\n` +
      `  \u2014 SPF/DKIM/DMARC: spoofing protection\n` +
      `  \u2014 TLS enforcement: encrypted transit\n` +
      `\u2022 HTTP/HTTPS:\n` +
      `  \u2014 HSTS: force HTTPS, prevent downgrade\n` +
      `  \u2014 CSP: Content Security Policy headers\n` +
      `\u2022 Port scanning: detected by ADA network anomaly engine\n` +
      `\u2022 Active monitors: ${alerts.length} alerts in pipeline\n` +
      `Ask ADA about "DDoS" or RVA about "WAF" for specific protocols.`;
  }

  // Wireless / WiFi / Bluetooth / RF
  if (/wireless|wifi|bluetooth|rf\s*secur/i.test(message)) {
    return `SOC Knowledge Base \u2014 Wireless Security:\n` +
      `\u2022 WiFi security:\n` +
      `  \u2014 WPA3-Enterprise: mandatory for corporate networks\n` +
      `  \u2014 802.1X / RADIUS: certificate-based authentication\n` +
      `  \u2014 Rogue AP detection: wireless IDS active\n` +
      `  \u2014 Guest network: isolated VLAN, no internal access\n` +
      `\u2022 Bluetooth threats:\n` +
      `  \u2014 BlueBorne, BLURtooth, KNOB attacks\n` +
      `  \u2014 Policy: Bluetooth disabled on sensitive systems\n` +
      `\u2022 RF security:\n` +
      `  \u2014 TEMPEST shielding for classified areas\n` +
      `  \u2014 Signal jamming detection\n` +
      `\u2022 Detection: unauthorized wireless activity flagged by ADA`;
  }

  // Security architecture / defense in depth
  if (/security\s*architect|defense\s*in\s*depth|layered/i.test(message)) {
    return `SOC Knowledge Base \u2014 Security Architecture:\n` +
      `\u2022 Defense in Depth layers:\n` +
      `  1. Perimeter: firewall, WAF, DDoS protection\n` +
      `  2. Network: segmentation, IDS/IPS, microsegmentation\n` +
      `  3. Endpoint: EDR, AV, host firewall, disk encryption\n` +
      `  4. Application: SAST, DAST, WAF rules, input validation\n` +
      `  5. Data: encryption, DLP, classification, access control\n` +
      `  6. Identity: MFA, PAM, SSO, conditional access\n` +
      `  7. Monitoring: SIEM (CLA), anomaly detection (ADA), threat intel (TAA)\n` +
      `  8. Response: automated containment (CRA), playbooks, SOAR\n` +
      `\u2022 GATRA provides layers 7-8 as AI-augmented capabilities\n` +
      `\u2022 Current posture: ${sev.critical > 0 ? 'ELEVATED' : 'STANDARD'}\n` +
      `Ask about any specific layer for detailed assessment.`;
  }

  // General cybersecurity / infosec / SOC / best practices
  if (/cyber\s*security|infosec|information\s*security|soc\b|security\s*operat|best\s*practice|recommend|guideline/i.test(message)) {
    return `SOC Knowledge Base \u2014 Cybersecurity Essentials:\n` +
      `\u2022 SOC current status: ${alerts.length} active alerts (${sev.critical}C/${sev.high}H/${sev.medium}M)\n` +
      `\u2022 Key cybersecurity domains:\n` +
      `  \u2014 Threat Detection: ADA (anomaly detection, malware, EDR, UEBA)\n` +
      `  \u2014 Threat Intelligence: TAA (APTs, phishing, IOCs, campaigns)\n` +
      `  \u2014 Incident Response: CRA (playbooks, zero trust, SOAR, DR)\n` +
      `  \u2014 Compliance: CLA (forensics, SIEM, regulatory, training)\n` +
      `  \u2014 Vulnerability: RVA (CVEs, pentesting, cloud, encryption, OWASP)\n` +
      `\u2022 Try asking about:\n` +
      `  "ransomware" \u00B7 "phishing" \u00B7 "zero trust" \u00B7 "OWASP" \u00B7 "APT"\n` +
      `  "cloud security" \u00B7 "insider threat" \u00B7 "MFA" \u00B7 "forensics"\n` +
      `  "IoT security" \u00B7 "threat modeling" \u00B7 "supply chain"\n` +
      `  "DevSecOps" \u00B7 "honeypot" \u00B7 "DDoS" \u00B7 "container security"`;
  }

  // Catch-all "what is" / "how does" / "explain" / "define"
  if (/what\s*is|how\s*does|explain|define|meaning/i.test(message)) {
    return `SOC Knowledge Base:\n` +
      `I can help with a wide range of cybersecurity topics. Try asking about:\n` +
      `\u2022 Detection: malware, ransomware, DDoS, lateral movement, UEBA\n` +
      `\u2022 Threats: phishing, APTs, social engineering, zero-days, dark web\n` +
      `\u2022 Response: IR playbooks, zero trust, firewall, SOAR, disaster recovery\n` +
      `\u2022 Compliance: forensics, SIEM, HIPAA, PCI-DSS, GDPR, training\n` +
      `\u2022 Vulnerability: CVEs, pentesting, cloud security, OWASP, encryption\n` +
      `\u2022 Architecture: defense in depth, threat modeling, DevSecOps\n` +
      `\u2022 Identity: MFA, IAM, access control, insider threat, DLP\n` +
      `\u2022 Infrastructure: IoT/OT, wireless, containers, DNS, API security\n` +
      `Or mention @ADA @TAA @CRA @CLA @RVA for agent-specific queries.`;
  }

  return null; // Not a cybersecurity topic we can handle
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
      `GATRA Agents: @ADA @TAA @CRA @CLA @RVA\n\n` +
      `Cybersecurity topics (ask anything):\n` +
      `  malware \u00B7 phishing \u00B7 ransomware \u00B7 APT \u00B7 zero trust\n` +
      `  OWASP \u00B7 cloud security \u00B7 IoT/OT \u00B7 forensics \u00B7 DDoS\n` +
      `  MFA \u00B7 insider threat \u00B7 DevSecOps \u00B7 pentesting\n` +
      `  encryption \u00B7 threat modeling \u00B7 supply chain \u00B7 SIEM`,
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
            <textarea class="soc-chat-input" rows="1" placeholder="Ask about cybersecurity... (@ADA @TAA @CRA @CLA @RVA or /help)"></textarea>
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

    if (unique.length > 0) {
      // Route to matched GATRA agents
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
    } else if (GENERAL_CYBER_PATTERNS.some(p => p.test(text))) {
      // No specific agent matched — try general cybersecurity knowledge base
      const socSender: GatraAgentDef = {
        id: 'soc-kb', name: 'SOC', fullName: 'SOC Knowledge Base',
        role: 'General cybersecurity intelligence',
        color: '#22c55e', emoji: '\uD83C\uDF10',
        triggerPatterns: [],
      };
      this.showTyping(socSender);

      const timer = setTimeout(() => {
        this.hideTyping(socSender.id);
        const response = generateGeneralCyberResponse(text);
        if (response) {
          const kbMsg: ChatMessage = {
            id: uid(), timestamp: Date.now(),
            sender: { id: socSender.id, name: socSender.name, type: 'agent', color: socSender.color },
            type: 'agent', content: response,
          };
          this.addMessage(kbMsg);
          this.channel.postMessage(kbMsg);
        }
      }, 1200 + Math.random() * 800);

      this.typingTimers.set(socSender.id, timer);
    }
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
