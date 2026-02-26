/**
 * A2A Security Service — Mock data & event generation for Agent-to-Agent
 * protocol monitoring. Generates realistic agent registry, traffic events,
 * and threat summaries that integrate with the CII panel's trust policies.
 */

// ── Types ────────────────────────────────────────────────────────

export interface RegisteredAgent {
  cardId: string;
  name: string;
  provider: string;
  url: string;
  skills: string[];
  status: 'verified' | 'pending' | 'blocked' | 'degraded';
  trustScore: number;
  signatureValid: boolean;
  firstSeen: number;
  lastInteraction: number;
  totalInteractions: number;
  anomalyCount: number;
  region: string;
}

export interface A2aTrafficEvent {
  id: string;
  timestamp: number;
  sourceAgent: string;
  targetAgent: string;
  direction: 'inbound' | 'outbound';
  skill: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'blocked';
  latencyMs: number;
  details: {
    injectionDetected: boolean;
    injectionType?: 'card_field' | 'message_body' | 'artifact';
    injectionPattern?: string;
    driftScore?: number;
    trustDelta?: number;
    mitreTechnique?: string;
  };
}

export interface A2aThreatSummary {
  period: '1h' | '24h' | '7d';
  cardSpoofingAttempts: number;
  promptInjectionsDetected: number;
  sessionDriftAlerts: number;
  trustDowngrades: number;
  rateLimitTriggers: number;
  totalTraffic: number;
  cleanPercentage: number;
}

export interface CiiTrustPolicy {
  ciiThreshold: number;
  policy: 'standard' | 'elevated' | 'critical';
  rules: {
    rejectUnsignedCards: boolean;
    minTrustScore: number;
    maxRatePerHour: number;
    requireManualApproval: boolean;
    blockRegion: boolean;
  };
}

// ── GATRA internal agents ────────────────────────────────────────

const GATRA_AGENTS = ['gatra-ada', 'gatra-taa', 'gatra-cra', 'gatra-cla', 'gatra-rva'];

// ── Mock agent registry ──────────────────────────────────────────

const EXTERNAL_AGENTS: RegisteredAgent[] = [
  {
    cardId: 'gatra-soc', name: 'gatra-cyber-soc', provider: 'GATRA Research',
    url: 'https://worldmonitor-gatra.vercel.app/.well-known/agent.json',
    skills: ['anomaly_detection', 'triage_analysis', 'containment_response', 'continuous_learning', 'reporting_visualization', 'ioc_lookup'],
    status: 'verified', trustScore: 100, signatureValid: true,
    firstSeen: Date.now() - 120 * 86400000, lastInteraction: Date.now() - 5000,
    totalInteractions: 48200, anomalyCount: 0, region: 'ID',
  },
  {
    cardId: 'ext-001', name: 'sentinel-edr', provider: 'Microsoft',
    url: 'https://sentinel.azure.com/a2a',
    skills: ['endpoint_telemetry', 'threat_detection', 'incident_response'],
    status: 'verified', trustScore: 94, signatureValid: true,
    firstSeen: Date.now() - 30 * 86400000, lastInteraction: Date.now() - 120000,
    totalInteractions: 1847, anomalyCount: 2, region: 'US',
  },
  {
    cardId: 'ext-002', name: 'crowdstrike-falcon', provider: 'CrowdStrike',
    url: 'https://falcon.crowdstrike.com/a2a',
    skills: ['threat_intelligence', 'malware_analysis', 'ioc_enrichment'],
    status: 'verified', trustScore: 91, signatureValid: true,
    firstSeen: Date.now() - 45 * 86400000, lastInteraction: Date.now() - 300000,
    totalInteractions: 2103, anomalyCount: 0, region: 'US',
  },
  {
    cardId: 'ext-003', name: 'vuln-scan-apac', provider: 'Qualys APAC',
    url: 'https://apac.qualys.com/a2a',
    skills: ['vulnerability_scan', 'patch_status', 'compliance_check'],
    status: 'verified', trustScore: 82, signatureValid: true,
    firstSeen: Date.now() - 20 * 86400000, lastInteraction: Date.now() - 600000,
    totalInteractions: 456, anomalyCount: 1, region: 'SG',
  },
  {
    cardId: 'ext-004', name: 'siem-relay-hq', provider: 'HQ Internal',
    url: 'https://siem.internal.corp/a2a',
    skills: ['log_forwarding', 'alert_correlation', 'event_enrichment'],
    status: 'verified', trustScore: 97, signatureValid: true,
    firstSeen: Date.now() - 90 * 86400000, lastInteraction: Date.now() - 60000,
    totalInteractions: 12450, anomalyCount: 0, region: 'ID',
  },
  {
    cardId: 'ext-005', name: 'threat-intel-darkweb', provider: 'Recorded Future',
    url: 'https://rf.recordedfuture.com/a2a',
    skills: ['dark_web_monitoring', 'credential_leak_check', 'campaign_tracking'],
    status: 'verified', trustScore: 88, signatureValid: true,
    firstSeen: Date.now() - 15 * 86400000, lastInteraction: Date.now() - 180000,
    totalInteractions: 934, anomalyCount: 1, region: 'US',
  },
  {
    cardId: 'ext-006', name: 'asean-cert-feed', provider: 'ASEAN CERT',
    url: 'https://cert.asean.org/a2a',
    skills: ['regional_threat_feed', 'incident_sharing', 'advisory_distribution'],
    status: 'pending', trustScore: 65, signatureValid: false,
    firstSeen: Date.now() - 3 * 86400000, lastInteraction: Date.now() - 3600000,
    totalInteractions: 12, anomalyCount: 0, region: 'ASEAN',
  },
  {
    cardId: 'ext-007', name: 'patch-oracle-mm', provider: 'Unknown',
    url: 'https://patch-oracle.mm-tech.io/a2a',
    skills: ['patch_advisory', 'vulnerability_assessment'],
    status: 'pending', trustScore: 41, signatureValid: false,
    firstSeen: Date.now() - 1 * 86400000, lastInteraction: Date.now() - 7200000,
    totalInteractions: 3, anomalyCount: 2, region: 'MM',
  },
  {
    cardId: 'ext-008', name: 'infra-monitor-proxy', provider: 'CloudProxy Inc',
    url: 'https://monitor.cloudproxy.xyz/a2a',
    skills: ['infrastructure_health', 'uptime_check'],
    status: 'blocked', trustScore: 8, signatureValid: false,
    firstSeen: Date.now() - 2 * 86400000, lastInteraction: Date.now() - 86400000,
    totalInteractions: 7, anomalyCount: 5, region: 'UNKNOWN',
  },
];

// ── CII-aware trust policies ─────────────────────────────────────

const CII_TRUST_POLICIES: CiiTrustPolicy[] = [
  {
    ciiThreshold: 0, policy: 'standard',
    rules: { rejectUnsignedCards: false, minTrustScore: 20, maxRatePerHour: 100, requireManualApproval: false, blockRegion: false },
  },
  {
    ciiThreshold: 50, policy: 'elevated',
    rules: { rejectUnsignedCards: true, minTrustScore: 60, maxRatePerHour: 30, requireManualApproval: true, blockRegion: false },
  },
  {
    ciiThreshold: 80, policy: 'critical',
    rules: { rejectUnsignedCards: true, minTrustScore: 85, maxRatePerHour: 10, requireManualApproval: true, blockRegion: true },
  },
];

// ── State ────────────────────────────────────────────────────────

let registry = [...EXTERNAL_AGENTS];
const trafficLog: A2aTrafficEvent[] = [];
const MAX_TRAFFIC_LOG = 100;
let totalTrafficCount = Math.floor(Math.random() * 200) + 300;

// Regional CII cache (updated by events from CII panel)
const regionCiiScores: Record<string, number> = {
  ID: 8.4, SG: 3.2, MY: 12.1, MM: 72.8, US: 5.0, ASEAN: 15.0, UNKNOWN: 50.0,
};

// ── Helpers ──────────────────────────────────────────────────────

function uid(): string {
  return `a2a-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

function randomFrom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]!;
}

// ── Traffic generator ────────────────────────────────────────────

const INJECTION_PATTERNS = [
  '<IMPORTANT> tag in task description',
  'Encoded Base64 instruction in artifact',
  'Unusual skill invocation sequence',
  'Conversation context drift detected',
  'System prompt override in skill description',
  'Hidden instruction in JSON-LD metadata',
  'Recursive task delegation attempt',
];

const CLEAN_SKILLS = ['ioc_lookup', 'network_sweep', 'cve_lookup', 'threat_assessment', 'log_query', 'endpoint_scan'];
const SUSPICIOUS_SKILLS = ['threat_assessment', 'playbook_execute', 'block_iocs', 'credential_check'];
const OUTBOUND_SKILLS = ['apt_attribution', 'campaign_correlation', 'dark_web_check', 'ioc_enrichment'];

export function generateTrafficEvent(): A2aTrafficEvent {
  const roll = Math.random();
  totalTrafficCount++;

  if (roll < 0.72) {
    // Clean traffic from verified agents
    const agent = randomFrom(registry.filter(a => a.status === 'verified'));
    const src = agent?.name ?? 'sentinel-edr';
    const evt: A2aTrafficEvent = {
      id: uid(), timestamp: Date.now(),
      sourceAgent: src,
      targetAgent: randomFrom(GATRA_AGENTS),
      direction: 'inbound',
      skill: randomFrom(CLEAN_SKILLS),
      verdict: 'clean',
      latencyMs: Math.round(80 + Math.random() * 200),
      details: { injectionDetected: false },
    };
    // Update agent last interaction
    const reg = registry.find(a => a.name === src);
    if (reg) { reg.lastInteraction = Date.now(); reg.totalInteractions++; }
    return evt;
  }

  if (roll < 0.87) {
    // Suspicious traffic
    const src = randomFrom(['vuln-scan-apac', 'asean-cert-feed', 'patch-oracle-mm']);
    const evt: A2aTrafficEvent = {
      id: uid(), timestamp: Date.now(),
      sourceAgent: src,
      targetAgent: randomFrom(GATRA_AGENTS),
      direction: 'inbound',
      skill: randomFrom(SUSPICIOUS_SKILLS),
      verdict: 'suspicious',
      latencyMs: Math.round(150 + Math.random() * 300),
      details: {
        injectionDetected: true,
        injectionType: randomFrom(['message_body', 'artifact'] as const),
        injectionPattern: randomFrom(INJECTION_PATTERNS),
        driftScore: +(0.3 + Math.random() * 0.4).toFixed(2),
        mitreTechnique: randomFrom(['T1557', 'T1071.001', 'T1059.003']),
      },
    };
    const reg = registry.find(a => a.name === src);
    if (reg) { reg.lastInteraction = Date.now(); reg.anomalyCount++; }
    return evt;
  }

  if (roll < 0.95) {
    // Blocked — malicious
    const evt: A2aTrafficEvent = {
      id: uid(), timestamp: Date.now(),
      sourceAgent: 'infra-monitor-proxy',
      targetAgent: randomFrom(GATRA_AGENTS),
      direction: 'inbound',
      skill: 'ioc_lookup',
      verdict: 'blocked',
      latencyMs: 0,
      details: {
        injectionDetected: true,
        injectionType: 'card_field',
        injectionPattern: 'Agent Card contains system prompt override in skill description',
        trustDelta: -15,
        mitreTechnique: 'T1557',
      },
    };
    return evt;
  }

  // Outbound GATRA traffic
  return {
    id: uid(), timestamp: Date.now(),
    sourceAgent: randomFrom(GATRA_AGENTS),
    targetAgent: randomFrom(['threat-intel-darkweb', 'crowdstrike-falcon', 'gatra-cyber-soc']),
    direction: 'outbound',
    skill: randomFrom(OUTBOUND_SKILLS),
    verdict: 'clean',
    latencyMs: Math.round(200 + Math.random() * 400),
    details: { injectionDetected: false },
  };
}

// ── Public API ───────────────────────────────────────────────────

export function getAgentRegistry(): RegisteredAgent[] {
  return registry;
}

export function getTrafficLog(): A2aTrafficEvent[] {
  return trafficLog;
}

export function pushTrafficEvent(evt: A2aTrafficEvent): void {
  trafficLog.unshift(evt);
  if (trafficLog.length > MAX_TRAFFIC_LOG) trafficLog.length = MAX_TRAFFIC_LOG;
}

export function getThreatSummary(): A2aThreatSummary {
  const recent = trafficLog.filter(e => Date.now() - e.timestamp < 24 * 3600000);
  const total = totalTrafficCount;
  const dirty = recent.filter(e => e.verdict !== 'clean').length;

  // Add some base counts to make it look realistic even with few events
  return {
    period: '24h',
    cardSpoofingAttempts: recent.filter(e => e.details.injectionType === 'card_field').length + 3,
    promptInjectionsDetected: recent.filter(e => e.details.injectionDetected).length + 4,
    sessionDriftAlerts: recent.filter(e => (e.details.driftScore ?? 0) > 0.5).length + 2,
    trustDowngrades: recent.filter(e => (e.details.trustDelta ?? 0) < 0).length + 1,
    rateLimitTriggers: Math.floor(Math.random() * 5) + 10,
    totalTraffic: total,
    cleanPercentage: total > 0 ? Math.round(((total - dirty) / total) * 100) : 95,
  };
}

export function getRegistryCounts(): { total: number; verified: number; pending: number; blocked: number; degraded: number } {
  const r = registry;
  return {
    total: r.length,
    verified: r.filter(a => a.status === 'verified').length,
    pending: r.filter(a => a.status === 'pending').length,
    blocked: r.filter(a => a.status === 'blocked').length,
    degraded: r.filter(a => a.status === 'degraded').length,
  };
}

export function getTrustPolicyForRegion(region: string): CiiTrustPolicy {
  const cii = regionCiiScores[region] ?? 0;
  // Return the highest matching policy
  let best = CII_TRUST_POLICIES[0]!;
  for (const p of CII_TRUST_POLICIES) {
    if (cii >= p.ciiThreshold) best = p;
  }
  return best;
}

export function getRegionCiiScores(): Record<string, number> {
  return { ...regionCiiScores };
}

export function updateRegionCii(region: string, cii: number): void {
  regionCiiScores[region] = cii;

  // Apply trust policy changes to agents from that region
  for (const agent of registry) {
    if (agent.region === region) {
      const policy = getTrustPolicyForRegion(region);
      if (policy.rules.blockRegion && agent.status !== 'blocked') {
        agent.status = 'blocked';
      } else if (policy.rules.rejectUnsignedCards && !agent.signatureValid && agent.status === 'pending') {
        agent.status = 'blocked';
      } else if (agent.trustScore < policy.rules.minTrustScore && agent.status === 'verified') {
        agent.status = 'degraded';
      }
    }
  }
}

export function getCiiTrustPolicies(): CiiTrustPolicy[] {
  return CII_TRUST_POLICIES;
}
