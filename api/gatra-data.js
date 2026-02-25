// Standalone Vercel Edge function — queries BigQuery for real GATRA SOC data.
// Falls back gracefully with { error, source: 'bigquery_error' } so the
// frontend connector can use mock data as fallback.
export const config = { runtime: 'edge' };

// ── Data sanitization — strip telco provider identifiers ──────────

const SANITIZE_RULES = [
  // Email domains
  [/@ioh\.co\.id/gi, '@telco-corp.local'],
  [/@indosat\.com/gi, '@telco-corp.local'],
  [/@indosatooredoo\.com/gi, '@telco-corp.local'],
  // Full company names (longest first to avoid partial matches)
  [/Indosat\s*Ooredoo\s*Hutchison/gi, 'TELCO-ID'],
  [/Indosat\s*Ooredoo/gi, 'TELCO-ID'],
  [/Indosat/gi, 'TELCO-ID'],
  [/IOH\b/g, 'TELCO-ID'],
  // Abbreviations in hostnames / event names
  [/\bioh\b/gi, 'telco-id'],
  // AIE rule prefixes that leak the provider name
  [/AIE:\s*Indosat:/gi, 'AIE: TELCO-ID:'],
  // Internal domain references
  [/\.ioh\.co\.id/gi, '.telco-corp.local'],
  [/\.indosat\.com/gi, '.telco-corp.local'],
  // APT group names
  [/Gallium/gi, 'APT-G01'],
  // Technical internals that should not be exposed
  [/\bbad_ip\b/g, 'malicious_traffic'],
  [/\bcredential_access\b/g, 'auth_anomaly'],
  [/\bBigQuery\b/gi, 'Cloud Analytics'],
  [/\bbigquery\b/g, 'cloud_analytics'],
];

/** Scrub a string of all telco provider references */
function sanitize(str) {
  if (!str || typeof str !== 'string') return str;
  let out = str;
  for (const [re, replacement] of SANITIZE_RULES) {
    out = out.replace(re, replacement);
  }
  return out;
}

/** Deep-sanitize all string values in an object/array */
function sanitizeDeep(obj) {
  if (typeof obj === 'string') return sanitize(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeDeep);
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = sanitizeDeep(v);
    }
    return out;
  }
  return obj;
}

// ── JWT / OAuth helpers ────────────────────────────────────────────

function base64url(input) {
  const str = typeof input === 'string'
    ? btoa(unescape(encodeURIComponent(input)))
    : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/bigquery.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }));

  // Import PKCS#8 private key
  const pemBody = sa.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');
  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    'pkcs8',
    binaryDer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const unsigned = `${header}.${claims}`;
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned),
  );
  const jwt = `${unsigned}.${base64url(sig)}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  if (!tokenRes.ok) {
    const detail = await tokenRes.text();
    throw new Error(`OAuth failed ${tokenRes.status}: ${detail}`);
  }
  return (await tokenRes.json()).access_token;
}

// ── BigQuery REST query ────────────────────────────────────────────

async function runQuery(token, projectId, sql) {
  const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${projectId}/queries`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: sql, useLegacySql: false, maxResults: 200, timeoutMs: 55000 }),
    signal: AbortSignal.timeout(58000),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`BigQuery ${res.status}: ${err.slice(0, 400)}`);
  }
  const data = await res.json();
  if (!data.jobComplete) throw new Error('BigQuery job timed out');
  return data.rows || [];
}

// ── Deterministic hash helpers ─────────────────────────────────────

function hashCode(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return h;
}
function hashPick(s, arr) { return arr[Math.abs(hashCode(s)) % arr.length]; }
function hashFloat(s) { return (Math.abs(hashCode(s)) % 10000) / 10000; }

// ── Reference data ─────────────────────────────────────────────────

const LOCATIONS = [
  { name: 'Jakarta', lat: -6.2088, lon: 106.8456 },
  { name: 'Surabaya', lat: -7.2575, lon: 112.7521 },
  { name: 'Bandung', lat: -6.9175, lon: 107.6191 },
  { name: 'Medan', lat: 3.5952, lon: 98.6722 },
  { name: 'Makassar', lat: -5.1477, lon: 119.4327 },
];

const MITRE_MAP = {
  login_failed:          { id: 'T1110', name: 'Brute Force' },
  login_success:         { id: 'T1078', name: 'Valid Accounts' },
  auth_failure:          { id: 'T1110', name: 'Brute Force' },
  file_access:           { id: 'T1083', name: 'File and Directory Discovery' },
  process_exec:          { id: 'T1059', name: 'Command and Scripting Interpreter' },
  network_connect:       { id: 'T1071', name: 'Application Layer Protocol' },
  dns_query:             { id: 'T1071.004', name: 'DNS' },
  registry_mod:          { id: 'T1112', name: 'Modify Registry' },
  service_create:        { id: 'T1543', name: 'Create or Modify System Process' },
  firewall_mod:          { id: 'T1562', name: 'Impair Defenses' },
  data_transfer:         { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
  privilege_escalation:  { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
  lateral_movement:      { id: 'T1021', name: 'Remote Services' },
};
const MITRE_DEFAULT = { id: 'T1036', name: 'Masquerading' };

const ACTORS = [
  'APT-41 (Winnti)', 'Lazarus Group', 'Mustang Panda',
  'OceanLotus (APT-32)', 'Naikon APT', 'SideWinder',
  'Turla Group', 'Unknown / Unattributed',
];
const CAMPAIGNS = [
  'Operation ShadowNet', 'Campaign CobaltStrike-SEA', 'Project DarkTide',
  'Operation MalayBridge', 'Campaign TelekomTarget', 'Opportunistic Scanning',
];
const KC_PHASES = ['reconnaissance', 'delivery', 'exploitation', 'installation', 'c2', 'actions'];
const CRA_TEMPLATES = [
  { text: 'Blocked source IP at perimeter firewall', type: 'ip_blocked' },
  { text: 'Isolated affected endpoint from network', type: 'endpoint_isolated' },
  { text: 'Revoked compromised service credentials', type: 'credential_rotated' },
  { text: 'Triggered SOAR playbook for incident', type: 'playbook_triggered' },
  { text: 'Enabled enhanced logging on segment', type: 'rule_pushed' },
];

// ── MITRE mapping for classification types ────────────────────────

const CLASSIFICATION_MITRE = {
  'Error':                { id: 'T1562', name: 'Impair Defenses' },
  'Operations':           { id: 'T1059', name: 'Command and Scripting Interpreter' },
  'Audit':                { id: 'T1078', name: 'Valid Accounts' },
  'Security':             { id: 'T1110', name: 'Brute Force' },
  'Authentication':       { id: 'T1078', name: 'Valid Accounts' },
  'Network':              { id: 'T1071', name: 'Application Layer Protocol' },
  'Malware':              { id: 'T1204', name: 'User Execution' },
  'Intrusion':            { id: 'T1190', name: 'Exploit Public-Facing Application' },
  'Suspicious':           { id: 'T1036', name: 'Masquerading' },
  'Compromise':           { id: 'T1021', name: 'Remote Services' },
};

// ── Row transforms — one per strategy type ────────────────────────

function priorityToSeverity(p) {
  if (p >= 80) return 'critical';
  if (p >= 60) return 'high';
  if (p >= 30) return 'medium';
  return 'low';
}

function probToSeverity(p) {
  if (p >= 0.9) return 'critical';
  if (p >= 0.7) return 'high';
  if (p >= 0.4) return 'medium';
  return 'low';
}

/** Derive MITRE technique from event name keywords */
function eventNameToMitre(name) {
  if (!name) return null;
  const n = name.toLowerCase();
  if (n.includes('c&c') || n.includes('c2') || n.includes('command and control')) return { id: 'T1071', name: 'Application Layer Protocol (C2)' };
  if (n.includes('gallium') || n.includes('apt')) return { id: 'T1190', name: 'Exploit Public-Facing Application' };
  if (n.includes('malware')) return { id: 'T1204', name: 'User Execution (Malware)' };
  if (n.includes('brute') || n.includes('login fail')) return { id: 'T1110', name: 'Brute Force' };
  if (n.includes('heartbeat') || n.includes('agent')) return { id: 'T1562', name: 'Impair Defenses' };
  if (n.includes('exfil') || n.includes('data transfer')) return { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' };
  if (n.includes('lateral') || n.includes('remote')) return { id: 'T1021', name: 'Remote Services' };
  if (n.includes('phish')) return { id: 'T1566', name: 'Phishing' };
  if (n.includes('credential') || n.includes('password')) return { id: 'T1110', name: 'Brute Force' };
  if (n.includes('scan') || n.includes('recon')) return { id: 'T1046', name: 'Network Service Discovery' };
  if (n.includes('privilege') || n.includes('escalat')) return { id: 'T1068', name: 'Exploitation for Privilege Escalation' };
  if (n.includes('firewall') || n.includes('rule')) return { id: 'T1562.004', name: 'Disable or Modify System Firewall' };
  if (n.includes('dns')) return { id: 'T1071.004', name: 'DNS' };
  return null;
}

/** Transform a siem_events row (alarmId, events JSON, priority, etc.) */
function siemRowToAlert(fields, idx) {
  const v = (i) => fields[i]?.v ?? '';
  const alarmId       = v(0) || `siem-${idx}`;
  const eventName     = v(1);
  const classification = v(2);
  const classType     = v(3);
  const entityName    = v(4);
  const impactedHost  = v(5);
  const originHost    = v(6);
  const logDate       = v(7);
  const logMessage    = v(8);
  const priority      = parseInt(v(9)) || 0;
  const severity      = v(10);
  const serviceName   = v(11);
  const direction     = v(12);
  const impactedIP    = v(13);
  const originIP      = v(14);
  const impactedPort  = v(15);
  const originPort    = v(16);
  const protocol      = v(17);
  const ingestionTime = v(18);

  // MITRE mapping — try event name keywords first, then classification
  const mitre = eventNameToMitre(eventName) || CLASSIFICATION_MITRE[classification] || CLASSIFICATION_MITRE[classType] || MITRE_DEFAULT;

  // Severity from priority field
  const sev = priorityToSeverity(priority);

  // Confidence from priority (normalize 0-100 range)
  const confidence = Math.min(99, Math.max(10, priority));

  // Location from entityName (e.g. "Balikpapan Region") or deterministic
  const loc = entityToLocation(entityName) || hashPick(alarmId, LOCATIONS);

  // Description
  let desc = eventName || logMessage || `SIEM alarm #${alarmId}`;
  if (desc.length > 200) desc = desc.slice(0, 197) + '...';

  // Infrastructure
  const infra = impactedHost || originHost || `SIEM-${entityName || 'UNKNOWN'}`;

  return {
    id: `gatra-siem-${alarmId}`,
    severity: sev,
    mitreId: mitre.id,
    mitreName: mitre.name,
    description: desc,
    confidence,
    lat: loc.lat + (hashFloat(alarmId) - 0.5) * 0.06,
    lon: loc.lon + (hashFloat(alarmId + 'x') - 0.5) * 0.06,
    locationName: loc.name,
    infrastructure: infra,
    timestamp: logDate || ingestionTime || new Date().toISOString(),
    agent: 'ADA',
    _srcIp: originIP,
    _dstIp: impactedIP,
    _label: classification === 'Security' || classification === 'Malware' ? 'threat' : '',
    _probY1: priority / 100,
  };
}

/** Transform an activity_logs row */
function activityRowToAlert(fields, idx) {
  const v = (i) => fields[i]?.v ?? '';
  const eventTs   = v(0);
  const user      = v(1);
  const action    = v(2);
  const details   = v(3);
  const page      = v(4);
  const sessionId = v(5) || `act-${idx}`;

  const mitre = MITRE_MAP[action] || MITRE_DEFAULT;

  // Parse details JSON if possible for richer info
  let detailObj = {};
  try { if (details) detailObj = JSON.parse(details); } catch {}

  const severity = action === 'login_failed' ? 'medium'
    : action === 'login_success' ? 'low'
    : 'low';

  const confidence = action.includes('fail') ? 55 : 35;
  const loc = hashPick(sessionId, LOCATIONS);

  let desc = `${action}: ${user || 'unknown'}`;
  if (page && page !== 'unknown') desc += ` on ${page}`;

  return {
    id: `gatra-act-${sessionId}-${idx}`,
    severity,
    mitreId: mitre.id,
    mitreName: mitre.name,
    description: desc,
    confidence,
    lat: loc.lat + (hashFloat(sessionId) - 0.5) * 0.06,
    lon: loc.lon + (hashFloat(sessionId + 'x') - 0.5) * 0.06,
    locationName: loc.name,
    infrastructure: page || 'Streamlit Dashboard',
    timestamp: eventTs || new Date().toISOString(),
    agent: 'ADA',
    _srcIp: '',
    _dstIp: '',
    _label: action === 'login_failed' ? 'threat' : '',
    _probY1: confidence / 100,
  };
}

// ── State table transforms (real GATRA agent output) ─────────────

/** Transform an ada_state row joined with siem_alarms */
function adaStateToAlert(fields, idx) {
  const v = (i) => fields[i]?.v ?? '';
  const id           = v(0) || `ada-${idx}`;
  const alarmId      = v(1);
  const score        = parseFloat(v(2)) || 0;
  const confidence   = parseFloat(v(3)) || 0;
  const detectionTs  = v(4);
  const valid        = v(5) === 'true';
  const caseClass    = v(6) || 'unknown';
  const runTime      = parseFloat(v(7)) || 0;
  const reasoning    = v(8);
  const recCaseClass = v(9);
  const createdAt    = v(10);
  const alarmRule    = v(11);
  const entityName   = v(12);
  const alarmDate    = v(13);

  // Map case_class to MITRE
  const CASE_CLASS_MITRE = {
    bad_ip:              { id: 'T1071', name: 'C2 Communication (Malicious Traffic)' },
    malware:             { id: 'T1204', name: 'User Execution (Malware)' },
    brute_force:         { id: 'T1110', name: 'Brute Force' },
    lateral_movement:    { id: 'T1021', name: 'Remote Services (Lateral)' },
    data_exfiltration:   { id: 'T1048', name: 'Exfiltration' },
    privilege_escalation:{ id: 'T1068', name: 'Privilege Escalation' },
    phishing:            { id: 'T1566', name: 'Phishing' },
    reconnaissance:      { id: 'T1046', name: 'Network Discovery' },
    other:               { id: 'T1036', name: 'Masquerading' },
    operational_warning: { id: 'T1562', name: 'Impair Defenses' },
    log_source_monitoring:{ id: 'T1562.002', name: 'Disable Windows Event Logging' },
  };

  // Try alarm rule keywords first (most specific), then case_class, then eventNameToMitre
  const mitre = eventNameToMitre(alarmRule)
    || CASE_CLASS_MITRE[caseClass]
    || CASE_CLASS_MITRE[recCaseClass]
    || MITRE_DEFAULT;

  // Severity: combine ML score with case_class context
  // Operational/monitoring alerts should be lower severity even with high ML scores
  const CASE_CLASS_SEVERITY_CAP = {
    other: 'medium',                // Operational events capped at medium
    log_source_monitoring: 'low',   // Log monitoring is informational
    operational_warning: 'medium',  // Operational warnings capped at medium
  };
  const cap = CASE_CLASS_SEVERITY_CAP[caseClass];

  let sev;
  if (cap) {
    // Capped case classes — ML score determines within cap
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const rawSev = score >= 0.9 ? 'high' : score >= 0.6 ? 'medium' : 'low';
    const capIdx = severityOrder.indexOf(cap);
    const rawIdx = severityOrder.indexOf(rawSev);
    sev = severityOrder[Math.min(capIdx, rawIdx)];
  } else {
    // Security-relevant case classes — use full ML score
    sev = score >= 0.9 ? 'critical'
      : score >= 0.7 ? 'high'
      : score >= 0.4 ? 'medium'
      : 'low';
  }

  // Confidence from ADA's actual confidence value (0-1 → 0-100)
  const conf = Math.min(99, Math.max(10, Math.round(confidence * 100)));

  // Location from entity name
  const loc = entityToLocation(entityName) || hashPick(alarmId || id, LOCATIONS);

  // Description — use real ADA reasoning or alarm rule
  let desc = reasoning || alarmRule || `ADA detection: ${caseClass}`;
  if (desc.length > 200) desc = desc.slice(0, 197) + '...';

  // Infrastructure from alarm rule or entity
  const infra = alarmRule
    ? alarmRule.replace(/^AIE:\s*/i, '').slice(0, 80)
    : entityName || 'GATRA Infrastructure';

  return {
    id: `gatra-ada-${alarmId || id}`,
    severity: sev,
    mitreId: mitre.id,
    mitreName: mitre.name,
    description: desc,
    confidence: conf,
    lat: loc.lat + (hashFloat(id) - 0.5) * 0.06,
    lon: loc.lon + (hashFloat(id + 'x') - 0.5) * 0.06,
    locationName: loc.name,
    infrastructure: infra,
    timestamp: createdAt || detectionTs || new Date().toISOString(),
    agent: 'ADA',
    caseClass,
    recCaseClass,
    mlScore: score,
    adaRuntime: runTime,
    valid,
    _srcIp: '',
    _dstIp: '',
    _label: (caseClass === 'bad_ip' || caseClass === 'malware' || !valid) ? 'threat' : '',
    _probY1: score,
  };
}

/** Transform a taa_state row into a TAA analysis object */
function taaStateToAnalysis(fields, idx) {
  const v = (i) => fields[i]?.v ?? '';
  const id         = v(0) || `taa-${idx}`;
  const alarmId    = v(1);
  const confidence = parseFloat(v(2)) || 0;
  const severity   = parseFloat(v(3)) || 0;
  const valid      = v(4) === 'true';
  const runTime    = parseFloat(v(5)) || 0;
  const reasoning  = v(6);
  const remarks    = v(7);
  const createdAt  = v(8);
  const isAnomaly  = v(9) === 'true';
  const alarmRule  = v(10);

  // Derive actor attribution from alarm rule keywords
  const ruleUpper = (alarmRule + ' ' + reasoning).toLowerCase();
  const actor = ruleUpper.includes('gallium') ? 'Gallium APT'
    : ruleUpper.includes('c&c') || ruleUpper.includes('c2') ? 'APT-41 (Winnti)'
    : ruleUpper.includes('brute') ? 'Opportunistic Scanner'
    : ruleUpper.includes('apt') ? 'Naikon APT'
    : hashPick(id, ACTORS);

  const campaign = hashPick(id + 'c', CAMPAIGNS);
  const killChainPhase = severity >= 0.8 ? 'actions'
    : severity >= 0.6 ? 'c2'
    : severity >= 0.4 ? 'exploitation'
    : severity >= 0.2 ? 'delivery'
    : 'reconnaissance';

  return {
    id: `taa-bq-${id.slice(0, 8)}`,
    alertId: `gatra-ada-${alarmId}`,
    actorAttribution: actor,
    campaign,
    killChainPhase,
    confidence: Math.min(99, Math.round(confidence * 100)),
    severity: Math.round(severity * 100),
    iocs: [],
    timestamp: createdAt || new Date().toISOString(),
    reasoning: reasoning.slice(0, 200) || remarks.slice(0, 200) || 'TAA analysis',
    isAnomaly,
    valid,
    taaRuntime: runTime,
  };
}

/** Transform a cra_state row into a CRA action object */
function craStateToAction(fields, idx) {
  const v = (i) => fields[i]?.v ?? '';
  const actionId   = v(0) || `cra-${idx}`;
  const alarmId    = v(1);
  const actionType = v(2) || 'notify_email';
  const remarks    = v(3);
  const reasoning  = v(4);
  const success    = v(5) === 'true';
  const createdAt  = v(6);
  const runtime    = parseFloat(v(7)) || 0;
  const alarmRule  = v(8);
  const entityName = v(9);

  // Map action_type to friendly text
  const ACTION_TEXT = {
    notify_email:       'Sent email notification to SOC team',
    ip_blocked:         'Blocked source IP at perimeter firewall',
    endpoint_isolated:  'Isolated affected endpoint from network',
    credential_rotated: 'Revoked compromised service credentials',
    playbook_triggered: 'Triggered SOAR playbook for incident',
    rule_pushed:        'Pushed updated detection rule',
    quarantine:         'Quarantined suspicious file/process',
  };

  const actionText = ACTION_TEXT[actionType]
    || reasoning.slice(0, 120)
    || remarks.slice(0, 120)
    || `CRA action: ${actionType}`;

  return {
    id: `cra-bq-${actionId.slice(0, 8)}`,
    action: actionText,
    actionType,
    target: alarmRule ? alarmRule.replace(/^AIE:\s*/i, '').slice(0, 80) : entityName || 'GATRA Infrastructure',
    timestamp: createdAt || new Date().toISOString(),
    success,
    runtime,
    alarmId,
  };
}

/** Map entity name to known Indonesian location */
function entityToLocation(entity) {
  if (!entity) return null;
  const e = entity.toLowerCase();
  if (e.includes('jakarta') || e.includes('jkt')) return { name: 'Jakarta', lat: -6.2088, lon: 106.8456 };
  if (e.includes('surabaya') || e.includes('sby')) return { name: 'Surabaya', lat: -7.2575, lon: 112.7521 };
  if (e.includes('bandung') || e.includes('bdg')) return { name: 'Bandung', lat: -6.9175, lon: 107.6191 };
  if (e.includes('medan') || e.includes('mdn')) return { name: 'Medan', lat: 3.5952, lon: 98.6722 };
  if (e.includes('makassar') || e.includes('mks') || e.includes('ujung pandang')) return { name: 'Makassar', lat: -5.1477, lon: 119.4327 };
  if (e.includes('balikpapan') || e.includes('bpp')) return { name: 'Balikpapan', lat: -1.2654, lon: 116.8311 };
  if (e.includes('semarang') || e.includes('smg')) return { name: 'Semarang', lat: -6.9666, lon: 110.4196 };
  if (e.includes('denpasar') || e.includes('bali')) return { name: 'Denpasar', lat: -8.6500, lon: 115.2167 };
  if (e.includes('palembang') || e.includes('plm')) return { name: 'Palembang', lat: -2.9761, lon: 104.7754 };
  if (e.includes('manado') || e.includes('mdo')) return { name: 'Manado', lat: 1.4748, lon: 124.8421 };
  return null;
}

// ── Build full snapshot ────────────────────────────────────────────

function buildSnapshot(alerts, realTaaAnalyses, realCraActions) {
  const critHigh = alerts.filter(a => a.severity === 'critical' || a.severity === 'high');
  const labeled = alerts.filter(a => a._label === 'threat');
  const anomalies = (realTaaAnalyses || []).filter(t => t.isAnomaly);

  // Incident summary
  const summary = {
    activeIncidents: critHigh.length,
    mttrMinutes: critHigh.length > 0 ? 8 + Math.abs(hashCode(String(Date.now()))) % 25 : 0,
    alerts24h: alerts.length,
    responses24h: (realCraActions || []).filter(c => c.success).length || labeled.length,
  };

  // Agent status — all real (we queried actual state tables)
  const now = new Date().toISOString();
  const agents = [
    { name: 'ADA', fullName: 'Anomaly Detection Agent', status: alerts.length > 0 ? 'online' : 'degraded', lastHeartbeat: now },
    { name: 'TAA', fullName: 'Triage & Analysis Agent', status: (realTaaAnalyses || []).length > 0 ? 'online' : 'processing', lastHeartbeat: now },
    { name: 'CRA', fullName: 'Containment & Response Agent', status: (realCraActions || []).length > 0 ? 'online' : 'processing', lastHeartbeat: now },
    { name: 'CLA', fullName: 'Continuous Learning Agent', status: labeled.length > 0 ? 'online' : 'processing', lastHeartbeat: now },
    { name: 'RVA', fullName: 'Reporting & Visualization Agent', status: 'online', lastHeartbeat: now },
  ];

  // Use real TAA analyses if available, fallback to synthetic
  const taaAnalyses = (realTaaAnalyses || []).length > 0
    ? realTaaAnalyses.slice(0, 8)
    : critHigh.slice(0, 6).map((a, i) => ({
        id: `taa-bq-${i}`,
        alertId: a.id,
        actorAttribution: hashPick(a.id, ACTORS),
        campaign: hashPick(a.id + 'c', CAMPAIGNS),
        killChainPhase: hashPick(a.id + 'k', KC_PHASES),
        confidence: Math.min(99, Math.round(a.confidence * 0.85 + hashFloat(a.id + 'cf') * 15)),
        iocs: [a._srcIp, a._dstIp].filter(Boolean),
        timestamp: a.timestamp,
      }));

  // Use real CRA actions if available, fallback to synthetic
  const craActions = (realCraActions || []).length > 0
    ? realCraActions.slice(0, 8)
    : critHigh.slice(0, 5).map((a, i) => {
        const tmpl = hashPick(a.id + 'cra', CRA_TEMPLATES);
        return {
          id: `cra-bq-${i}`,
          action: tmpl.text,
          actionType: tmpl.type,
          target: a.infrastructure,
          timestamp: a.timestamp,
          success: hashFloat(a.id + 'ok') > 0.1,
        };
      });

  // Clean internal fields
  const cleanAlerts = alerts.map(({ _srcIp, _dstIp, _label, _probY1, ...rest }) => rest);

  return {
    alerts: cleanAlerts,
    agents,
    summary,
    craActions,
    taaAnalyses,
    correlations: [],
    lastRefresh: now,
    source: 'gatra_live',
    rowCount: alerts.length,
  };
}

// ── Main handler ───────────────────────────────────────────────────

export default async function handler(req) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  const saKeyJson = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!saKeyJson) {
    return new Response(
      JSON.stringify({ error: 'GOOGLE_SERVICE_ACCOUNT_KEY not configured', source: 'config_error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } },
    );
  }

  try {
    const sa = JSON.parse(saKeyJson);
    const saProject = sa.project_id || 'chronicle-dev-2be9';
    const token = await getAccessToken(sa);

    const PROD_PROJECT = 'gatra-prd-c335';
    const DATASET = 'gatra_database';

    // ── Diagnostic mode: ?diag=1 — enumerate tables & freshness ──
    if (new URL(req.url).searchParams.has('diag')) {
      const diagResults = {};
      // List tables in dev project
      try {
        const devTables = await runQuery(token, saProject,
          `SELECT table_id, row_count, TIMESTAMP_MILLIS(last_modified_time) AS last_modified
           FROM \`${saProject}.${DATASET}.__TABLES__\`
           ORDER BY last_modified_time DESC`);
        diagResults.devTables = devTables.map(r => ({
          name: r.f[0]?.v, rows: r.f[1]?.v, lastModified: r.f[2]?.v,
        }));
      } catch (e) { diagResults.devTablesError = String(e).slice(0, 300); }

      // List tables in prod project
      try {
        const prodTables = await runQuery(token, PROD_PROJECT,
          `SELECT table_id, row_count, TIMESTAMP_MILLIS(last_modified_time) AS last_modified
           FROM \`${PROD_PROJECT}.${DATASET}.__TABLES__\`
           ORDER BY last_modified_time DESC`);
        diagResults.prodTables = prodTables.map(r => ({
          name: r.f[0]?.v, rows: r.f[1]?.v, lastModified: r.f[2]?.v,
        }));
      } catch (e) { diagResults.prodTablesError = String(e).slice(0, 300); }

      // Try sampling columns from any tables we find
      if (diagResults.devTables) {
        diagResults.tableSchemas = {};
        for (const tbl of diagResults.devTables.slice(0, 8)) {
          try {
            const cols = await runQuery(token, saProject,
              `SELECT column_name, data_type FROM \`${saProject}.${DATASET}\`.INFORMATION_SCHEMA.COLUMNS WHERE table_name = '${tbl.name}' ORDER BY ordinal_position`);
            diagResults.tableSchemas[tbl.name] = cols.map(r => ({ col: r.f[0]?.v, type: r.f[1]?.v }));
          } catch (e) { diagResults.tableSchemas[tbl.name] = { error: String(e).slice(0, 150) }; }
        }
      }

      // Check freshness of known tables
      const freshnessChecks = [
        { label: 'dev_siem', project: saProject, sql: `SELECT MAX(ingestion_time) AS latest, MIN(ingestion_time) AS oldest, COUNT(*) AS total FROM \`${saProject}.${DATASET}.siem_events\`` },
        { label: 'dev_activity', project: saProject, sql: `SELECT MAX(event_timestamp) AS latest, MIN(event_timestamp) AS oldest, COUNT(*) AS total FROM \`${saProject}.${DATASET}.activity_logs\`` },
      ];
      diagResults.freshness = {};
      for (const chk of freshnessChecks) {
        try {
          const rows = await runQuery(token, chk.project, chk.sql);
          if (rows.length > 0) {
            diagResults.freshness[chk.label] = {
              latest: rows[0].f[0]?.v, oldest: rows[0].f[1]?.v, total: rows[0].f[2]?.v,
            };
          }
        } catch (e) { diagResults.freshness[chk.label] = { error: String(e).slice(0, 200) }; }
      }

      // Key test: cross-project query (run job in dev, read prod tables)
      const crossProjectTests = [
        { label: 'prod_xproject_tables', sql: `SELECT table_id, row_count, TIMESTAMP_MILLIS(last_modified_time) AS lm FROM \`${PROD_PROJECT}.${DATASET}.__TABLES__\` ORDER BY last_modified_time DESC LIMIT 15` },
        { label: 'prod_xproject_queue', sql: `SELECT COUNT(*) AS cnt, MAX(scored_at) AS latest FROM \`${PROD_PROJECT}.${DATASET}.ada_predictions_v4_prod_queue\` WHERE snapshot_dt >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)` },
      ];
      diagResults.crossProject = {};
      for (const t of crossProjectTests) {
        try {
          // Run job in DEV project but reference PROD tables
          const rows = await runQuery(token, saProject, t.sql);
          diagResults.crossProject[t.label] = rows.map(r => r.f.map(c => c?.v));
        } catch (e) { diagResults.crossProject[t.label] = { error: String(e).slice(0, 300) }; }
      }

      // Get schemas and sample for state tables
      diagResults.stateSchemas = {};
      for (const tbl of ['ada_state', 'taa_state', 'cra_state', 'siem_alarms', 'processed_alerts']) {
        try {
          const cols = await runQuery(token, saProject,
            `SELECT column_name, data_type FROM \`${saProject}.${DATASET}\`.INFORMATION_SCHEMA.COLUMNS WHERE table_name = '${tbl}' ORDER BY ordinal_position`);
          diagResults.stateSchemas[tbl] = cols.map(r => `${r.f[0]?.v} (${r.f[1]?.v})`);
        } catch (e) { diagResults.stateSchemas[tbl] = { error: String(e).slice(0, 150) }; }
      }

      // Freshness of state tables
      const stateFresh = [
        { label: 'ada_state', sql: `SELECT MAX(created_at) AS latest, MIN(created_at) AS oldest FROM \`${saProject}.${DATASET}.ada_state\`` },
        { label: 'taa_state', sql: `SELECT MAX(created_at) AS latest, MIN(created_at) AS oldest FROM \`${saProject}.${DATASET}.taa_state\`` },
        { label: 'cra_state', sql: `SELECT MAX(created_at) AS latest, MIN(created_at) AS oldest FROM \`${saProject}.${DATASET}.cra_state\`` },
      ];
      diagResults.stateFreshness = {};
      for (const chk of stateFresh) {
        try {
          const rows = await runQuery(token, saProject, chk.sql);
          if (rows.length > 0) diagResults.stateFreshness[chk.label] = { latest: rows[0].f[0]?.v, oldest: rows[0].f[1]?.v };
        } catch (e) { diagResults.stateFreshness[chk.label] = { error: String(e).slice(0, 150) }; }
      }

      return new Response(JSON.stringify({ diag: true, saProject, saEmail: sa.client_email, ...diagResults }, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // ── Query rich state tables + SIEM data ──────────────────────────

    let allAlerts = [];
    let realTaaAnalyses = [];
    let realCraActions = [];
    let usedStrategies = [];
    const strategyErrors = [];

    // Strategy 1: ADA state joined with SIEM alarms — stratified sample across case classes + alarm rules
    try {
      const rows = await runQuery(token, saProject, `
        WITH ranked AS (
          SELECT
            a.id, a.alarm_id, a.score, a.confidence,
            CAST(a.detection_timestamp AS STRING) AS detection_ts,
            a.valid, a.case_class, a.run_time,
            IFNULL(a.reasoning, '') AS reasoning,
            IFNULL(a.rec_case_class, '') AS rec_case_class,
            CAST(a.created_at AS STRING) AS created_at,
            IFNULL(s.alarmRuleName, '') AS alarm_rule,
            IFNULL(s.entityName, '') AS entity_name,
            IFNULL(s.dateInserted, '') AS alarm_date,
            ROW_NUMBER() OVER (
              PARTITION BY IFNULL(a.case_class, 'unknown'), IFNULL(s.alarmRuleName, 'none')
              ORDER BY a.created_at DESC
            ) AS rn
          FROM \`${saProject}.${DATASET}.ada_state\` a
          LEFT JOIN \`${saProject}.${DATASET}.siem_alarms\` s
            ON SAFE_CAST(a.alarm_id AS INT64) = s.alarmId
        )
        SELECT id, alarm_id, score, confidence, detection_ts, valid, case_class, run_time,
               reasoning, rec_case_class, created_at, alarm_rule, entity_name, alarm_date
        FROM ranked
        WHERE rn <= 5
        ORDER BY created_at DESC
        LIMIT 100`);
      if (rows.length > 0) {
        const transformed = rows.map((r, i) => adaStateToAlert(r.f, i));
        allAlerts.push(...transformed);
        usedStrategies.push(`ada_state(${rows.length})`);
      }
    } catch (e) { strategyErrors.push({ name: 'ada_state', error: String(e).slice(0, 200) }); }

    // Strategy 2: TAA state — real triage analyses with confidence, severity, anomaly detection
    try {
      const rows = await runQuery(token, saProject, `
        SELECT
          t.id, t.alarm_id, t.confidence, t.severity, t.valid,
          t.run_time, IFNULL(t.reasoning, '') AS reasoning,
          IFNULL(t.remarks, '') AS remarks,
          CAST(t.created_at AS STRING) AS created_at,
          t.is_anomaly,
          IFNULL(s.alarmRuleName, '') AS alarm_rule
        FROM \`${saProject}.${DATASET}.taa_state\` t
        LEFT JOIN \`${saProject}.${DATASET}.siem_alarms\` s
          ON SAFE_CAST(t.alarm_id AS INT64) = s.alarmId
        ORDER BY t.created_at DESC
        LIMIT 40`);
      if (rows.length > 0) {
        realTaaAnalyses = rows.map((r, i) => taaStateToAnalysis(r.f, i));
        usedStrategies.push(`taa_state(${rows.length})`);
      }
    } catch (e) { strategyErrors.push({ name: 'taa_state', error: String(e).slice(0, 200) }); }

    // Strategy 3: CRA state — real containment/response actions
    try {
      const rows = await runQuery(token, saProject, `
        SELECT
          c.cra_action_id, c.alarm_id, c.action_type,
          IFNULL(c.remarks, '') AS remarks,
          IFNULL(c.reasoning, '') AS reasoning,
          c.success, CAST(c.created_at AS STRING) AS created_at,
          c.runtime,
          IFNULL(s.alarmRuleName, '') AS alarm_rule,
          IFNULL(s.entityName, '') AS entity_name
        FROM \`${saProject}.${DATASET}.cra_state\` c
        LEFT JOIN \`${saProject}.${DATASET}.siem_alarms\` s
          ON SAFE_CAST(c.alarm_id AS INT64) = s.alarmId
        ORDER BY c.created_at DESC
        LIMIT 30`);
      if (rows.length > 0) {
        realCraActions = rows.map((r, i) => craStateToAction(r.f, i));
        usedStrategies.push(`cra_state(${rows.length})`);
      }
    } catch (e) { strategyErrors.push({ name: 'cra_state', error: String(e).slice(0, 200) }); }

    // Strategy 4 (fallback): SIEM events if ada_state yielded nothing
    if (allAlerts.length === 0) {
      try {
        const rows = await runQuery(token, saProject, `
          WITH recent AS (
            SELECT alarmId, events, ingestion_time
            FROM \`${saProject}.${DATASET}.siem_events\`
            ORDER BY ingestion_time DESC LIMIT 80
          )
          SELECT s.alarmId,
            IFNULL(JSON_VALUE(e, '$.commonEventName'), '') AS eventName,
            IFNULL(JSON_VALUE(e, '$.classificationName'), '') AS classification,
            IFNULL(JSON_VALUE(e, '$.classificationTypeName'), '') AS classType,
            IFNULL(JSON_VALUE(e, '$.entityName'), '') AS entityName,
            IFNULL(JSON_VALUE(e, '$.impactedHostName'), '') AS impactedHost,
            IFNULL(JSON_VALUE(e, '$.originHostName'), '') AS originHost,
            IFNULL(JSON_VALUE(e, '$.logDate'), '') AS logDate,
            IFNULL(JSON_VALUE(e, '$.logMessage'), '') AS logMessage,
            IFNULL(JSON_VALUE(e, '$.priority'), '0') AS priority,
            IFNULL(JSON_VALUE(e, '$.severity'), '') AS severity,
            IFNULL(JSON_VALUE(e, '$.serviceName'), '') AS serviceName,
            IFNULL(JSON_VALUE(e, '$.directionName'), '') AS direction,
            IFNULL(JSON_VALUE(e, '$.impactedIP'), '') AS impactedIP,
            IFNULL(JSON_VALUE(e, '$.originIP'), '') AS originIP,
            IFNULL(JSON_VALUE(e, '$.impactedPort'), '-1') AS impactedPort,
            IFNULL(JSON_VALUE(e, '$.originPort'), '-1') AS originPort,
            IFNULL(JSON_VALUE(e, '$.protocolName'), '') AS protocol,
            CAST(s.ingestion_time AS STRING) AS ingestionTime
          FROM recent s, UNNEST(JSON_QUERY_ARRAY(s.events)) AS e
          ORDER BY SAFE_CAST(JSON_VALUE(e, '$.priority') AS INT64) DESC LIMIT 60`);
        if (rows.length > 0) {
          allAlerts.push(...rows.map((r, i) => siemRowToAlert(r.f, i)));
          usedStrategies.push(`siem_events(${rows.length})`);
        }
      } catch (e) { strategyErrors.push({ name: 'siem_events', error: String(e).slice(0, 200) }); }
    }

    // ── Time-rebase: shift historical timestamps to present ──────────
    // Finds the most recent event and offsets all timestamps so it maps to ~now
    const now = Date.now();
    let maxTs = 0;
    for (const a of allAlerts) {
      const t = new Date(a.timestamp).getTime();
      if (t > maxTs) maxTs = t;
    }
    for (const t of realTaaAnalyses) {
      const ts = new Date(t.timestamp).getTime();
      if (ts > maxTs) maxTs = ts;
    }
    for (const c of realCraActions) {
      const ts = new Date(c.timestamp).getTime();
      if (ts > maxTs) maxTs = ts;
    }

    // Offset = how far to shift. We put the newest event at ~5 min ago.
    const rebaseOffset = maxTs > 0 ? (now - 300_000 - maxTs) : 0;

    function rebaseTs(isoOrUnix) {
      if (!isoOrUnix || rebaseOffset === 0) return isoOrUnix;
      const t = new Date(isoOrUnix).getTime();
      if (isNaN(t)) return isoOrUnix;
      return new Date(t + rebaseOffset).toISOString();
    }

    // Apply time-rebase to all data
    for (const a of allAlerts) a.timestamp = rebaseTs(a.timestamp);
    for (const t of realTaaAnalyses) t.timestamp = rebaseTs(t.timestamp);
    for (const c of realCraActions) c.timestamp = rebaseTs(c.timestamp);

    // Sort by timestamp, newest first
    allAlerts.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime() || 0;
      const tb = new Date(b.timestamp).getTime() || 0;
      return tb - ta;
    });

    // Deduplicate by alarm_id, keep first (newest)
    const seen = new Set();
    const alerts = [];
    for (const a of allAlerts) {
      if (!seen.has(a.id)) {
        seen.add(a.id);
        alerts.push(a);
      }
    }

    const snapshot = buildSnapshot(alerts, realTaaAnalyses, realCraActions);
    snapshot.strategy = usedStrategies.join('+') || 'none';
    snapshot.rebaseOffsetH = Math.round(rebaseOffset / 3600_000);
    // Include debug info only when ?debug=1 is passed
    if (new URL(req.url).searchParams.has('debug')) {
      snapshot.strategyErrors = strategyErrors;
      snapshot.saProject = saProject;
      snapshot.saEmail = sa.client_email;
    }

    // Sanitize all string fields — strip telco provider identifiers
    const sanitized = sanitizeDeep(snapshot);

    return new Response(JSON.stringify(sanitized), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=60',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (err) {
    console.error('[gatra-data] BigQuery error:', err);
    return new Response(
      JSON.stringify({ error: String(err), source: 'api_error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } },
    );
  }
}
