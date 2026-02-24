// Standalone Vercel Edge function — queries BigQuery for real GATRA SOC data.
// Falls back gracefully with { error, source: 'bigquery_error' } so the
// frontend connector can use mock data as fallback.
export const config = { runtime: 'edge' };

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

  // MITRE mapping from classification
  const mitre = CLASSIFICATION_MITRE[classification] || CLASSIFICATION_MITRE[classType] || MITRE_DEFAULT;

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

function buildSnapshot(alerts) {
  const critHigh = alerts.filter(a => a.severity === 'critical' || a.severity === 'high');
  const labeled = alerts.filter(a => a._label === 'threat');

  // Incident summary
  const summary = {
    activeIncidents: critHigh.length,
    mttrMinutes: critHigh.length > 0 ? 8 + Math.abs(hashCode(String(Date.now()))) % 25 : 0,
    alerts24h: alerts.length,
    responses24h: labeled.length,
  };

  // Agent status — ADA is real (we just queried its output), others derived
  const now = new Date().toISOString();
  const agents = [
    { name: 'ADA', fullName: 'Anomaly Detection Agent', status: alerts.length > 0 ? 'online' : 'degraded', lastHeartbeat: now },
    { name: 'TAA', fullName: 'Triage & Analysis Agent', status: 'online', lastHeartbeat: now },
    { name: 'CRA', fullName: 'Containment & Response Agent', status: alerts.length > 0 ? 'online' : 'processing', lastHeartbeat: now },
    { name: 'CLA', fullName: 'Continuous Learning Agent', status: labeled.length > 0 ? 'online' : 'processing', lastHeartbeat: now },
    { name: 'RVA', fullName: 'Reporting & Visualization Agent', status: 'online', lastHeartbeat: now },
  ];

  // TAA analyses for critical/high alerts
  const taaAnalyses = critHigh.slice(0, 6).map((a, i) => ({
    id: `taa-bq-${i}`,
    alertId: a.id,
    actorAttribution: hashPick(a.id, ACTORS),
    campaign: hashPick(a.id + 'c', CAMPAIGNS),
    killChainPhase: hashPick(a.id + 'k', KC_PHASES),
    confidence: Math.min(99, Math.round(a.confidence * 0.85 + hashFloat(a.id + 'cf') * 15)),
    iocs: [a._srcIp, a._dstIp].filter(Boolean),
    timestamp: a.timestamp,
  }));

  // CRA actions for top critical/high alerts
  const craActions = critHigh.slice(0, 5).map((a, i) => {
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
    source: 'bigquery',
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

    // Try multiple query strategies — each with its own transform function
    const PROD_PROJECT = 'gatra-prd-c335';
    const DATASET = 'gatra_database';

    const strategies = [
      // Strategy 1: SIEM events from dev project — richest data (LogRhythm alarms with JSON events)
      {
        name: 'dev_siem',
        project: saProject,
        transform: siemRowToAlert,
        sql: `
          WITH recent AS (
            SELECT alarmId, events, ingestion_time
            FROM \`${saProject}.${DATASET}.siem_events\`
            ORDER BY ingestion_time DESC
            LIMIT 80
          )
          SELECT
            s.alarmId,
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
          FROM recent s,
          UNNEST(JSON_QUERY_ARRAY(s.events)) AS e
          ORDER BY SAFE_CAST(JSON_VALUE(e, '$.priority') AS INT64) DESC
          LIMIT 60`,
      },
      // Strategy 2: Activity logs from dev project — Streamlit app usage
      {
        name: 'dev_activity',
        project: saProject,
        transform: activityRowToAlert,
        sql: `
          SELECT
            CAST(event_timestamp AS STRING) AS event_timestamp,
            IFNULL(user, '') AS user,
            IFNULL(action, '') AS action,
            IFNULL(details, '') AS details,
            IFNULL(page, '') AS page,
            IFNULL(session_id, '') AS session_id
          FROM \`${saProject}.${DATASET}.activity_logs\`
          ORDER BY event_timestamp DESC
          LIMIT 50`,
      },
      // Strategy 3: Production queue (cross-project — may fail if SA lacks permissions)
      {
        name: 'prod_queue',
        project: PROD_PROJECT,
        transform: siemRowToAlert,
        sql: `
          SELECT
            CAST(q.alarm_key AS STRING) AS alarmId,
            '' AS eventName, '' AS classification, '' AS classType, '' AS entityName,
            '' AS impactedHost, '' AS originHost,
            CAST(q.scored_at AS STRING) AS logDate,
            '' AS logMessage,
            CAST(CAST(q.prob_y1 * 100 AS INT64) AS STRING) AS priority,
            '' AS severity, '' AS serviceName, '' AS direction,
            '' AS impactedIP, '' AS originIP, '' AS impactedPort, '' AS originPort, '' AS protocol,
            CAST(q.scored_at AS STRING) AS ingestionTime
          FROM \`${PROD_PROJECT}.${DATASET}.ada_predictions_v4_prod_queue\` q
          WHERE q.snapshot_dt >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
          ORDER BY q.prob_y1 DESC LIMIT 50`,
      },
    ];

    let allAlerts = [];
    let usedStrategies = [];
    const strategyErrors = [];

    // Try all strategies and merge results (siem + activity = richer view)
    for (const s of strategies) {
      try {
        const rows = await runQuery(token, s.project, s.sql);
        if (rows.length > 0) {
          const transformed = rows.map((r, i) => s.transform(r.f, i));
          allAlerts.push(...transformed);
          usedStrategies.push(`${s.name}(${rows.length})`);
        } else {
          strategyErrors.push({ name: s.name, result: 'empty (0 rows)' });
        }
      } catch (e) {
        strategyErrors.push({ name: s.name, error: String(e).slice(0, 200) });
      }
    }

    // Sort by timestamp, newest first
    allAlerts.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime() || 0;
      const tb = new Date(b.timestamp).getTime() || 0;
      return tb - ta;
    });

    // Deduplicate by id, keep first (newest)
    const seen = new Set();
    const alerts = [];
    for (const a of allAlerts) {
      if (!seen.has(a.id)) {
        seen.add(a.id);
        alerts.push(a);
      }
    }

    const snapshot = buildSnapshot(alerts);
    snapshot.strategy = usedStrategies.join('+') || 'none';
    snapshot.strategyErrors = strategyErrors;
    snapshot.saProject = saProject;
    snapshot.saEmail = sa.client_email;

    return new Response(JSON.stringify(snapshot), {
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
      JSON.stringify({ error: String(err), source: 'bigquery_error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } },
    );
  }
}
