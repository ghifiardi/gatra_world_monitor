/**
 * A2A Agent Card Validator — Vercel Edge Function
 *
 * Fetches an A2A Agent Card from a given URL and validates it against
 * the A2A protocol v0.3 specification. Returns a structured validation
 * report with pass/fail/warn checks grouped by category.
 *
 * Usage:
 *   GET  /api/a2a/validate-card?url=https://example.com/.well-known/agent.json
 *   POST /api/a2a/validate-card  { "url": "https://..." }
 */
export const config = { runtime: 'edge' };

// ── Validation check structure ────────────────────────────────────

/** @typedef {'pass'|'fail'|'warn'|'info'} CheckSeverity */
/** @typedef {{ id: string, category: string, severity: CheckSeverity, message: string, detail?: string }} ValidationCheck */

// ── A2A spec constants ────────────────────────────────────────────

const REQUIRED_TOP_LEVEL = ['name', 'description', 'version', 'url', 'supportedInterfaces', 'capabilities', 'defaultInputModes', 'defaultOutputModes', 'skills'];
const OPTIONAL_TOP_LEVEL = ['provider', 'securitySchemes', 'securityRequirements', 'documentationUrl', 'iconUrl', 'signatures'];
const VALID_PROTOCOL_BINDINGS = ['JSONRPC', 'GRPC', 'HTTP+JSON'];
const VALID_INPUT_OUTPUT_MODES = ['text/plain', 'application/json', 'image/png', 'image/jpeg', 'audio/wav', 'audio/mp3', 'video/mp4', 'application/pdf', 'text/html', 'text/markdown'];
const REQUIRED_INTERFACE_FIELDS = ['url', 'protocolBinding', 'protocolVersion'];
const REQUIRED_SKILL_FIELDS = ['id', 'name', 'description', 'tags'];
const CAPABILITY_FIELDS = ['streaming', 'pushNotifications', 'stateTransitionHistory'];

// ── Main handler ──────────────────────────────────────────────────

export default async function handler(req) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(),
    });
  }

  // Extract URL from query string (GET) or body (POST)
  let cardUrl;
  if (req.method === 'POST') {
    try {
      const body = await req.json();
      cardUrl = body.url;
    } catch {
      return errorResponse(400, 'Invalid JSON body. Expected { "url": "..." }');
    }
  } else {
    const params = new URL(req.url).searchParams;
    cardUrl = params.get('url');
  }

  if (!cardUrl) {
    return errorResponse(400, 'Missing required parameter: url');
  }

  // Validate URL format
  let parsedUrl;
  try {
    parsedUrl = new URL(cardUrl);
  } catch {
    return errorResponse(400, `Invalid URL: ${cardUrl}`);
  }

  if (!parsedUrl.protocol.startsWith('http')) {
    return errorResponse(400, 'URL must use http or https protocol');
  }

  // ── Fetch the agent card ──────────────────────────────────────

  const checks = [];
  let card;
  let fetchMs;
  let httpStatus;
  let contentType;

  try {
    const start = Date.now();
    const res = await fetch(cardUrl, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'GATRA-A2A-Validator/1.0' },
      signal: AbortSignal.timeout(10000),
    });
    fetchMs = Date.now() - start;
    httpStatus = res.status;
    contentType = res.headers.get('content-type') || '';

    if (!res.ok) {
      checks.push(check('fetch-status', 'fetch', 'fail', `HTTP ${res.status} — agent card not reachable`, `URL: ${cardUrl}`));
      return validationResponse(cardUrl, null, checks, fetchMs, httpStatus);
    }

    checks.push(check('fetch-status', 'fetch', 'pass', `HTTP ${res.status} OK`, `Fetched in ${fetchMs}ms`));

    // Check content type
    if (contentType.includes('application/json')) {
      checks.push(check('content-type', 'fetch', 'pass', 'Content-Type is application/json'));
    } else {
      checks.push(check('content-type', 'fetch', 'warn', `Content-Type is "${contentType}" — expected application/json`));
    }

    // Check CORS
    const acao = res.headers.get('access-control-allow-origin');
    if (acao === '*' || acao) {
      checks.push(check('cors', 'fetch', 'pass', `CORS header present: ${acao}`));
    } else {
      checks.push(check('cors', 'fetch', 'warn', 'No Access-Control-Allow-Origin header — cross-origin discovery may fail'));
    }

    // Check response time
    if (fetchMs < 1000) {
      checks.push(check('latency', 'fetch', 'pass', `Response time: ${fetchMs}ms`));
    } else if (fetchMs < 3000) {
      checks.push(check('latency', 'fetch', 'warn', `Slow response: ${fetchMs}ms — may affect agent discovery`));
    } else {
      checks.push(check('latency', 'fetch', 'warn', `Very slow response: ${fetchMs}ms — agents may time out`));
    }

    // Parse JSON
    const text = await res.text();
    try {
      card = JSON.parse(text);
    } catch (e) {
      checks.push(check('json-parse', 'fetch', 'fail', 'Response is not valid JSON', String(e)));
      return validationResponse(cardUrl, null, checks, fetchMs, httpStatus);
    }

    checks.push(check('json-parse', 'fetch', 'pass', 'Valid JSON parsed successfully'));

  } catch (e) {
    const msg = String(e);
    if (msg.includes('TimeoutError') || msg.includes('abort')) {
      checks.push(check('fetch-timeout', 'fetch', 'fail', 'Request timed out after 10 seconds', `URL: ${cardUrl}`));
    } else {
      checks.push(check('fetch-error', 'fetch', 'fail', `Failed to fetch agent card: ${msg.slice(0, 200)}`));
    }
    return validationResponse(cardUrl, null, checks, 0, 0);
  }

  // ── Validate structure ────────────────────────────────────────

  if (typeof card !== 'object' || card === null || Array.isArray(card)) {
    checks.push(check('root-type', 'structure', 'fail', 'Agent card must be a JSON object'));
    return validationResponse(cardUrl, card, checks, fetchMs, httpStatus);
  }

  // Required top-level fields
  for (const field of REQUIRED_TOP_LEVEL) {
    if (card[field] === undefined || card[field] === null) {
      checks.push(check(`required-${field}`, 'structure', 'fail', `Missing required field: "${field}"`));
    } else {
      checks.push(check(`required-${field}`, 'structure', 'pass', `Required field "${field}" present`));
    }
  }

  // Optional fields info
  for (const field of OPTIONAL_TOP_LEVEL) {
    if (card[field] !== undefined) {
      checks.push(check(`optional-${field}`, 'structure', 'info', `Optional field "${field}" present`));
    }
  }

  // Unexpected fields
  const knownFields = new Set([...REQUIRED_TOP_LEVEL, ...OPTIONAL_TOP_LEVEL]);
  for (const key of Object.keys(card)) {
    if (!knownFields.has(key)) {
      checks.push(check(`unknown-field-${key}`, 'structure', 'warn', `Unknown top-level field: "${key}"`));
    }
  }

  // ── Validate field types & values ─────────────────────────────

  // name
  if (typeof card.name === 'string') {
    if (card.name.length === 0) {
      checks.push(check('name-empty', 'fields', 'fail', 'Field "name" must not be empty'));
    } else if (card.name.length > 100) {
      checks.push(check('name-length', 'fields', 'warn', `Field "name" is ${card.name.length} chars — consider keeping under 100`));
    } else {
      checks.push(check('name-valid', 'fields', 'pass', `Name: "${card.name}"`));
    }
  } else if (card.name !== undefined) {
    checks.push(check('name-type', 'fields', 'fail', `Field "name" must be a string, got ${typeof card.name}`));
  }

  // description
  if (typeof card.description === 'string') {
    if (card.description.length === 0) {
      checks.push(check('desc-empty', 'fields', 'fail', 'Field "description" must not be empty'));
    } else if (card.description.length < 20) {
      checks.push(check('desc-short', 'fields', 'warn', 'Description is very short — consider adding more detail'));
    } else {
      checks.push(check('desc-valid', 'fields', 'pass', `Description: ${card.description.length} chars`));
    }
  } else if (card.description !== undefined) {
    checks.push(check('desc-type', 'fields', 'fail', `Field "description" must be a string, got ${typeof card.description}`));
  }

  // version
  if (typeof card.version === 'string') {
    if (/^\d+\.\d+(\.\d+)?(-[\w.]+)?$/.test(card.version)) {
      checks.push(check('version-semver', 'fields', 'pass', `Version: ${card.version} (valid semver)`));
    } else {
      checks.push(check('version-format', 'fields', 'warn', `Version "${card.version}" is not semver — consider using X.Y.Z format`));
    }
  } else if (card.version !== undefined) {
    checks.push(check('version-type', 'fields', 'fail', `Field "version" must be a string, got ${typeof card.version}`));
  }

  // url
  if (typeof card.url === 'string') {
    try {
      new URL(card.url);
      checks.push(check('url-valid', 'fields', 'pass', `URL: ${card.url}`));
    } catch {
      checks.push(check('url-invalid', 'fields', 'fail', `Field "url" is not a valid URL: "${card.url}"`));
    }
  } else if (card.url !== undefined) {
    checks.push(check('url-type', 'fields', 'fail', `Field "url" must be a string, got ${typeof card.url}`));
  }

  // ── Validate supportedInterfaces ──────────────────────────────

  if (Array.isArray(card.supportedInterfaces)) {
    if (card.supportedInterfaces.length === 0) {
      checks.push(check('interfaces-empty', 'interfaces', 'fail', 'supportedInterfaces must have at least one entry'));
    }

    card.supportedInterfaces.forEach((iface, i) => {
      const prefix = `interface[${i}]`;

      if (typeof iface !== 'object' || iface === null) {
        checks.push(check(`${prefix}-type`, 'interfaces', 'fail', `${prefix}: must be an object`));
        return;
      }

      // Required interface fields
      for (const field of REQUIRED_INTERFACE_FIELDS) {
        if (!iface[field]) {
          checks.push(check(`${prefix}-${field}`, 'interfaces', 'fail', `${prefix}: missing required field "${field}"`));
        }
      }

      // Validate URL
      if (typeof iface.url === 'string') {
        try {
          new URL(iface.url);
          checks.push(check(`${prefix}-url`, 'interfaces', 'pass', `${prefix}: URL ${iface.url}`));
        } catch {
          checks.push(check(`${prefix}-url-invalid`, 'interfaces', 'fail', `${prefix}: invalid URL "${iface.url}"`));
        }
      }

      // Validate protocolBinding
      if (iface.protocolBinding) {
        if (VALID_PROTOCOL_BINDINGS.includes(iface.protocolBinding)) {
          checks.push(check(`${prefix}-binding`, 'interfaces', 'pass', `${prefix}: protocol ${iface.protocolBinding}`));
        } else {
          checks.push(check(`${prefix}-binding-unknown`, 'interfaces', 'warn', `${prefix}: unknown protocolBinding "${iface.protocolBinding}" — expected one of: ${VALID_PROTOCOL_BINDINGS.join(', ')}`));
        }
      }

      // Validate protocolVersion
      if (iface.protocolVersion) {
        checks.push(check(`${prefix}-version`, 'interfaces', 'pass', `${prefix}: protocol version ${iface.protocolVersion}`));
      }
    });
  } else if (card.supportedInterfaces !== undefined) {
    checks.push(check('interfaces-type', 'interfaces', 'fail', 'supportedInterfaces must be an array'));
  }

  // ── Validate capabilities ─────────────────────────────────────

  if (typeof card.capabilities === 'object' && card.capabilities !== null && !Array.isArray(card.capabilities)) {
    for (const field of CAPABILITY_FIELDS) {
      if (card.capabilities[field] !== undefined) {
        if (typeof card.capabilities[field] === 'boolean') {
          checks.push(check(`cap-${field}`, 'capabilities', 'pass', `capabilities.${field}: ${card.capabilities[field]}`));
        } else {
          checks.push(check(`cap-${field}-type`, 'capabilities', 'warn', `capabilities.${field} should be boolean, got ${typeof card.capabilities[field]}`));
        }
      }
    }

    // Check for unknown capability fields
    for (const key of Object.keys(card.capabilities)) {
      if (!CAPABILITY_FIELDS.includes(key)) {
        checks.push(check(`cap-unknown-${key}`, 'capabilities', 'info', `Custom capability: "${key}"`));
      }
    }

    checks.push(check('capabilities-valid', 'capabilities', 'pass', 'Capabilities object is well-formed'));
  } else if (card.capabilities !== undefined) {
    checks.push(check('capabilities-type', 'capabilities', 'fail', 'capabilities must be a plain object'));
  }

  // ── Validate defaultInputModes / defaultOutputModes ───────────

  for (const modeField of ['defaultInputModes', 'defaultOutputModes']) {
    const modes = card[modeField];
    if (Array.isArray(modes)) {
      if (modes.length === 0) {
        checks.push(check(`${modeField}-empty`, 'modes', 'fail', `${modeField} must have at least one entry`));
      }
      for (const mode of modes) {
        if (typeof mode !== 'string') {
          checks.push(check(`${modeField}-entry-type`, 'modes', 'fail', `${modeField} entries must be strings`));
        } else if (VALID_INPUT_OUTPUT_MODES.includes(mode)) {
          checks.push(check(`${modeField}-${mode}`, 'modes', 'pass', `${modeField}: ${mode}`));
        } else {
          checks.push(check(`${modeField}-${mode}`, 'modes', 'warn', `${modeField}: "${mode}" is not a standard MIME type`));
        }
      }
    } else if (modes !== undefined) {
      checks.push(check(`${modeField}-type`, 'modes', 'fail', `${modeField} must be an array`));
    }
  }

  // ── Validate skills ───────────────────────────────────────────

  if (Array.isArray(card.skills)) {
    if (card.skills.length === 0) {
      checks.push(check('skills-empty', 'skills', 'warn', 'Skills array is empty — agent has no declared capabilities'));
    } else {
      checks.push(check('skills-count', 'skills', 'pass', `${card.skills.length} skill(s) declared`));
    }

    const skillIds = new Set();

    card.skills.forEach((skill, i) => {
      const prefix = `skill[${i}]`;

      if (typeof skill !== 'object' || skill === null) {
        checks.push(check(`${prefix}-type`, 'skills', 'fail', `${prefix}: must be an object`));
        return;
      }

      // Required skill fields
      for (const field of REQUIRED_SKILL_FIELDS) {
        if (!skill[field] && skill[field] !== '') {
          checks.push(check(`${prefix}-${field}`, 'skills', 'fail', `${prefix}: missing required field "${field}"`));
        }
      }

      // Skill ID uniqueness
      if (skill.id) {
        if (skillIds.has(skill.id)) {
          checks.push(check(`${prefix}-id-dup`, 'skills', 'fail', `${prefix}: duplicate skill ID "${skill.id}"`));
        } else {
          skillIds.add(skill.id);
        }
      }

      // Tags must be an array of strings
      if (skill.tags !== undefined) {
        if (!Array.isArray(skill.tags)) {
          checks.push(check(`${prefix}-tags-type`, 'skills', 'fail', `${prefix}: tags must be an array`));
        } else if (skill.tags.length === 0) {
          checks.push(check(`${prefix}-tags-empty`, 'skills', 'warn', `${prefix}: tags array is empty`));
        } else {
          const nonStrings = skill.tags.filter(t => typeof t !== 'string');
          if (nonStrings.length > 0) {
            checks.push(check(`${prefix}-tags-strings`, 'skills', 'fail', `${prefix}: all tags must be strings`));
          }
        }
      }

      // Examples (optional but recommended)
      if (skill.examples) {
        if (!Array.isArray(skill.examples)) {
          checks.push(check(`${prefix}-examples-type`, 'skills', 'warn', `${prefix}: examples should be an array`));
        } else {
          checks.push(check(`${prefix}-examples`, 'skills', 'info', `${prefix}: ${skill.examples.length} example(s)`));
        }
      }

      // Description length
      if (typeof skill.description === 'string' && skill.description.length < 10) {
        checks.push(check(`${prefix}-desc-short`, 'skills', 'warn', `${prefix}: description is very short`));
      }
    });
  } else if (card.skills !== undefined) {
    checks.push(check('skills-type', 'skills', 'fail', 'skills must be an array'));
  }

  // ── Validate provider ─────────────────────────────────────────

  if (card.provider) {
    if (typeof card.provider !== 'object' || card.provider === null) {
      checks.push(check('provider-type', 'provider', 'fail', 'provider must be an object'));
    } else {
      if (card.provider.organization) {
        checks.push(check('provider-org', 'provider', 'pass', `Provider: ${card.provider.organization}`));
      } else {
        checks.push(check('provider-org-missing', 'provider', 'warn', 'provider.organization is recommended'));
      }
      if (card.provider.url) {
        try {
          new URL(card.provider.url);
          checks.push(check('provider-url', 'provider', 'pass', `Provider URL: ${card.provider.url}`));
        } catch {
          checks.push(check('provider-url-invalid', 'provider', 'fail', `provider.url is not a valid URL`));
        }
      }
    }
  }

  // ── Validate securitySchemes ──────────────────────────────────

  if (card.securitySchemes) {
    if (typeof card.securitySchemes !== 'object' || Array.isArray(card.securitySchemes)) {
      checks.push(check('security-type', 'security', 'fail', 'securitySchemes must be a plain object'));
    } else {
      const schemeCount = Object.keys(card.securitySchemes).length;
      checks.push(check('security-count', 'security', 'pass', `${schemeCount} security scheme(s) defined`));

      for (const [name, scheme] of Object.entries(card.securitySchemes)) {
        if (typeof scheme !== 'object' || scheme === null) {
          checks.push(check(`security-${name}-type`, 'security', 'fail', `Security scheme "${name}" must be an object`));
          continue;
        }
        if (!scheme.type) {
          checks.push(check(`security-${name}-no-type`, 'security', 'fail', `Security scheme "${name}" missing "type" field`));
        } else {
          const validTypes = ['apiKey', 'http', 'oauth2', 'openIdConnect'];
          if (validTypes.includes(scheme.type)) {
            checks.push(check(`security-${name}-valid`, 'security', 'pass', `Scheme "${name}": type=${scheme.type}`));
          } else {
            checks.push(check(`security-${name}-unknown`, 'security', 'warn', `Scheme "${name}": unknown type "${scheme.type}"`));
          }
        }
      }
    }

    // Validate securityRequirements reference valid schemes
    if (Array.isArray(card.securityRequirements)) {
      for (const req of card.securityRequirements) {
        if (typeof req === 'object' && req !== null) {
          for (const schemeName of Object.keys(req)) {
            if (!card.securitySchemes[schemeName]) {
              checks.push(check(`secreq-${schemeName}`, 'security', 'fail', `securityRequirements references undefined scheme "${schemeName}"`));
            } else {
              checks.push(check(`secreq-${schemeName}`, 'security', 'pass', `Security requirement "${schemeName}" references valid scheme`));
            }
          }
        }
      }
    }
  } else {
    checks.push(check('security-none', 'security', 'warn', 'No securitySchemes defined — agent accepts unauthenticated requests'));
  }

  // ── Well-known URL check ──────────────────────────────────────

  if (parsedUrl.pathname === '/.well-known/agent.json') {
    checks.push(check('well-known', 'best-practices', 'pass', 'Served at standard /.well-known/agent.json path'));
  } else {
    checks.push(check('well-known', 'best-practices', 'warn', `Not served at /.well-known/agent.json — agents may not discover this card automatically`));
  }

  // ── URL consistency check ─────────────────────────────────────

  if (card.url && card.supportedInterfaces?.[0]?.url) {
    try {
      const cardOrigin = new URL(card.url).origin;
      const ifaceOrigin = new URL(card.supportedInterfaces[0].url).origin;
      if (cardOrigin === ifaceOrigin) {
        checks.push(check('url-consistency', 'best-practices', 'pass', 'Agent URL and interface URL share the same origin'));
      } else {
        checks.push(check('url-consistency', 'best-practices', 'info', `Agent URL (${cardOrigin}) differs from interface URL (${ifaceOrigin})`));
      }
    } catch { /* URL parse errors already caught above */ }
  }

  return validationResponse(cardUrl, card, checks, fetchMs, httpStatus);
}

// ── Helpers ───────────────────────────────────────────────────────

function check(id, category, severity, message, detail) {
  const c = { id, category, severity, message };
  if (detail) c.detail = detail;
  return c;
}

function validationResponse(url, card, checks, fetchMs, httpStatus) {
  const fails = checks.filter(c => c.severity === 'fail').length;
  const warns = checks.filter(c => c.severity === 'warn').length;
  const passes = checks.filter(c => c.severity === 'pass').length;
  const infos = checks.filter(c => c.severity === 'info').length;

  const verdict = fails > 0 ? 'invalid' : warns > 0 ? 'valid_with_warnings' : 'valid';

  const result = {
    url,
    timestamp: new Date().toISOString(),
    verdict,
    summary: {
      total: checks.length,
      pass: passes,
      fail: fails,
      warn: warns,
      info: infos,
    },
    fetchMs: fetchMs || 0,
    httpStatus: httpStatus || 0,
    card: card ? {
      name: card.name,
      version: card.version,
      skillCount: Array.isArray(card.skills) ? card.skills.length : 0,
      provider: card.provider?.organization || null,
    } : null,
    checks,
  };

  return new Response(JSON.stringify(result, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=30',
      ...corsHeaders(),
    },
  });
}

function errorResponse(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}
