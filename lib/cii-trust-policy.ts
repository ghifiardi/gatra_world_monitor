/**
 * GATRA CII-Aware Trust Policy Engine
 * =====================================
 * Maps real Country Instability Index (CII) scores — derived from ACLED
 * conflict data, regime-aware scoring, and Welford baselines — to dynamic
 * trust tiers that govern how incoming A2A agent requests are processed.
 *
 * Referenced in:
 *   - IEEE S&P Oakland 2027 paper (Section 4.2: Geopolitical Trust Adaptation)
 *   - GATRA investor deck (Slide 7: Differentiator - Real-time CII Integration)
 *
 * This is the canonical TypeScript source.  The runtime edge-function copy
 * lives at api/_cii-trust-policy.js (plain JS for Vercel Edge).
 */

// ── Trust Tiers ─────────────────────────────────────────────────

export const TrustTier = {
  STANDARD: 'STANDARD',  // CII 0-34   — normal processing
  ELEVATED: 'ELEVATED',  // CII 35-60  — heightened scrutiny
  CRITICAL: 'CRITICAL',  // CII >60    — near-rejection; allowlist required
} as const;

export type TrustTierValue = (typeof TrustTier)[keyof typeof TrustTier];

// ── CII Score Database (ACLED-derived, Feb 2026) ────────────────

export const COUNTRY_CII_OVERRIDES: Record<string, number> = {
  // Southeast Asia
  MM: 72.8,  // Myanmar — military junta, ongoing conflict
  PH: 38.2,  // Philippines — NPA insurgency, Bangsamoro
  ID: 22.1,  // Indonesia — relatively stable; home market
  TH: 31.4,  // Thailand — post-coup political tension
  KH: 44.7,  // Cambodia — autocratic consolidation
  LA: 35.9,  // Laos — political repression
  VN: 28.6,  // Vietnam — authoritarian but stable
  MY: 19.3,  // Malaysia — stable democratic transition
  SG: 8.1,   // Singapore — highly stable
  BN: 12.0,  // Brunei
  TL: 41.2,  // Timor-Leste — fragile state

  // South Asia
  BD: 48.3,  // Bangladesh — post-Sheikh Hasina instability
  PK: 61.7,  // Pakistan — critical; PTI conflict, IMF fragility
  AF: 89.4,  // Afghanistan — Taliban; highest CII in dataset
  IN: 29.1,  // India — stable nationally

  // East Asia
  KP: 78.2,  // North Korea — regime opacity, sanctions
  CN: 24.3,  // China — stable authoritarian
  TW: 15.6,  // Taiwan — geopolitical risk offset by institutional strength

  // Middle East
  YE: 91.2,  // Yemen — ongoing civil war
  SY: 88.1,  // Syria — reconstruction phase but fragile
  IQ: 52.4,  // Iraq — elevated

  // Africa (key cases)
  SO: 83.6,  // Somalia
  SS: 79.3,  // South Sudan
  SD: 71.8,  // Sudan — active coup aftermath

  // Stable democracies
  US: 12.4,  JP: 5.2,  KR: 11.8,  AU: 6.1,  GB: 8.7,
  DE: 7.3,   FR: 9.1,  NL: 5.8,   CA: 7.0,  NZ: 4.9,
};

// ── Types ───────────────────────────────────────────────────────

export interface TrustPolicy {
  tier: TrustTierValue;
  ciiScore: number;
  country: string;
  requireJWS: boolean;
  requireAdminAllowlist: boolean;
  deepInjectionScan: boolean;
  maxRequestsPerHour: number;
  errorCode: number | null;
  errorMessage: string | null;
  auditLevel: 'standard' | 'enhanced' | 'forensic';
}

export interface CountryResolution {
  countryCode: string;
  source: 'vercel-geo' | 'cf-geo' | 'tld' | 'self-reported' | 'unknown';
}

export interface CiiPolicyDecision {
  allowed: boolean;
  policy: TrustPolicy;
  countryCode: string;
  countrySource: string;
  isInAllowlist: boolean;
  enforcedAt: string;
}

export interface CiiRejectionResponse {
  jsonrpc: '2.0';
  id: string | number;
  error: {
    code: number;
    message: string;
    data: {
      ciiScore: number;
      tier: TrustTierValue;
      country: string;
      countrySource: string;
      policy: string;
      remediation: string;
      referenceDoc: string;
    };
  };
}

export interface PolicyRequest {
  headers: Record<string, string>;
  agentCardUrl?: string;
}

// ── CII Score → Trust Tier ──────────────────────────────────────

export function ciiScoreToTier(score: number): TrustTierValue {
  if (score > 60) return TrustTier.CRITICAL;
  if (score > 34) return TrustTier.ELEVATED;
  return TrustTier.STANDARD;
}

// ── Trust Policy Builder ────────────────────────────────────────

export function buildTrustPolicy(country: string, ciiScore: number): TrustPolicy {
  const tier = ciiScoreToTier(ciiScore);
  const base = { tier, ciiScore, country };

  switch (tier) {
    case TrustTier.STANDARD:
      return {
        ...base,
        requireJWS: false,
        requireAdminAllowlist: false,
        deepInjectionScan: false,
        maxRequestsPerHour: 100,
        errorCode: null,
        errorMessage: null,
        auditLevel: 'standard',
      };

    case TrustTier.ELEVATED:
      return {
        ...base,
        requireJWS: true,
        requireAdminAllowlist: false,
        deepInjectionScan: true,
        maxRequestsPerHour: 30,
        errorCode: null,
        errorMessage: null,
        auditLevel: 'enhanced',
      };

    case TrustTier.CRITICAL:
      return {
        ...base,
        requireJWS: true,
        requireAdminAllowlist: true,
        deepInjectionScan: true,
        maxRequestsPerHour: 10,
        errorCode: -32050,
        errorMessage:
          `Agent request rejected: origin country "${country}" has critical instability ` +
          `(CII ${ciiScore.toFixed(1)}). Requests from this region require explicit ` +
          `GATRA administrator approval. Reference: GATRA-POL-CII-CRITICAL`,
        auditLevel: 'forensic',
      };
  }
}

// ── TLD → Country Mapping ───────────────────────────────────────

const TLD_TO_COUNTRY: Record<string, string> = {
  '.mm': 'MM', '.ph': 'PH', '.id': 'ID', '.th': 'TH', '.kh': 'KH',
  '.la': 'LA', '.vn': 'VN', '.my': 'MY', '.sg': 'SG', '.bn': 'BN',
  '.tl': 'TL', '.bd': 'BD', '.pk': 'PK', '.af': 'AF', '.in': 'IN',
  '.np': 'NP', '.lk': 'LK', '.kp': 'KP', '.cn': 'CN', '.tw': 'TW',
  '.jp': 'JP', '.kr': 'KR', '.ru': 'RU', '.ua': 'UA', '.ir': 'IR',
  '.iq': 'IQ', '.sy': 'SY', '.ye': 'YE', '.so': 'SO', '.ss': 'SS',
  '.sd': 'SD', '.ly': 'LY', '.ml': 'ML', '.cf': 'CF', '.cd': 'CD',
};

function extractTldCountry(url: string): string | null {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    for (const [tld, code] of Object.entries(TLD_TO_COUNTRY)) {
      if (hostname.endsWith(tld)) return code;
    }
  } catch { /* invalid URL */ }
  return null;
}

// ── Agent Country Resolution ────────────────────────────────────

/**
 * Resolve the calling agent's country of origin.
 * Priority: Vercel geo (most reliable) -> CF geo -> TLD -> self-reported -> unknown
 */
export function resolveAgentCountry(req: PolicyRequest): CountryResolution {
  const h = req.headers;

  // 1. Vercel edge geo header — most authoritative (unforgeable)
  const vercelCountry = h['x-vercel-ip-country'];
  if (vercelCountry && typeof vercelCountry === 'string' && vercelCountry.length === 2) {
    return { countryCode: vercelCountry.toUpperCase(), source: 'vercel-geo' };
  }

  // 2. CloudFlare geo header
  const cfCountry = h['cf-ipcountry'];
  if (cfCountry && typeof cfCountry === 'string' && cfCountry.length === 2 && cfCountry !== 'XX') {
    return { countryCode: cfCountry.toUpperCase(), source: 'cf-geo' };
  }

  // 3. Agent card provider URL TLD
  if (req.agentCardUrl) {
    const tld = extractTldCountry(req.agentCardUrl);
    if (tld) return { countryCode: tld, source: 'tld' };
  }

  // 4. Self-reported header (lowest trust — can be spoofed)
  const selfReported = h['x-agent-country'];
  if (selfReported && typeof selfReported === 'string' && selfReported.length === 2) {
    return { countryCode: selfReported.toUpperCase(), source: 'self-reported' };
  }

  return { countryCode: 'XX', source: 'unknown' };
}

// ── CII Score Lookup ────────────────────────────────────────────

export function getCiiScore(countryCode: string): number {
  return COUNTRY_CII_OVERRIDES[countryCode.toUpperCase()] ?? 0.0;
}

// ── Main Policy Evaluation ──────────────────────────────────────

/**
 * Evaluate the CII trust policy for an incoming A2A request.
 *
 * @param req        - Request with headers and optional agentCardUrl
 * @param allowlist  - Set of approved agent IDs for CRITICAL regions
 * @param agentId    - Caller's agent ID (from auth or agent card)
 */
export function evaluateCiiTrustPolicy(
  req: PolicyRequest,
  allowlist: Set<string>,
  agentId: string,
): CiiPolicyDecision {
  const { countryCode, source } = resolveAgentCountry(req);
  const ciiScore = getCiiScore(countryCode);
  const policy = buildTrustPolicy(countryCode, ciiScore);

  const isInAllowlist = allowlist.has(agentId) || allowlist.has('*');

  let allowed = true;
  if (policy.tier === TrustTier.CRITICAL && !isInAllowlist) {
    allowed = false;
  }

  return {
    allowed,
    policy,
    countryCode,
    countrySource: source,
    isInAllowlist,
    enforcedAt: new Date().toISOString(),
  };
}

// ── JSON-RPC Rejection Response Builder ─────────────────────────

export function buildCiiRejectionResponse(
  requestId: string | number,
  decision: CiiPolicyDecision,
): CiiRejectionResponse {
  return {
    jsonrpc: '2.0',
    id: requestId,
    error: {
      code: decision.policy.errorCode ?? -32050,
      message: decision.policy.errorMessage ?? 'Request rejected by CII trust policy',
      data: {
        ciiScore: decision.policy.ciiScore,
        tier: decision.policy.tier,
        country: decision.countryCode,
        countrySource: decision.countrySource,
        policy: 'GATRA-POL-CII-CRITICAL',
        remediation: 'Contact GATRA administrator to request allowlist approval',
        referenceDoc: 'https://worldmonitor-gatra.vercel.app/.well-known/agent.json',
      },
    },
  };
}

// ── Rate Limit Tiers ────────────────────────────────────────────

export function getTierRateLimits(tier: TrustTierValue) {
  switch (tier) {
    case TrustTier.CRITICAL:
      return { maxPerMinute: 1, maxBurst: 2 };
    case TrustTier.ELEVATED:
      return { maxPerMinute: 3, maxBurst: 5 };
    case TrustTier.STANDARD:
    default:
      return { maxPerMinute: 60, maxBurst: 10 };
  }
}

// ── Runtime Score Updates ───────────────────────────────────────

export function updateCiiScore(countryCode: string, score: number) {
  COUNTRY_CII_OVERRIDES[countryCode.toUpperCase()] = score;
}
