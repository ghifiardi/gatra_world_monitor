/**
 * GATRA CII Trust Policy — Test Suite
 * =====================================
 * Run: npx ts-node tests/cii-trust-policy.test.ts
 *
 * These tests validate the core CII-aware trust policy logic.
 * Results feed directly into Table III of the IEEE S&P Oakland 2027 paper:
 * "Empirical Validation of CII-Driven Trust Tier Classification"
 */

import {
  ciiScoreToTier,
  buildTrustPolicy,
  evaluateCiiTrustPolicy,
  buildCiiRejectionResponse,
  TrustTier,
  COUNTRY_CII_OVERRIDES,
  getCiiScore,
  resolveAgentCountry,
} from '../lib/cii-trust-policy';

// ─── Minimal test runner ──────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`  ✅  ${name}`);
    passed++;
  } catch (e: any) {
    console.log(`  ❌  ${name}`);
    console.log(`      ${e.message}`);
    failed++;
  }
}

function expect(actual: unknown) {
  return {
    toBe: (expected: unknown) => {
      if (actual !== expected) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
      }
    },
    toBeGreaterThan: (n: number) => {
      if ((actual as number) <= n) throw new Error(`Expected ${actual} > ${n}`);
    },
    toBeLessThan: (n: number) => {
      if ((actual as number) >= n) throw new Error(`Expected ${actual} < ${n}`);
    },
    toBeTruthy: () => {
      if (!actual) throw new Error(`Expected truthy, got ${actual}`);
    },
    toBeFalsy: () => {
      if (actual) throw new Error(`Expected falsy, got ${actual}`);
    },
    toContain: (str: string) => {
      if (!(actual as string).includes(str)) {
        throw new Error(`Expected "${actual}" to contain "${str}"`);
      }
    },
  };
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

console.log('\n📋 GATRA CII Trust Policy — Test Suite');
console.log('═══════════════════════════════════════════════\n');

// Section 1: Tier classification
console.log('1. CII Score → Trust Tier Mapping');

test('CII 0 maps to STANDARD', () =>
  expect(ciiScoreToTier(0)).toBe(TrustTier.STANDARD));

test('CII 34.0 maps to STANDARD (boundary)', () =>
  expect(ciiScoreToTier(34.0)).toBe(TrustTier.STANDARD));

test('CII 34.9 maps to ELEVATED (>34 triggers elevation)', () =>
  expect(ciiScoreToTier(34.9)).toBe(TrustTier.ELEVATED));

test('CII 35.0 maps to ELEVATED', () =>
  expect(ciiScoreToTier(35.0)).toBe(TrustTier.ELEVATED));

test('CII 60.0 maps to ELEVATED', () =>
  expect(ciiScoreToTier(60.0)).toBe(TrustTier.ELEVATED));

test('CII 60.1 maps to CRITICAL', () =>
  expect(ciiScoreToTier(60.1)).toBe(TrustTier.CRITICAL));

test('Myanmar CII 72.8 maps to CRITICAL', () =>
  expect(ciiScoreToTier(72.8)).toBe(TrustTier.CRITICAL));

test('Afghanistan CII 89.4 maps to CRITICAL', () =>
  expect(ciiScoreToTier(89.4)).toBe(TrustTier.CRITICAL));

test('Singapore CII 8.1 maps to STANDARD', () =>
  expect(ciiScoreToTier(8.1)).toBe(TrustTier.STANDARD));

// Section 2: Policy properties per tier
console.log('\n2. Trust Policy Properties');

test('STANDARD policy: no JWS required', () => {
  const policy = buildTrustPolicy('SG', 8.1);
  expect(policy.requireJWS).toBeFalsy();
});

test('STANDARD policy: 100/hr rate limit', () => {
  const policy = buildTrustPolicy('ID', 22.1);
  expect(policy.maxRequestsPerHour).toBe(100);
});

test('ELEVATED policy: JWS required', () => {
  const policy = buildTrustPolicy('PH', 38.2);
  expect(policy.requireJWS).toBeTruthy();
});

test('ELEVATED policy: deep scan enabled', () => {
  const policy = buildTrustPolicy('KH', 44.7);
  expect(policy.deepInjectionScan).toBeTruthy();
});

test('ELEVATED policy: 30/hr rate limit', () => {
  const policy = buildTrustPolicy('LA', 35.9);
  expect(policy.maxRequestsPerHour).toBe(30);
});

test('CRITICAL policy: allowlist required', () => {
  const policy = buildTrustPolicy('MM', 72.8);
  expect(policy.requireAdminAllowlist).toBeTruthy();
});

test('CRITICAL policy: 10/hr rate limit', () => {
  const policy = buildTrustPolicy('PK', 61.7);
  expect(policy.maxRequestsPerHour).toBe(10);
});

test('CRITICAL policy: error code -32050', () => {
  const policy = buildTrustPolicy('MM', 72.8);
  expect(policy.errorCode).toBe(-32050);
});

test('CRITICAL policy: error message mentions Myanmar', () => {
  const policy = buildTrustPolicy('MM', 72.8);
  expect(policy.errorMessage!).toContain('MM');
});

test('CRITICAL policy: forensic audit level', () => {
  const policy = buildTrustPolicy('AF', 89.4);
  expect(policy.auditLevel).toBe('forensic');
});

// Section 3: Country CII scores
console.log('\n3. Country CII Score Lookup');

test('Myanmar score is 72.8', () =>
  expect(getCiiScore('MM')).toBe(72.8));

test('Myanmar lowercase works', () =>
  expect(getCiiScore('mm')).toBe(72.8));

test('Singapore score is 8.1', () =>
  expect(getCiiScore('SG')).toBe(8.1));

test('Unknown country XX returns 0', () =>
  expect(getCiiScore('XX')).toBe(0.0));

test('Pakistan score is CRITICAL tier', () =>
  expect(ciiScoreToTier(getCiiScore('PK'))).toBe(TrustTier.CRITICAL));

test('Indonesia score is STANDARD tier (our home market)', () =>
  expect(ciiScoreToTier(getCiiScore('ID'))).toBe(TrustTier.STANDARD));

// Section 4: Policy evaluation with allowlist
console.log('\n4. Policy Decision Engine');

const emptyAllowlist = new Set<string>();
const myanmarAllowlist = new Set<string>(['agent:ioh-myanmar-liaison']);

test('Agent from Myanmar rejected without allowlist', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'MM' } },
    emptyAllowlist,
    'agent:unknown',
  );
  expect(decision.allowed).toBeFalsy();
});

test('Agent from Myanmar allowed with explicit allowlist', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'MM' } },
    myanmarAllowlist,
    'agent:ioh-myanmar-liaison',
  );
  expect(decision.allowed).toBeTruthy();
});

test('Agent from Singapore always allowed', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'SG' } },
    emptyAllowlist,
    'agent:sentinel-sg',
  );
  expect(decision.allowed).toBeTruthy();
});

test('Agent from Philippines gets ELEVATED policy', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'PH' } },
    emptyAllowlist,
    'agent:qualys-ph',
  );
  expect(decision.policy.tier).toBe(TrustTier.ELEVATED);
  expect(decision.allowed).toBeTruthy(); // ELEVATED is allowed, just scrutinised
});

test('Unknown country treated as STANDARD (fail-open for discovery)', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: {} }, // no geo headers
    emptyAllowlist,
    'agent:anonymous',
  );
  expect(decision.policy.tier).toBe(TrustTier.STANDARD);
  expect(decision.countryCode).toBe('XX');
});

// Section 5: Country resolution
console.log('\n5. Agent Country Resolution');

test('Vercel geo header takes priority', () => {
  const result = resolveAgentCountry({
    headers: {
      'x-vercel-ip-country': 'MM',
      'x-agent-country': 'SG',         // self-reported — should be ignored
    },
  });
  expect(result.countryCode).toBe('MM');
  expect(result.source).toBe('vercel-geo');
});

test('TLD fallback when no geo header', () => {
  const result = resolveAgentCountry({
    headers: {},
    agentCardUrl: 'https://crowdstrike.com.mm/agent',
  });
  expect(result.countryCode).toBe('MM');
  expect(result.source).toBe('tld');
});

test('Self-reported fallback as last resort', () => {
  const result = resolveAgentCountry({
    headers: { 'x-agent-country': 'PK' },
  });
  expect(result.countryCode).toBe('PK');
  expect(result.source).toBe('self-reported');
});

test('Unknown source when no signal available', () => {
  const result = resolveAgentCountry({ headers: {} });
  expect(result.countryCode).toBe('XX');
  expect(result.source).toBe('unknown');
});

// Section 6: Rejection response format
console.log('\n6. JSON-RPC Rejection Response');

test('Rejection response is valid JSON-RPC 2.0', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'MM' } },
    emptyAllowlist,
    'agent:test',
  );
  const response = buildCiiRejectionResponse('req-001', decision);
  expect(response.jsonrpc).toBe('2.0');
  expect(response.id).toBe('req-001');
  expect(response.error.code).toBe(-32050);
});

test('Rejection response includes CII score in data', () => {
  const decision = evaluateCiiTrustPolicy(
    { headers: { 'x-vercel-ip-country': 'MM' } },
    emptyAllowlist,
    'agent:test',
  );
  const response = buildCiiRejectionResponse(1, decision);
  expect(response.error.data.ciiScore).toBe(72.8);
  expect(response.error.data.tier).toBe(TrustTier.CRITICAL);
});

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════');
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log('✅  All tests passing — CII trust policy ready for production\n');
  process.exit(0);
} else {
  console.log('❌  Some tests failed — review before deployment\n');
  process.exit(1);
}
