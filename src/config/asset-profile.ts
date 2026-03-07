/**
 * Asset Profile — customer tech stack for CISA KEV relevance scoring.
 *
 * Each customer deployment defines vendors, products, and industry keywords
 * their infrastructure depends on. GATRA SOC alerts matching these assets
 * score higher in the relevance ranking.
 *
 * For SelectUSA 2026 demo: hardcoded Tier-1 APAC Telecom profile.
 * Future: load from customer config JSON or Notion/API.
 */

// ── Types ───────────────────────────────────────────────────────────

export interface AssetProfileEntry {
  /** Canonical vendor name — fuzzy-matched against CISA KEV vendorProject. */
  vendor: string;
  /** Optional specific products — matched against KEV product + description. */
  products?: string[];
  /** 0–1 importance multiplier (default 1.0). Core infra > endpoints. */
  weight?: number;
}

export interface AssetProfile {
  id: string;
  name: string;
  description: string;
  industry: string;
  region: string;

  /** Vendors and products the customer operates. */
  vendors: AssetProfileEntry[];

  /** Industry keywords — boost alerts whose descriptions mention these terms. */
  industryKeywords: string[];

  /** ISO country codes or region names for geo-proximity signals (future use). */
  regions: string[];
}

// ── Default profile: Tier-1 APAC Telecom ────────────────────────────

export const DEFAULT_ASSET_PROFILE: AssetProfile = {
  id: 'apac-telco-tier1',
  name: 'Tier-1 APAC Telecom',
  description: 'Large Indonesian telecom — 100M subscribers, nationwide mobile/fixed/enterprise',
  industry: 'Telecommunications',
  region: 'APAC',

  vendors: [
    // ── Network infrastructure (core) ──
    { vendor: 'Cisco',        products: ['IOS', 'IOS XE', 'ASA', 'Firepower', 'NX-OS', 'SD-WAN', 'Adaptive Security Appliance'], weight: 1.0 },
    { vendor: 'Juniper',      products: ['Junos', 'SRX', 'EX Series'], weight: 0.9 },
    { vendor: 'Huawei',       products: ['EulerOS', 'EMUI', 'HarmonyOS'], weight: 0.9 },
    { vendor: 'Nokia',        products: ['NetAct', 'NSP'], weight: 0.8 },
    { vendor: 'Ericsson',     products: ['BSCS', 'ENM'], weight: 0.8 },
    { vendor: 'ZTE',          products: ['ZXHN'], weight: 0.7 },

    // ── Security infrastructure ──
    { vendor: 'Palo Alto',    products: ['PAN-OS', 'Cortex', 'GlobalProtect', 'Prisma'], weight: 1.0 },
    { vendor: 'Fortinet',     products: ['FortiOS', 'FortiGate', 'FortiManager', 'FortiAnalyzer', 'FortiProxy'], weight: 1.0 },
    { vendor: 'SonicWall',    products: ['SMA', 'SonicOS'], weight: 0.7 },
    { vendor: 'Ivanti',       products: ['Connect Secure', 'Policy Secure', 'EPMM', 'Neurons'], weight: 0.8 },
    { vendor: 'F5',           products: ['BIG-IP', 'BIG-IQ'], weight: 0.8 },
    { vendor: 'Citrix',       products: ['ADC', 'Gateway', 'NetScaler'], weight: 0.7 },

    // ── Enterprise IT / Cloud ──
    { vendor: 'Microsoft',    products: ['Exchange', 'Windows', 'Office', 'Azure', 'Outlook', 'SharePoint', '.NET', 'Active Directory', 'Hyper-V'], weight: 1.0 },
    { vendor: 'VMware',       products: ['vCenter', 'ESXi', 'vSphere', 'NSX', 'Aria'], weight: 0.9 },
    { vendor: 'Oracle',       products: ['Database', 'WebLogic', 'Java', 'MySQL'], weight: 0.8 },
    { vendor: 'SAP',          products: ['NetWeaver', 'S/4HANA'], weight: 0.7 },
    { vendor: 'Linux',        products: ['Kernel'], weight: 0.7 },
    { vendor: 'Red Hat',      products: ['Enterprise Linux', 'JBoss'], weight: 0.7 },

    // ── Web / Application stack ──
    { vendor: 'Apache',       products: ['HTTP Server', 'Tomcat', 'Log4j', 'Struts', 'OFBiz'], weight: 0.9 },
    { vendor: 'NGINX',        products: ['NGINX Plus'], weight: 0.7 },

    // ── Endpoint / Mobile (lower weight — not core infra) ──
    { vendor: 'Google',       products: ['Chrome', 'Android', 'Chromium'], weight: 0.5 },
    { vendor: 'Apple',        products: ['iOS', 'macOS', 'Safari', 'WebKit'], weight: 0.5 },
    { vendor: 'Samsung',      products: ['Galaxy', 'Exynos'], weight: 0.4 },
    { vendor: 'Qualcomm',     products: ['Snapdragon', 'MSM'], weight: 0.4 },
  ],

  industryKeywords: [
    'telecom', 'telco', 'telecommunications', 'mobile', 'cellular',
    '5g', 'lte', '4g', 'network', 'isp', 'carrier', 'subscriber',
    'sim', 'radius', 'ss7', 'diameter', 'billing', 'bss', 'oss',
    'core network', 'ran', 'volte', 'ims', 'critical infrastructure',
    'cii', 'dns', 'bgp', 'mpls', 'vpn',
  ],

  regions: ['ID', 'SG', 'MY', 'PH', 'TH', 'VN', 'AU', 'JP', 'IN'],
};

// ── Active profile accessor (future: UI-switchable) ─────────────────

let _activeProfile: AssetProfile = DEFAULT_ASSET_PROFILE;

export function getActiveAssetProfile(): AssetProfile {
  return _activeProfile;
}

export function setActiveAssetProfile(profile: AssetProfile): void {
  _activeProfile = profile;
}
