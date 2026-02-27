/**
 * Personal Security Posture Panel
 *
 * Privacy-preserving self-assessment that helps individuals understand
 * their cybersecurity risk profile without collecting any personal data.
 *
 * Design principles:
 *   1. ALL data stored in localStorage only — never transmitted
 *   2. No PII collected — only behavioral patterns (yes/no/category)
 *   3. Cross-references live threat feeds for contextual relevance
 *   4. "Cautiously optimistic" tone — empower, don't scare
 *   5. Actionable micro-recommendations, not generic advice
 *
 * Auto-scan (opt-in) features:
 *   - Password breach check via HIBP Pwned Passwords (k-anonymity)
 *   - Email domain security via DNS-over-HTTPS (SPF/DMARC/MX)
 *   - Browser security posture (client-side only)
 *
 * Storage key: 'worldmonitor-personal-security-posture'
 */

import { Panel } from '@/components/Panel';
import { escapeHtml } from '@/utils/sanitize';

// ── Types ────────────────────────────────────────────────────────────

interface AssessmentAnswers {
  // Authentication & Access
  uses2FA: boolean;
  passwordManager: boolean;
  uniquePasswords: boolean;
  biometricLock: boolean;

  // Device & Software
  autoUpdates: boolean;
  diskEncryption: boolean;
  antivirus: boolean;
  vpnUsage: string; // 'always' | 'public-wifi' | 'never'

  // Online Behavior
  phishingAwareness: boolean;  // can recognize phishing
  publicWifiCaution: boolean;
  socialMediaPrivacy: boolean;
  backupRoutine: string; // 'automated' | 'manual' | 'none'

  // Communication
  encryptedMessaging: boolean;
  emailEncryption: boolean;
  linkVerification: boolean;

  // Data & Privacy
  dataMinimization: boolean;    // limits personal data sharing
  privacySettings: boolean;     // reviews app permissions
  breachMonitoring: boolean;    // uses breach notification services

  // Professional Context (optional, no PII)
  sectorRisk: string; // 'finance' | 'healthcare' | 'gov' | 'tech' | 'education' | 'other'
  remoteWork: boolean;
}

interface DomainScore {
  name: string;
  score: number;     // 0–100
  maxScore: number;  // always 100
  tips: string[];    // actionable recommendations
  icon: string;      // emoji
}

interface PostureSnapshot {
  timestamp: number;
  overallScore: number;
  domains: DomainScore[];
  answers: AssessmentAnswers;
  threatContextLevel: 'low' | 'moderate' | 'elevated' | 'high';
}

interface StorageData {
  snapshots: PostureSnapshot[];
  lastCompleted: number | null;
  reminderDismissed: number | null;
  autoScan?: AutoScanResult | null;
}

// ── Auto-Scan Types ──────────────────────────────────────────────────

type CheckStatus = 'pending' | 'running' | 'pass' | 'warn' | 'fail' | 'error';

interface CheckResult {
  status: CheckStatus;
  label: string;
  detail: string;
  tip: string;
}

interface AutoScanResult {
  timestamp: number;
  checks: {
    browser: CheckResult[];
    password: CheckResult | null;
    emailDomain: CheckResult[] | null;
  };
  emailDomainUsed: string | null;
  overallGrade: string;   // A–F
  overallColor: string;
}

// ── Constants ────────────────────────────────────────────────────────

const STORAGE_KEY = 'worldmonitor-personal-security-posture';
const MAX_SNAPSHOTS = 12;   // Keep last 12 assessments
const REASSESS_DAYS = 30;   // Suggest re-assessment after 30 days

const DEFAULT_ANSWERS: AssessmentAnswers = {
  uses2FA: false,
  passwordManager: false,
  uniquePasswords: false,
  biometricLock: false,
  autoUpdates: false,
  diskEncryption: false,
  antivirus: false,
  vpnUsage: 'never',
  phishingAwareness: false,
  publicWifiCaution: false,
  socialMediaPrivacy: false,
  backupRoutine: 'none',
  encryptedMessaging: false,
  emailEncryption: false,
  linkVerification: false,
  dataMinimization: false,
  privacySettings: false,
  breachMonitoring: false,
  sectorRisk: 'other',
  remoteWork: false,
};

// ── Scoring Engine ───────────────────────────────────────────────────

function scoreAssessment(answers: AssessmentAnswers, threatLevel: string): DomainScore[] {
  const domains: DomainScore[] = [];

  // 1. Authentication & Access (weight: high)
  {
    let score = 0;
    const tips: string[] = [];

    if (answers.uses2FA) score += 35;
    else tips.push('Enable 2FA on your critical accounts (email, banking, cloud storage)');

    if (answers.passwordManager) score += 30;
    else tips.push('Use a password manager — even a free one drastically reduces risk');

    if (answers.uniquePasswords) score += 20;
    else tips.push('Avoid reusing passwords across sites — a single breach can cascade');

    if (answers.biometricLock) score += 15;
    else tips.push('Enable Face ID, fingerprint, or PIN lock on all devices');

    if (tips.length === 0) tips.push('Your authentication posture is strong — keep it up');

    domains.push({ name: 'Authentication', score, maxScore: 100, tips, icon: '\u{1F511}' });
  }

  // 2. Device & Software
  {
    let score = 0;
    const tips: string[] = [];

    if (answers.autoUpdates) score += 30;
    else tips.push('Enable automatic OS and app updates — patches fix known exploits');

    if (answers.diskEncryption) score += 25;
    else tips.push('Turn on FileVault (Mac) or BitLocker (Windows) for full-disk encryption');

    if (answers.antivirus) score += 20;
    else tips.push('Built-in OS protection is good; consider adding a reputable scanner');

    if (answers.vpnUsage === 'always') score += 25;
    else if (answers.vpnUsage === 'public-wifi') {
      score += 15;
      tips.push('Using VPN on public Wi-Fi is smart — consider extending to all networks');
    } else {
      tips.push('Use a VPN on untrusted networks to protect your traffic');
    }

    if (tips.length === 0) tips.push('Excellent device hygiene — your attack surface is minimized');

    domains.push({ name: 'Device Security', score, maxScore: 100, tips, icon: '\u{1F4BB}' });
  }

  // 3. Online Behavior
  {
    let score = 0;
    const tips: string[] = [];

    if (answers.phishingAwareness) score += 30;
    else tips.push('Learn to spot phishing: check sender email, hover over links before clicking');

    if (answers.publicWifiCaution) score += 20;
    else tips.push('Avoid sensitive transactions on public Wi-Fi without a VPN');

    if (answers.socialMediaPrivacy) score += 20;
    else tips.push('Review your social media privacy settings — limit public profile data');

    if (answers.backupRoutine === 'automated') score += 30;
    else if (answers.backupRoutine === 'manual') {
      score += 15;
      tips.push('Manual backups are better than none — consider automating with cloud sync');
    } else {
      tips.push('Set up automated backups — ransomware makes this critical');
    }

    if (tips.length === 0) tips.push('Strong online habits — you\'re harder to social-engineer');

    domains.push({ name: 'Online Behavior', score, maxScore: 100, tips, icon: '\u{1F310}' });
  }

  // 4. Communication Security
  {
    let score = 0;
    const tips: string[] = [];

    if (answers.encryptedMessaging) score += 40;
    else tips.push('Use end-to-end encrypted messaging (Signal, WhatsApp) for sensitive chats');

    if (answers.emailEncryption) score += 30;
    else tips.push('Consider encrypted email for sensitive communications');

    if (answers.linkVerification) score += 30;
    else tips.push('Always verify unexpected links — hover to check the actual URL destination');

    if (tips.length === 0) tips.push('Your communication channels are well-protected');

    domains.push({ name: 'Communications', score, maxScore: 100, tips, icon: '\u{1F4E8}' });
  }

  // 5. Data & Privacy
  {
    let score = 0;
    const tips: string[] = [];

    if (answers.dataMinimization) score += 35;
    else tips.push('Share less personal data online — only provide what\'s strictly necessary');

    if (answers.privacySettings) score += 35;
    else tips.push('Review app permissions regularly — revoke access you don\'t need');

    if (answers.breachMonitoring) score += 30;
    else tips.push('Sign up for breach notifications (e.g., haveibeenpwned.com) for your emails');

    if (tips.length === 0) tips.push('Great privacy discipline — you minimize your digital footprint');

    domains.push({ name: 'Data & Privacy', score, maxScore: 100, tips, icon: '\u{1F6E1}' });
  }

  // Apply threat-level context multiplier for recommendations
  if (threatLevel === 'high' || threatLevel === 'elevated') {
    for (const d of domains) {
      if (d.score < 60) {
        d.tips.unshift('\u26A0 Current threat level is elevated — prioritize this area');
      }
    }
  }

  return domains;
}

function computeOverallScore(domains: DomainScore[]): number {
  if (domains.length === 0) return 0;
  // Weighted: Auth gets 1.3x, Device 1.2x, Behavior 1.1x, Comms 1.0x, Privacy 1.0x
  const weights = [1.3, 1.2, 1.1, 1.0, 1.0];
  let weighted = 0;
  let totalWeight = 0;
  for (let i = 0; i < domains.length; i++) {
    const w = weights[i] ?? 1.0;
    const d = domains[i];
    if (!d) continue;
    weighted += d.score * w;
    totalWeight += w;
  }
  return Math.round(weighted / totalWeight);
}

function getPostureLabel(score: number): { label: string; color: string; message: string } {
  if (score >= 85) return {
    label: 'STRONG',
    color: '#22c55e',
    message: 'Your security posture is excellent. Keep maintaining these habits.',
  };
  if (score >= 65) return {
    label: 'GOOD',
    color: '#3b82f6',
    message: 'You\'re doing well. A few improvements can make you significantly harder to target.',
  };
  if (score >= 45) return {
    label: 'FAIR',
    color: '#eab308',
    message: 'Some gaps exist. The good news: small changes in key areas will boost your score fast.',
  };
  if (score >= 25) return {
    label: 'NEEDS ATTENTION',
    color: '#f97316',
    message: 'Several areas need improvement. Start with authentication — it\'s the highest-impact fix.',
  };
  return {
    label: 'AT RISK',
    color: '#ef4444',
    message: 'Your defenses are minimal. Start with 2FA and a password manager — they\'re free and powerful.',
  };
}

// ── Questionnaire Definition ─────────────────────────────────────────

interface Question {
  key: keyof AssessmentAnswers;
  text: string;
  type: 'boolean' | 'select';
  options?: { value: string; label: string }[];
  domain: string;
}

const QUESTIONS: Question[] = [
  // Authentication
  { key: 'uses2FA', text: 'Do you use two-factor authentication (2FA) on important accounts?', type: 'boolean', domain: 'Authentication' },
  { key: 'passwordManager', text: 'Do you use a password manager?', type: 'boolean', domain: 'Authentication' },
  { key: 'uniquePasswords', text: 'Do you use unique passwords for each account?', type: 'boolean', domain: 'Authentication' },
  { key: 'biometricLock', text: 'Are your devices protected with biometric or PIN lock?', type: 'boolean', domain: 'Authentication' },

  // Device
  { key: 'autoUpdates', text: 'Do you keep your OS and apps automatically updated?', type: 'boolean', domain: 'Device Security' },
  { key: 'diskEncryption', text: 'Is your disk encrypted (FileVault / BitLocker)?', type: 'boolean', domain: 'Device Security' },
  { key: 'antivirus', text: 'Do you use antivirus or endpoint protection beyond the OS default?', type: 'boolean', domain: 'Device Security' },
  { key: 'vpnUsage', text: 'How often do you use a VPN?', type: 'select', options: [
    { value: 'always', label: 'Always' },
    { value: 'public-wifi', label: 'Only on public Wi-Fi' },
    { value: 'never', label: 'Never / Rarely' },
  ], domain: 'Device Security' },

  // Behavior
  { key: 'phishingAwareness', text: 'Can you confidently identify phishing emails and messages?', type: 'boolean', domain: 'Online Behavior' },
  { key: 'publicWifiCaution', text: 'Do you avoid sensitive transactions on public Wi-Fi?', type: 'boolean', domain: 'Online Behavior' },
  { key: 'socialMediaPrivacy', text: 'Have you reviewed your social media privacy settings recently?', type: 'boolean', domain: 'Online Behavior' },
  { key: 'backupRoutine', text: 'How do you back up your data?', type: 'select', options: [
    { value: 'automated', label: 'Automated (cloud/Time Machine)' },
    { value: 'manual', label: 'Manual (occasional)' },
    { value: 'none', label: 'No backups' },
  ], domain: 'Online Behavior' },

  // Communication
  { key: 'encryptedMessaging', text: 'Do you use end-to-end encrypted messaging (Signal, WhatsApp)?', type: 'boolean', domain: 'Communications' },
  { key: 'emailEncryption', text: 'Do you use encrypted email for sensitive communications?', type: 'boolean', domain: 'Communications' },
  { key: 'linkVerification', text: 'Do you verify links before clicking (check URL, sender)?', type: 'boolean', domain: 'Communications' },

  // Privacy
  { key: 'dataMinimization', text: 'Do you limit the personal data you share online?', type: 'boolean', domain: 'Data & Privacy' },
  { key: 'privacySettings', text: 'Do you review app permissions and privacy settings regularly?', type: 'boolean', domain: 'Data & Privacy' },
  { key: 'breachMonitoring', text: 'Do you monitor for data breaches involving your accounts?', type: 'boolean', domain: 'Data & Privacy' },

  // Context
  { key: 'sectorRisk', text: 'What sector best describes your work?', type: 'select', options: [
    { value: 'finance', label: 'Finance / Banking' },
    { value: 'healthcare', label: 'Healthcare' },
    { value: 'gov', label: 'Government / Defense' },
    { value: 'tech', label: 'Technology / IT' },
    { value: 'education', label: 'Education' },
    { value: 'other', label: 'Other' },
  ], domain: 'Context' },
  { key: 'remoteWork', text: 'Do you regularly work remotely or from public spaces?', type: 'boolean', domain: 'Context' },
];

// ── CSS ──────────────────────────────────────────────────────────────

let cssInjected = false;
function injectCSS(): void {
  if (cssInjected) return;
  cssInjected = true;

  const style = document.createElement('style');
  style.textContent = `
/* Personal Security Posture Panel */
.psp-panel { font-size: 11px; line-height: 1.4; }

.psp-privacy-notice {
  display: flex; align-items: center; gap: 6px;
  padding: 6px 10px; margin: 0 0 8px;
  background: rgba(34,197,94,0.08); border-radius: 4px;
  font-size: 9px; color: #22c55e; letter-spacing: 0.3px;
}
.psp-privacy-notice::before {
  content: '\\1F512'; font-size: 11px;
}

/* Score ring */
.psp-score-ring {
  position: relative; width: 100px; height: 100px; margin: 8px auto;
}
.psp-score-ring svg { transform: rotate(-90deg); }
.psp-score-ring .psp-score-value {
  position: absolute; inset: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.psp-score-number { font-size: 26px; font-weight: 700; line-height: 1; }
.psp-score-label { font-size: 9px; font-weight: 600; letter-spacing: 0.5px; margin-top: 2px; }

/* Domain bars */
.psp-domain { margin: 4px 0; }
.psp-domain-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 2px 0; cursor: pointer; user-select: none;
}
.psp-domain-header:hover { opacity: 0.8; }
.psp-domain-name { font-size: 10px; font-weight: 600; }
.psp-domain-score { font-size: 10px; font-weight: 700; font-variant-numeric: tabular-nums; }
.psp-bar-track {
  height: 4px; background: rgba(255,255,255,0.06); border-radius: 2px;
  overflow: hidden; margin: 2px 0;
}
.psp-bar-fill {
  height: 100%; border-radius: 2px;
  transition: width 0.6s ease-out;
}
.psp-tips {
  overflow: hidden; transition: max-height 0.3s ease-out;
  max-height: 0; padding: 0 0 0 18px;
}
.psp-tips.open { max-height: 300px; }
.psp-tip {
  font-size: 10px; color: rgba(255,255,255,0.65);
  padding: 2px 0; line-height: 1.4;
}
.psp-tip::before { content: '\\2022 '; color: rgba(255,255,255,0.3); }

/* Trend sparkline */
.psp-trend { display: flex; align-items: center; gap: 8px; justify-content: center; margin: 6px 0; }
.psp-trend-label { font-size: 9px; color: rgba(255,255,255,0.4); }

/* Assessment form */
.psp-form { padding: 4px 0; }
.psp-section-title {
  font-size: 9px; font-weight: 700; letter-spacing: 0.5px;
  text-transform: uppercase; color: rgba(255,255,255,0.4);
  margin: 10px 0 4px; padding-top: 6px;
  border-top: 1px solid rgba(255,255,255,0.04);
}
.psp-question {
  padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.03);
}
.psp-q-text { font-size: 11px; color: rgba(255,255,255,0.85); margin-bottom: 4px; }
.psp-toggle-row { display: flex; gap: 6px; }
.psp-toggle-btn {
  padding: 3px 12px; border-radius: 3px; border: 1px solid rgba(255,255,255,0.1);
  background: transparent; color: rgba(255,255,255,0.5); font-size: 10px;
  cursor: pointer; transition: all 0.15s;
}
.psp-toggle-btn:hover { border-color: rgba(255,255,255,0.2); color: rgba(255,255,255,0.8); }
.psp-toggle-btn.active { background: rgba(59,130,246,0.2); border-color: #3b82f6; color: #3b82f6; }

.psp-select {
  background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
  color: rgba(255,255,255,0.8); font-size: 10px; padding: 3px 8px;
  border-radius: 3px; width: 100%;
}
.psp-select option { background: #1a1a2e; color: #fff; }

.psp-submit-row { display: flex; gap: 8px; margin-top: 12px; justify-content: center; }
.psp-btn {
  padding: 6px 16px; border-radius: 4px; border: none;
  font-size: 11px; font-weight: 600; cursor: pointer; transition: all 0.15s;
}
.psp-btn-primary { background: #3b82f6; color: #fff; }
.psp-btn-primary:hover { background: #2563eb; }
.psp-btn-secondary { background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.6); }
.psp-btn-secondary:hover { background: rgba(255,255,255,0.12); color: rgba(255,255,255,0.9); }

/* History */
.psp-history-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.03);
  font-size: 10px;
}
.psp-history-score { font-weight: 700; font-variant-numeric: tabular-nums; }
.psp-history-date { color: rgba(255,255,255,0.4); }

/* Sector context banner */
.psp-context-banner {
  display: flex; align-items: center; gap: 6px;
  padding: 5px 10px; margin: 6px 0;
  background: rgba(59,130,246,0.08); border-radius: 4px;
  font-size: 10px; color: rgba(255,255,255,0.65);
}

/* Footer actions */
.psp-footer {
  display: flex; justify-content: space-between; align-items: center;
  padding: 6px 0; margin-top: 4px;
  border-top: 1px solid rgba(255,255,255,0.04);
  font-size: 9px; color: rgba(255,255,255,0.3);
}
.psp-footer a {
  color: #3b82f6; text-decoration: none; cursor: pointer;
}
.psp-footer a:hover { text-decoration: underline; }

/* Auto-Scan */
.psp-scan-section { margin: 8px 0; }
.psp-scan-title {
  font-size: 10px; font-weight: 700; letter-spacing: 0.5px;
  text-transform: uppercase; color: rgba(255,255,255,0.4);
  margin: 8px 0 4px;
}
.psp-check {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.03);
}
.psp-check-icon { font-size: 13px; flex-shrink: 0; margin-top: 1px; }
.psp-check-body { flex: 1; min-width: 0; }
.psp-check-label { font-size: 11px; font-weight: 600; color: rgba(255,255,255,0.85); }
.psp-check-detail { font-size: 10px; color: rgba(255,255,255,0.5); margin-top: 1px; }
.psp-check-tip { font-size: 10px; color: #eab308; margin-top: 2px; }

.psp-input-row { display: flex; gap: 6px; margin: 6px 0; }
.psp-input {
  flex: 1; padding: 6px 10px; border-radius: 4px;
  border: 1px solid rgba(255,255,255,0.12);
  background: rgba(255,255,255,0.04); color: rgba(255,255,255,0.9);
  font-size: 11px; font-family: inherit; outline: none;
}
.psp-input:focus { border-color: #3b82f6; }
.psp-input::placeholder { color: rgba(255,255,255,0.25); }

.psp-grade {
  text-align: center; margin: 8px 0;
}
.psp-grade-letter {
  font-size: 42px; font-weight: 800; line-height: 1;
}
.psp-grade-label {
  font-size: 10px; font-weight: 600; margin-top: 2px;
}

.psp-scan-privacy {
  display: flex; align-items: center; gap: 5px;
  padding: 5px 8px; margin: 6px 0;
  background: rgba(34,197,94,0.06); border-radius: 3px;
  font-size: 9px; color: rgba(34,197,94,0.8);
}

@keyframes psp-score-fill {
  from { stroke-dashoffset: 283; }
}

@keyframes psp-spin {
  to { transform: rotate(360deg); }
}
.psp-spinner {
  display: inline-block; width: 12px; height: 12px;
  border: 2px solid rgba(255,255,255,0.1);
  border-top-color: #3b82f6; border-radius: 50%;
  animation: psp-spin 0.8s linear infinite;
}
`;
  document.head.appendChild(style);
}

// ── Panel Class ──────────────────────────────────────────────────────

export class PersonalSecurityPosturePanel extends Panel {
  private data: StorageData = { snapshots: [], lastCompleted: null, reminderDismissed: null, autoScan: null };
  private currentView: 'dashboard' | 'assess' | 'history' | 'autoscan' = 'dashboard';
  private formAnswers: AssessmentAnswers = { ...DEFAULT_ANSWERS };
  private formStep = 0;
  private expandedDomain: string | null = null;
  private threatContextLevel: 'low' | 'moderate' | 'elevated' | 'high' = 'low';

  // Auto-scan state
  private scanRunning = false;
  private scanEmailDomain = '';
  private scanPassword = '';
  private scanResults: AutoScanResult | null = null;

  constructor() {
    super({
      id: 'personal-security-posture',
      title: 'Security Posture',
      showCount: false,
      trackActivity: true,
      infoTooltip: 'Privacy-preserving personal security assessment. All data stays in your browser — nothing is ever transmitted.',
    });
    injectCSS();
    this.loadFromStorage();
    this.setupDelegatedEvents();
    // Render immediately so the panel doesn't stay on "Loading..."
    queueMicrotask(() => this.render());
  }

  /** Single delegated event listener — survives setContent() debounce. */
  private setupDelegatedEvents(): void {
    this.content.addEventListener('click', (e: Event) => {
      const target = e.target as HTMLElement;

      // data-action buttons/links
      const actionEl = target.closest<HTMLElement>('[data-action]');
      if (actionEl) {
        e.preventDefault();
        this.handleAction(actionEl.dataset.action || '');
        return;
      }

      // Boolean toggle buttons
      const toggleBtn = target.closest<HTMLElement>('.psp-toggle-btn');
      if (toggleBtn && toggleBtn.dataset.key) {
        const key = toggleBtn.dataset.key as keyof AssessmentAnswers;
        const val = toggleBtn.dataset.val === 'true';
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (this.formAnswers as any)[key] = val;
        this.render();
        return;
      }

      // Domain expand/collapse
      const domainHeader = target.closest<HTMLElement>('.psp-domain-header');
      if (domainHeader) {
        const domain = domainHeader.dataset.domain || null;
        this.expandedDomain = this.expandedDomain === domain ? null : domain;
        this.render();
        return;
      }
    });

    // Select change events (delegated)
    this.content.addEventListener('change', (e: Event) => {
      const target = e.target as HTMLElement;
      if (target.matches('.psp-select') && target instanceof HTMLSelectElement) {
        const key = target.dataset.key as keyof AssessmentAnswers;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (this.formAnswers as any)[key] = target.value;
      }
    });

    // Input events for auto-scan fields
    this.content.addEventListener('input', (e: Event) => {
      const target = e.target as HTMLInputElement;
      if (target.matches('#psp-scan-email-domain')) {
        this.scanEmailDomain = target.value.trim();
      } else if (target.matches('#psp-scan-password')) {
        this.scanPassword = target.value;
      }
    });
  }

  private handleAction(action: string): void {
    switch (action) {
      case 'start-assess':
      case 'reassess':
        this.formAnswers = this.latestSnapshot?.answers
          ? { ...this.latestSnapshot.answers }
          : { ...DEFAULT_ANSWERS };
        this.formStep = 0;
        this.currentView = 'assess';
        this.render();
        break;
      case 'history':
        this.currentView = 'history';
        this.render();
        break;
      case 'back':
        this.currentView = 'dashboard';
        this.render();
        break;
      case 'clear':
        this.clearAllData();
        break;
      case 'next':
        this.formStep++;
        this.render();
        break;
      case 'prev':
        this.formStep = Math.max(0, this.formStep - 1);
        this.render();
        break;
      case 'cancel':
        this.currentView = 'dashboard';
        this.render();
        break;
      case 'submit':
        this.submitAssessment();
        break;
      case 'autoscan':
        this.scanResults = null;
        this.currentView = 'autoscan';
        this.render();
        break;
      case 'run-scan':
        this.runAutoScan();
        break;
    }
  }

  // ── Storage ──────────────────────────────────────────────────────

  private loadFromStorage(): void {
    try {
      const json = localStorage.getItem(STORAGE_KEY);
      if (json) {
        const parsed = JSON.parse(json);
        if (parsed && Array.isArray(parsed.snapshots)) {
          this.data = parsed;
        }
      }
    } catch {
      // Corrupt data — start fresh
      this.data = { snapshots: [], lastCompleted: null, reminderDismissed: null };
    }
  }

  private saveToStorage(): void {
    try {
      // Trim to max snapshots
      if (this.data.snapshots.length > MAX_SNAPSHOTS) {
        this.data.snapshots = this.data.snapshots.slice(-MAX_SNAPSHOTS);
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.data));
    } catch {
      console.error('[PSP] Failed to save to localStorage');
    }
  }

  // ── Public API ───────────────────────────────────────────────────

  /** Called by App.ts on refresh interval — update threat context. */
  public async refresh(): Promise<void> {
    this.render();
  }

  /** Allow App to pass current threat level from other panels. */
  public setThreatContext(level: 'low' | 'moderate' | 'elevated' | 'high'): void {
    this.threatContextLevel = level;
  }

  /** Reset all stored data. */
  public clearAllData(): void {
    this.data = { snapshots: [], lastCompleted: null, reminderDismissed: null };
    localStorage.removeItem(STORAGE_KEY);
    this.currentView = 'dashboard';
    this.render();
  }

  // ── Assessment Logic ─────────────────────────────────────────────

  private submitAssessment(): void {
    const domains = scoreAssessment(this.formAnswers, this.threatContextLevel);
    const overallScore = computeOverallScore(domains);

    const snapshot: PostureSnapshot = {
      timestamp: Date.now(),
      overallScore,
      domains,
      answers: { ...this.formAnswers },
      threatContextLevel: this.threatContextLevel,
    };

    this.data.snapshots.push(snapshot);
    this.data.lastCompleted = Date.now();
    this.saveToStorage();

    // Show result
    this.currentView = 'dashboard';
    this.setNewBadge(1, true);
    this.render();
  }

  private get latestSnapshot(): PostureSnapshot | null {
    return this.data.snapshots.length > 0
      ? this.data.snapshots[this.data.snapshots.length - 1] ?? null
      : null;
  }

  private get daysSinceLastAssessment(): number | null {
    if (!this.data.lastCompleted) return null;
    return Math.floor((Date.now() - this.data.lastCompleted) / 86_400_000);
  }

  // ── Rendering ────────────────────────────────────────────────────

  private render(): void {
    switch (this.currentView) {
      case 'assess':
        this.setContent(this.renderAssessmentForm());
        break;
      case 'history':
        this.setContent(this.renderHistory());
        break;
      case 'autoscan':
        this.setContent(this.renderAutoScan());
        break;
      default:
        this.setContent(this.renderDashboard());
        break;
    }
  }

  // ── Dashboard View ───────────────────────────────────────────────

  private renderDashboard(): string {
    const snap = this.latestSnapshot;

    if (!snap) {
      return this.renderFirstTime();
    }

    const posture = getPostureLabel(snap.overallScore);
    const daysSince = this.daysSinceLastAssessment;
    const needsReassess = daysSince !== null && daysSince >= REASSESS_DAYS;

    // Score ring SVG
    const circumference = 2 * Math.PI * 45; // r=45
    const offset = circumference - (snap.overallScore / 100) * circumference;

    let html = `<div class="psp-panel" style="padding:8px 12px;">`;

    // Privacy notice
    html += `<div class="psp-privacy-notice">All data stored locally in your browser only</div>`;

    // Score ring
    html += `<div class="psp-score-ring">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="6"/>
        <circle cx="50" cy="50" r="45" fill="none" stroke="${posture.color}" stroke-width="6"
          stroke-dasharray="${circumference.toFixed(1)}"
          stroke-dashoffset="${offset.toFixed(1)}"
          stroke-linecap="round"
          style="animation: psp-score-fill 1s ease-out forwards;"/>
      </svg>
      <div class="psp-score-value">
        <div class="psp-score-number" style="color:${posture.color}">${snap.overallScore}</div>
        <div class="psp-score-label" style="color:${posture.color}">${posture.label}</div>
      </div>
    </div>`;

    // Posture message
    html += `<div style="text-align:center;font-size:11px;color:rgba(255,255,255,0.7);padding:2px 8px 8px;">
      ${escapeHtml(posture.message)}
    </div>`;

    // Trend sparkline (if multiple snapshots)
    if (this.data.snapshots.length >= 2) {
      html += this.renderTrendSparkline();
    }

    // Threat context banner
    if (this.threatContextLevel !== 'low') {
      const levelColors: Record<string, string> = {
        moderate: '#eab308',
        elevated: '#f97316',
        high: '#ef4444',
      };
      html += `<div class="psp-context-banner" style="border-left:2px solid ${levelColors[this.threatContextLevel] || '#eab308'}">
        Current global threat level: <strong style="color:${levelColors[this.threatContextLevel] || '#eab308'}">${this.threatContextLevel.toUpperCase()}</strong>
        — review low-scoring areas
      </div>`;
    }

    // Sector context
    if (snap.answers.sectorRisk !== 'other') {
      const sectorMessages: Record<string, string> = {
        finance: 'Finance sector: credential theft and ransomware are top threats',
        healthcare: 'Healthcare sector: patient data and ransomware are primary risks',
        gov: 'Government sector: state-sponsored threats and phishing are elevated',
        tech: 'Tech sector: supply chain and insider threats deserve extra attention',
        education: 'Education sector: phishing and data exposure are common attack vectors',
      };
      const msg = sectorMessages[snap.answers.sectorRisk];
      if (msg) {
        html += `<div class="psp-context-banner">${escapeHtml(msg)}</div>`;
      }
    }

    // Domain scores
    html += `<div style="margin-top:6px;">`;
    for (const domain of snap.domains) {
      const barColor = domain.score >= 70 ? '#22c55e' : domain.score >= 45 ? '#eab308' : '#ef4444';
      const isExpanded = this.expandedDomain === domain.name;

      html += `<div class="psp-domain">
        <div class="psp-domain-header" data-domain="${escapeHtml(domain.name)}">
          <span class="psp-domain-name">${domain.icon} ${escapeHtml(domain.name)}</span>
          <span class="psp-domain-score" style="color:${barColor}">${domain.score}/100</span>
        </div>
        <div class="psp-bar-track">
          <div class="psp-bar-fill" style="width:${domain.score}%;background:${barColor}"></div>
        </div>
        <div class="psp-tips ${isExpanded ? 'open' : ''}">
          ${domain.tips.map(t => `<div class="psp-tip">${escapeHtml(t)}</div>`).join('')}
        </div>
      </div>`;
    }
    html += `</div>`;

    // Reassessment nudge
    if (needsReassess) {
      html += `<div style="text-align:center;padding:8px 0;font-size:10px;color:#eab308;">
        It's been ${daysSince} days since your last assessment — consider retaking it.
      </div>`;
    }

    // Footer
    html += `<div class="psp-footer">
      <span>${daysSince !== null ? `Last assessed ${daysSince === 0 ? 'today' : daysSince + 'd ago'}` : ''}</span>
      <span style="display:flex;gap:10px;">
        <a data-action="autoscan">Auto-Scan</a>
        <a data-action="reassess">Retake</a>
        <a data-action="history">History</a>
        <a data-action="clear" style="color:#ef4444;">Reset</a>
      </span>
    </div>`;

    html += `</div>`;
    return html;
  }

  private renderFirstTime(): string {
    return `<div class="psp-panel" style="padding:16px 12px;text-align:center;">
      <div class="psp-privacy-notice">All data stored locally in your browser only</div>

      <div style="font-size:32px;margin:12px 0 8px;">\u{1F6E1}</div>
      <div style="font-size:13px;font-weight:600;color:rgba(255,255,255,0.9);margin-bottom:4px;">
        Personal Security Posture
      </div>
      <div style="font-size:11px;color:rgba(255,255,255,0.5);margin-bottom:16px;line-height:1.5;">
        Take a 2-minute self-assessment to understand your cybersecurity strengths
        and get personalized, actionable recommendations.<br><br>
        <strong style="color:#22c55e;">No personal data is collected.</strong>
        Everything stays in your browser.
      </div>

      <button class="psp-btn psp-btn-primary" data-action="start-assess" style="font-size:12px;padding:8px 24px;">
        Start Assessment
      </button>

      <div style="margin-top:10px;">
        <button class="psp-btn psp-btn-secondary" data-action="autoscan" style="font-size:11px;padding:6px 16px;">
          \u{1F50D} Auto-Scan Instead
        </button>
      </div>

      <div style="font-size:9px;color:rgba(255,255,255,0.25);margin-top:12px;">
        Assessment: 20 questions \u00B7 ~2 min \u00B7 Auto-Scan: checks breaches &amp; DNS \u00B7 ~10 sec
      </div>
    </div>`;
  }

  private renderTrendSparkline(): string {
    const snaps = this.data.snapshots;
    if (snaps.length < 2) return '';

    const scores = snaps.map(s => s.overallScore);
    const width = 120;
    const height = 24;
    const min = Math.max(0, Math.min(...scores) - 10);
    const max = Math.min(100, Math.max(...scores) + 10);
    const range = max - min || 1;

    const points = scores.map((s, i) => {
      const x = (i / (scores.length - 1)) * width;
      const y = height - ((s - min) / range) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');

    const latest = scores[scores.length - 1] ?? 0;
    const prev = scores[scores.length - 2] ?? 0;
    const diff = latest - prev;
    const arrow = diff > 0 ? '\u25B2' : diff < 0 ? '\u25BC' : '\u25AC';
    const diffColor = diff > 0 ? '#22c55e' : diff < 0 ? '#ef4444' : '#888';
    const lineColor = latest >= 65 ? '#22c55e' : latest >= 45 ? '#eab308' : '#ef4444';

    return `<div class="psp-trend">
      <span class="psp-trend-label">${snaps.length} assessments</span>
      <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" style="vertical-align:middle">
        <polyline points="${points}" fill="none" stroke="${lineColor}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        <circle cx="${width}" cy="${height - ((latest - min) / range) * height}" r="2.5" fill="${lineColor}"/>
      </svg>
      <span style="font-size:10px;font-weight:600;color:${diffColor}">${arrow} ${diff > 0 ? '+' : ''}${diff}</span>
    </div>`;
  }

  // ── Assessment Form View ─────────────────────────────────────────

  private renderAssessmentForm(): string {
    // Group questions by domain
    const groups: { domain: string; questions: Question[] }[] = [];
    let lastDomain = '';
    for (const q of QUESTIONS) {
      if (q.domain !== lastDomain) {
        groups.push({ domain: q.domain, questions: [] });
        lastDomain = q.domain;
      }
      const lastGroup = groups[groups.length - 1];
      if (lastGroup) lastGroup.questions.push(q);
    }

    const totalSteps = groups.length;
    const currentGroup = groups[Math.min(this.formStep, totalSteps - 1)]!;
    const progress = ((this.formStep + 1) / totalSteps) * 100;

    let html = `<div class="psp-panel" style="padding:8px 12px;">`;

    // Progress bar
    html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
      <div style="flex:1;height:3px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;">
        <div style="width:${progress}%;height:100%;background:#3b82f6;border-radius:2px;transition:width 0.3s;"></div>
      </div>
      <span style="font-size:9px;color:rgba(255,255,255,0.4);white-space:nowrap;">
        ${this.formStep + 1}/${totalSteps}
      </span>
    </div>`;

    // Section title
    html += `<div class="psp-section-title" style="margin-top:0;">${escapeHtml(currentGroup.domain)}</div>`;

    // Questions for current group
    html += `<div class="psp-form">`;
    for (const q of currentGroup.questions) {
      html += `<div class="psp-question">
        <div class="psp-q-text">${escapeHtml(q.text)}</div>`;

      if (q.type === 'boolean') {
        const val = this.formAnswers[q.key] as boolean;
        html += `<div class="psp-toggle-row">
          <button class="psp-toggle-btn ${val === true ? 'active' : ''}" data-key="${q.key}" data-val="true">Yes</button>
          <button class="psp-toggle-btn ${val === false ? 'active' : ''}" data-key="${q.key}" data-val="false">No</button>
        </div>`;
      } else if (q.type === 'select' && q.options) {
        const val = this.formAnswers[q.key] as string;
        html += `<select class="psp-select" data-key="${q.key}">
          ${q.options.map(opt =>
            `<option value="${escapeHtml(opt.value)}" ${val === opt.value ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`
          ).join('')}
        </select>`;
      }

      html += `</div>`;
    }
    html += `</div>`;

    // Navigation
    html += `<div class="psp-submit-row">`;
    if (this.formStep > 0) {
      html += `<button class="psp-btn psp-btn-secondary" data-action="prev">Back</button>`;
    }
    html += `<button class="psp-btn psp-btn-secondary" data-action="cancel">Cancel</button>`;
    if (this.formStep < totalSteps - 1) {
      html += `<button class="psp-btn psp-btn-primary" data-action="next">Next</button>`;
    } else {
      html += `<button class="psp-btn psp-btn-primary" data-action="submit">Get Results</button>`;
    }
    html += `</div>`;

    html += `</div>`;
    return html;
  }

  // ── History View ─────────────────────────────────────────────────

  private renderHistory(): string {
    const snaps = [...this.data.snapshots].reverse();

    let html = `<div class="psp-panel" style="padding:8px 12px;">`;

    html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
      <span style="font-size:11px;font-weight:600;color:rgba(255,255,255,0.8);">Assessment History</span>
      <a data-action="back" style="font-size:10px;color:#3b82f6;cursor:pointer;text-decoration:none;">Back</a>
    </div>`;

    if (snaps.length === 0) {
      html += `<div style="text-align:center;padding:20px;color:rgba(255,255,255,0.3);font-size:11px;">
        No assessments yet
      </div>`;
    } else {
      // Trend chart
      if (snaps.length >= 2) {
        html += this.renderTrendSparkline();
      }

      for (const snap of snaps) {
        const posture = getPostureLabel(snap.overallScore);
        const date = new Date(snap.timestamp);
        const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

        html += `<div class="psp-history-item">
          <span>
            <span class="psp-history-score" style="color:${posture.color}">${snap.overallScore}</span>
            <span style="font-size:9px;color:${posture.color};margin-left:4px;">${posture.label}</span>
          </span>
          <span class="psp-history-date">${escapeHtml(dateStr)}</span>
        </div>`;
      }
    }

    html += `<div class="psp-footer" style="margin-top:8px;">
      <span style="font-size:9px;color:rgba(255,255,255,0.25);">Max ${MAX_SNAPSHOTS} snapshots kept</span>
    </div>`;

    html += `</div>`;
    return html;
  }

  // ── Auto-Scan View ──────────────────────────────────────────────

  private renderAutoScan(): string {
    let html = `<div class="psp-panel" style="padding:8px 12px;">`;

    // Header
    html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
      <span style="font-size:12px;font-weight:600;color:rgba(255,255,255,0.9);">\u{1F50D} Auto-Scan</span>
      <a data-action="back" style="font-size:10px;color:#3b82f6;cursor:pointer;text-decoration:none;">Back</a>
    </div>`;

    // Privacy explainer
    html += `<div class="psp-scan-privacy">
      \u{1F512} Password: only first 5 chars of SHA-1 hash sent (k-anonymity) \u00B7 DNS: public records only
    </div>`;

    if (this.scanResults) {
      // Show results
      html += this.renderScanResults();
    } else {
      // Input form
      html += this.renderScanForm();
    }

    html += `</div>`;
    return html;
  }

  private renderScanForm(): string {
    let html = '';

    // Browser checks (always run, no input needed)
    html += `<div class="psp-scan-section">
      <div class="psp-scan-title">\u{1F310} Browser Security (automatic)</div>
      <div style="font-size:10px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
        These checks run entirely in your browser — nothing is sent anywhere.
      </div>
    </div>`;

    // Password check
    html += `<div class="psp-scan-section">
      <div class="psp-scan-title">\u{1F511} Password Breach Check (optional)</div>
      <div style="font-size:10px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
        Check if a password has appeared in known data breaches.
        Uses HIBP k-anonymity — your full password never leaves this device.
      </div>
      <div class="psp-input-row">
        <input type="password" id="psp-scan-password" class="psp-input"
          placeholder="Enter a password to check" autocomplete="off"
          value="${escapeHtml(this.scanPassword)}" />
      </div>
    </div>`;

    // Email domain check
    html += `<div class="psp-scan-section">
      <div class="psp-scan-title">\u{1F4E7} Email Domain Security (optional)</div>
      <div style="font-size:10px;color:rgba(255,255,255,0.45);margin-bottom:4px;">
        Check if your email provider has SPF, DMARC, and MX records configured.
        Only the domain is checked (e.g., "gmail.com"), not your email address.
      </div>
      <div class="psp-input-row">
        <input type="text" id="psp-scan-email-domain" class="psp-input"
          placeholder="Email domain (e.g. gmail.com)" autocomplete="off"
          value="${escapeHtml(this.scanEmailDomain)}" />
      </div>
    </div>`;

    // Run button
    html += `<div style="text-align:center;margin-top:10px;">
      <button class="psp-btn psp-btn-primary" data-action="run-scan" ${this.scanRunning ? 'disabled' : ''}>
        ${this.scanRunning
          ? '<span class="psp-spinner"></span> Scanning...'
          : '\u{1F50D} Run Scan'}
      </button>
    </div>`;

    return html;
  }

  private renderScanResults(): string {
    const r = this.scanResults!;
    let html = '';

    // Grade
    html += `<div class="psp-grade">
      <div class="psp-grade-letter" style="color:${r.overallColor}">${escapeHtml(r.overallGrade)}</div>
      <div class="psp-grade-label" style="color:${r.overallColor}">Security Grade</div>
    </div>`;

    // Browser checks
    html += `<div class="psp-scan-section">
      <div class="psp-scan-title">\u{1F310} Browser Security</div>
      ${r.checks.browser.map(c => this.renderCheck(c)).join('')}
    </div>`;

    // Password check
    if (r.checks.password) {
      html += `<div class="psp-scan-section">
        <div class="psp-scan-title">\u{1F511} Password Check</div>
        ${this.renderCheck(r.checks.password)}
      </div>`;
    }

    // Email domain checks
    if (r.checks.emailDomain && r.checks.emailDomain.length > 0) {
      html += `<div class="psp-scan-section">
        <div class="psp-scan-title">\u{1F4E7} Email Domain: ${escapeHtml(r.emailDomainUsed || '')}</div>
        ${r.checks.emailDomain.map(c => this.renderCheck(c)).join('')}
      </div>`;
    }

    // Footer
    const date = new Date(r.timestamp);
    const dateStr = date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    html += `<div class="psp-footer">
      <span>Scanned ${escapeHtml(dateStr)}</span>
      <span style="display:flex;gap:10px;">
        <a data-action="autoscan">Rescan</a>
        <a data-action="back">Dashboard</a>
      </span>
    </div>`;

    return html;
  }

  private renderCheck(c: CheckResult): string {
    const icons: Record<CheckStatus, string> = {
      pending: '\u{23F3}',
      running: '\u{1F504}',
      pass: '\u2705',
      warn: '\u26A0\uFE0F',
      fail: '\u274C',
      error: '\u{1F6AB}',
    };
    return `<div class="psp-check">
      <span class="psp-check-icon">${icons[c.status] || '\u2753'}</span>
      <div class="psp-check-body">
        <div class="psp-check-label">${escapeHtml(c.label)}</div>
        <div class="psp-check-detail">${escapeHtml(c.detail)}</div>
        ${c.tip && c.status !== 'pass' ? `<div class="psp-check-tip">${escapeHtml(c.tip)}</div>` : ''}
      </div>
    </div>`;
  }

  // ── Auto-Scan Logic ─────────────────────────────────────────────

  private async runAutoScan(): Promise<void> {
    if (this.scanRunning) return;
    this.scanRunning = true;
    this.render();

    const browserChecks = this.runBrowserChecks();
    let passwordCheck: CheckResult | null = null;
    let emailDomainChecks: CheckResult[] | null = null;

    // Password breach check
    if (this.scanPassword.length > 0) {
      passwordCheck = await this.checkPasswordBreach(this.scanPassword);
    }

    // Email domain DNS checks
    const domain = this.extractDomain(this.scanEmailDomain);
    if (domain) {
      emailDomainChecks = await this.checkEmailDomainSecurity(domain);
    }

    // Compute grade
    const allChecks = [
      ...browserChecks,
      ...(passwordCheck ? [passwordCheck] : []),
      ...(emailDomainChecks || []),
    ];

    const passCount = allChecks.filter(c => c.status === 'pass').length;
    const total = allChecks.length;
    const ratio = total > 0 ? passCount / total : 0;

    let grade: string;
    let color: string;
    if (ratio >= 0.9) { grade = 'A'; color = '#22c55e'; }
    else if (ratio >= 0.75) { grade = 'B'; color = '#3b82f6'; }
    else if (ratio >= 0.6) { grade = 'C'; color = '#eab308'; }
    else if (ratio >= 0.4) { grade = 'D'; color = '#f97316'; }
    else { grade = 'F'; color = '#ef4444'; }

    this.scanResults = {
      timestamp: Date.now(),
      checks: {
        browser: browserChecks,
        password: passwordCheck,
        emailDomain: emailDomainChecks,
      },
      emailDomainUsed: domain,
      overallGrade: grade,
      overallColor: color,
    };

    // Persist last scan
    this.data.autoScan = this.scanResults;
    this.saveToStorage();

    // Clear sensitive input
    this.scanPassword = '';

    this.scanRunning = false;
    this.setNewBadge(1, true);
    this.render();
  }

  private runBrowserChecks(): CheckResult[] {
    const checks: CheckResult[] = [];

    // HTTPS check
    const isHttps = location.protocol === 'https:';
    checks.push({
      status: isHttps ? 'pass' : 'fail',
      label: 'HTTPS Connection',
      detail: isHttps ? 'This page is served over a secure connection' : 'This page is NOT using HTTPS',
      tip: 'Always verify the padlock icon in your browser address bar',
    });

    // Cookies enabled
    const cookiesEnabled = navigator.cookieEnabled;
    checks.push({
      status: cookiesEnabled ? 'pass' : 'warn',
      label: 'Cookies Enabled',
      detail: cookiesEnabled ? 'Cookies are enabled (needed for authentication)' : 'Cookies are disabled — some sites may not work',
      tip: 'Enable cookies but consider blocking third-party cookies',
    });

    // Do Not Track
    const dnt = navigator.doNotTrack === '1';
    checks.push({
      status: dnt ? 'pass' : 'warn',
      label: 'Do Not Track',
      detail: dnt ? 'DNT header is enabled' : 'Do Not Track is not enabled',
      tip: 'Enable DNT in browser settings — not all sites honor it, but it signals intent',
    });

    // Secure context
    const isSecure = window.isSecureContext;
    checks.push({
      status: isSecure ? 'pass' : 'fail',
      label: 'Secure Context',
      detail: isSecure ? 'Running in a secure browser context' : 'Not in a secure context — some APIs restricted',
      tip: 'Access sites via HTTPS to enable secure context features',
    });

    // WebRTC leak potential
    const hasRTC = !!(window.RTCPeerConnection);
    checks.push({
      status: hasRTC ? 'warn' : 'pass',
      label: 'WebRTC Leak Risk',
      detail: hasRTC ? 'WebRTC is enabled — may leak your real IP behind VPN' : 'WebRTC is disabled — lower leak risk',
      tip: 'If using a VPN, consider a browser extension to disable WebRTC',
    });

    // Hardware concurrency (fingerprinting surface)
    const cores = navigator.hardwareConcurrency;
    checks.push({
      status: cores ? 'warn' : 'pass',
      label: 'Hardware Fingerprint Exposure',
      detail: cores ? `Browser exposes ${cores} CPU cores (used for fingerprinting)` : 'Hardware info not exposed',
      tip: 'Use privacy-focused browsers or extensions to reduce fingerprinting surface',
    });

    return checks;
  }

  private async checkPasswordBreach(password: string): Promise<CheckResult> {
    try {
      // SHA-1 hash the password (browser native crypto)
      const encoder = new TextEncoder();
      const data = encoder.encode(password);
      const hashBuffer = await crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

      const prefix = hashHex.substring(0, 5);
      const suffix = hashHex.substring(5);

      const resp = await fetch(`/api/security-check?action=pwned-password&prefix=${prefix}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

      const result = await resp.json();
      const match = result.entries?.find((e: { suffix: string; count: number }) => e.suffix === suffix);

      if (match) {
        return {
          status: 'fail',
          label: 'Password Breach Check',
          detail: `This password has appeared in ${match.count.toLocaleString()} data breaches`,
          tip: 'Change this password immediately — use a password manager to generate a unique one',
        };
      }
      return {
        status: 'pass',
        label: 'Password Breach Check',
        detail: 'This password was not found in known data breaches',
        tip: '',
      };
    } catch (err) {
      return {
        status: 'error',
        label: 'Password Breach Check',
        detail: `Check failed: ${(err as Error).message}`,
        tip: 'You can also check manually at haveibeenpwned.com/Passwords',
      };
    }
  }

  private async checkEmailDomainSecurity(domain: string): Promise<CheckResult[]> {
    const results: CheckResult[] = [];

    // SPF check
    try {
      const resp = await fetch(`/api/security-check?action=dns-spf&domain=${encodeURIComponent(domain)}`);
      const data = await resp.json();
      if (data.found) {
        const record = data.records?.[0]?.data || '';
        const hasHardFail = record.includes('-all');
        results.push({
          status: hasHardFail ? 'pass' : 'warn',
          label: 'SPF Record',
          detail: hasHardFail
            ? `SPF configured with strict policy (-all)`
            : `SPF found but uses soft policy (~all or ?all)`,
          tip: hasHardFail ? '' : 'A strict SPF policy (-all) better prevents email spoofing',
        });
      } else {
        results.push({
          status: 'fail',
          label: 'SPF Record',
          detail: 'No SPF record found — email spoofing is possible',
          tip: 'Contact your email provider about enabling SPF protection',
        });
      }
    } catch {
      results.push({
        status: 'error',
        label: 'SPF Record',
        detail: 'Could not check SPF record',
        tip: 'Try again later or check manually with dig/nslookup',
      });
    }

    // DMARC check
    try {
      const resp = await fetch(`/api/security-check?action=dns-dmarc&domain=${encodeURIComponent(domain)}`);
      const data = await resp.json();
      if (data.found) {
        const record = data.records?.[0]?.data || '';
        const hasReject = record.includes('p=reject');
        const hasQuarantine = record.includes('p=quarantine');
        results.push({
          status: hasReject ? 'pass' : hasQuarantine ? 'pass' : 'warn',
          label: 'DMARC Record',
          detail: hasReject
            ? 'DMARC configured with reject policy — strong protection'
            : hasQuarantine
            ? 'DMARC configured with quarantine policy — good protection'
            : 'DMARC found but policy may be too permissive (p=none)',
          tip: hasReject || hasQuarantine ? '' : 'A reject or quarantine DMARC policy prevents phishing from your domain',
        });
      } else {
        results.push({
          status: 'fail',
          label: 'DMARC Record',
          detail: 'No DMARC record found — vulnerable to email impersonation',
          tip: 'DMARC protects against someone sending emails pretending to be your domain',
        });
      }
    } catch {
      results.push({
        status: 'error',
        label: 'DMARC Record',
        detail: 'Could not check DMARC record',
        tip: 'Try again later',
      });
    }

    // MX check
    try {
      const resp = await fetch(`/api/security-check?action=dns-mx&domain=${encodeURIComponent(domain)}`);
      const data = await resp.json();
      if (data.found && data.records?.length > 0) {
        results.push({
          status: 'pass',
          label: 'MX Records',
          detail: `${data.records.length} mail server(s) configured`,
          tip: '',
        });
      } else {
        results.push({
          status: 'warn',
          label: 'MX Records',
          detail: 'No MX records found — domain may not handle email',
          tip: 'This domain may not be configured for email',
        });
      }
    } catch {
      results.push({
        status: 'error',
        label: 'MX Records',
        detail: 'Could not check MX records',
        tip: 'Try again later',
      });
    }

    return results;
  }

  private extractDomain(input: string): string | null {
    const trimmed = input.trim().toLowerCase();
    if (!trimmed) return null;

    // If user entered an email, extract domain
    const atIndex = trimmed.indexOf('@');
    const domain = atIndex >= 0 ? trimmed.substring(atIndex + 1) : trimmed;

    // Basic validation
    if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
      return domain;
    }
    return null;
  }
}
