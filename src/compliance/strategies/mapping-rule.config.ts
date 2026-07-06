// =============================================================================
// Compliance Mapping Rule Configuration
// =============================================================================
//
// SINGLE SOURCE OF TRUTH for all AutoRule vulnerability-to-control mappings.
//
// Structure:
//   Each entry defines one rule. The `keywords` array is matched (case-insensitive,
//   substring) against the vulnerability `type` field. When ANY keyword matches,
//   ALL `controlKeys` listed are mapped to the vulnerability.
//
// Confidence assignment:
//   HIGH  — full canonical vulnerability class match (strong semantic signal)
//   MEDIUM — partial keyword match (still useful, but analyst review recommended)
//
// Adding new rules:
//   Add a new MappingRule entry here. No other file needs to change.
//
// =============================================================================

import { MappingConfidence } from '@prisma/client';

export interface MappingRule {
  /** Keywords matched case-insensitively as substrings against vuln.type */
  keywords: string[];
  /** One or more SecurityControl.controlKey values to map */
  controlKeys: string[];
  /** Confidence level to assign when this rule fires */
  confidence: MappingConfidence;
}

export const MAPPING_RULES: MappingRule[] = [
  // ── Input Validation & Injection ─────────────────────────────────────────────
  {
    keywords: ['sql injection', 'sqli'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['cross site scripting', 'xss', 'stored xss', 'reflected xss', 'dom xss'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['command injection', 'os command', 'code injection', 'remote code execution', 'rce'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['path traversal', 'directory traversal', 'lfi', 'local file inclusion', 'rfi', 'remote file inclusion'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['server side request forgery', 'ssrf'],
    controlKeys: ['INPUT_VALIDATION', 'NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['xml injection', 'xxe', 'xml external entity'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['ldap injection', 'nosql injection', 'xpath injection', 'header injection', 'template injection', 'ssti'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['open redirect', 'url redirect', 'unvalidated redirect'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'MEDIUM',
  },
  {
    keywords: ['insecure deserialization', 'deserialization'],
    controlKeys: ['INPUT_VALIDATION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['csrf', 'cross-site request forgery', 'cross site request forgery'],
    controlKeys: ['INPUT_VALIDATION', 'AUTH_CONTROLS'],
    confidence: 'HIGH',
  },

  // ── Authentication & Access Control ──────────────────────────────────────────
  {
    keywords: ['hardcoded secret', 'hardcoded credential', 'hardcoded password', 'hardcoded api key', 'hardcoded token'],
    controlKeys: ['SECRETS_MGMT', 'AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['credential exposure', 'credentials exposed', 'exposed credentials', 'leaked credentials', 'credentials leak'],
    controlKeys: ['SECRETS_MGMT', 'AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['weak password', 'default password', 'password policy', 'password complexity', 'default credentials', 'default credential'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['broken authentication', 'broken auth', 'authentication bypass', 'auth bypass', 'unauth', 'unauthorized admin', 'unauthenticated access'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['missing mfa', 'no mfa', 'multi-factor', 'two factor', '2fa', 'mfa not enforced'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['session fixation', 'session hijacking', 'session management', 'insecure session'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['broken access control', 'bac', 'idor', 'insecure direct object reference', 'privilege escalation', 'unauthorized access'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['jwt', 'json web token', 'token forgery', 'token validation'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'MEDIUM',
  },
  {
    keywords: ['account takeover', 'ato'],
    controlKeys: ['AUTH_CONTROLS'],
    confidence: 'HIGH',
  },

  // ── Secrets Management ────────────────────────────────────────────────────────
  {
    keywords: ['exposed secret', 'secret exposure', 'api key exposed', 'api key in code', 'credentials in code', 'credentials in repository'],
    controlKeys: ['SECRETS_MGMT'],
    confidence: 'HIGH',
  },
  {
    keywords: ['private key exposed', 'rsa key exposed', 'ssh key exposed', 'certificate private key', 'ssh weak key', 'weak ssh key', 'weak key', 'insecure key'],
    controlKeys: ['SECRETS_MGMT', 'ENCRYPTION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['plaintext password', 'password in log', 'password in config'],
    controlKeys: ['SECRETS_MGMT'],
    confidence: 'HIGH',
  },

  // ── Encryption & TLS ──────────────────────────────────────────────────────────
  {
    keywords: ['missing tls', 'no tls', 'missing ssl', 'no ssl', 'http instead of https', 'unencrypted communication', 'outdated tls', 'outdated ssl'],
    controlKeys: ['ENCRYPTION', 'NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['weak cipher', 'insecure cipher', 'deprecated cipher', 'rc4', 'des', 'md5', 'sha1'],
    controlKeys: ['ENCRYPTION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['certificate expired', 'ssl certificate expired', 'tls certificate expired'],
    controlKeys: ['ENCRYPTION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['self-signed certificate', 'untrusted certificate', 'certificate validation'],
    controlKeys: ['ENCRYPTION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['tls 1.0', 'tls 1.1', 'sslv2', 'sslv3', 'old tls', 'weak tls'],
    controlKeys: ['ENCRYPTION', 'NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['data at rest not encrypted', 'unencrypted storage', 'unencrypted database', 'unencrypted disk'],
    controlKeys: ['ENCRYPTION'],
    confidence: 'HIGH',
  },
  {
    keywords: ['hsts missing', 'http strict transport security', 'missing security header'],
    controlKeys: ['ENCRYPTION', 'SECURE_CONFIG'],
    confidence: 'MEDIUM',
  },

  // ── Patch Management ──────────────────────────────────────────────────────────
  {
    keywords: ['missing patch', 'unpatched', 'outdated software', 'end of life', 'eol software', 'end-of-life', 'outdated firmware', 'firmware vulnerability', 'firmware update'],
    controlKeys: ['PATCH_MGMT'],
    confidence: 'HIGH',
  },
  {
    keywords: ['vulnerable package', 'vulnerable library', 'vulnerable component', 'outdated dependency', 'dependency vulnerability'],
    controlKeys: ['PATCH_MGMT'],
    confidence: 'HIGH',
  },
  {
    keywords: ['os vulnerability', 'kernel vulnerability', 'operating system vulnerability'],
    controlKeys: ['PATCH_MGMT'],
    confidence: 'HIGH',
  },
  {
    keywords: ['cve-', 'known vulnerability', 'disclosed vulnerability'],
    controlKeys: ['PATCH_MGMT'],
    confidence: 'MEDIUM',
  },

  // ── Secure Configuration ──────────────────────────────────────────────────────
  {
    keywords: ['misconfiguration', 'insecure configuration', 'default configuration', 'insecure default'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'HIGH',
  },
  {
    keywords: ['debug mode enabled', 'debug endpoint exposed', 'verbose error', 'stack trace exposed', 'error disclosure'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'HIGH',
  },
  {
    keywords: ['directory listing', 'directory browsing'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'HIGH',
  },
  {
    keywords: ['cors misconfiguration', 'cors wildcard', 'permissive cors'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'HIGH',
  },
  {
    keywords: ['content security policy', 'csp missing', 'missing csp'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'MEDIUM',
  },
  {
    keywords: ['clickjacking', 'x-frame-options missing'],
    controlKeys: ['SECURE_CONFIG'],
    confidence: 'HIGH',
  },

  // ── Network Security ──────────────────────────────────────────────────────────
  {
    keywords: ['open port', 'unnecessary port', 'exposed port', 'port exposure', 'unnecessary service', 'management interface', 'exposed management', 'admin interface exposed', 'exposed interface'],
    controlKeys: ['NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['firewall misconfiguration', 'firewall bypass', 'firewall rule'],
    controlKeys: ['NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['network segmentation', 'insufficient segmentation', 'flat network'],
    controlKeys: ['NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['dns misconfiguration', 'dns rebinding', 'dns hijacking'],
    controlKeys: ['NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['man in the middle', 'mitm', 'arp spoofing'],
    controlKeys: ['NETWORK_SECURITY', 'ENCRYPTION'],
    confidence: 'HIGH',
  },

  // ── Cloud Security ────────────────────────────────────────────────────────────
  {
    keywords: ['cloud misconfiguration', 's3 bucket', 'public bucket', 'publicly accessible bucket', 'storage misconfiguration', 'privileged container', 'container privilege', 'privileged pod'],
    controlKeys: ['CLOUD_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['iam misconfiguration', 'iam over-permission', 'excessive iam', 'overly permissive iam', 'iam privilege'],
    controlKeys: ['CLOUD_SECURITY', 'AUTH_CONTROLS'],
    confidence: 'HIGH',
  },
  {
    keywords: ['cloud exposure', 'cloud resource exposed', 'cloud service exposed', 'public cloud resource'],
    controlKeys: ['CLOUD_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['security group', 'security group misconfiguration', 'nacl misconfiguration'],
    controlKeys: ['CLOUD_SECURITY', 'NETWORK_SECURITY'],
    confidence: 'HIGH',
  },
  {
    keywords: ['cloudtrail disabled', 'cloud logging disabled', 'cloud audit log'],
    controlKeys: ['CLOUD_SECURITY', 'LOGGING_MONITORING'],
    confidence: 'HIGH',
  },

  // ── Logging & Monitoring ──────────────────────────────────────────────────────
  {
    keywords: ['logging disabled', 'no logging', 'log disabled', 'insufficient logging'],
    controlKeys: ['LOGGING_MONITORING'],
    confidence: 'HIGH',
  },
  {
    keywords: ['missing audit log', 'audit log disabled', 'audit trail missing'],
    controlKeys: ['LOGGING_MONITORING'],
    confidence: 'HIGH',
  },
  {
    keywords: ['monitoring disabled', 'no monitoring', 'insufficient monitoring', 'alert not configured'],
    controlKeys: ['LOGGING_MONITORING'],
    confidence: 'HIGH',
  },
  {
    keywords: ['sensitive data in log', 'pii in logs', 'password in logs', 'credential in logs'],
    controlKeys: ['LOGGING_MONITORING', 'SECRETS_MGMT'],
    confidence: 'HIGH',
  },

  // ── Asset Management ──────────────────────────────────────────────────────────
  {
    keywords: ['asset inventory', 'undocumented asset', 'unknown asset', 'shadow it', 'unmanaged asset'],
    controlKeys: ['ASSET_MGMT'],
    confidence: 'HIGH',
  },
  {
    keywords: ['end of support', 'unsupported software', 'unsupported os', 'unsupported system'],
    controlKeys: ['ASSET_MGMT', 'PATCH_MGMT'],
    confidence: 'HIGH',
  },
];
