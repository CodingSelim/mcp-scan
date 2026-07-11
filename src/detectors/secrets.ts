/**
 * Secret detection: high-signal provider token patterns plus a
 * generic high-entropy fallback. Kept conservative to limit false positives.
 */

export interface SecretMatch {
  readonly kind: string;
  readonly match: string;
}

interface SecretPattern {
  readonly kind: string;
  readonly regex: RegExp;
}

const PATTERNS: readonly SecretPattern[] = [
  { kind: "AWS Access Key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "GitHub Token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { kind: "GitLab Token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "OpenAI Key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { kind: "Anthropic Key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "Slack Token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "Slack Webhook", regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_-]+\/B[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+/g },
  { kind: "Google API Key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: "Google OAuth Secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "Stripe Key", regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: "SendGrid Key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { kind: "Twilio Key", regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { kind: "npm Token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: "Hugging Face Token", regex: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { kind: "JWT", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { kind: "Private Key Block", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  {
    kind: "Database Connection String",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+/gi,
  },
  {
    kind: "Generic Secret Assignment",
    regex:
      /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)\b\s*[:=]\s*["']?([A-Za-z0-9_\-./+]{8,})["']?/gi,
  },
];

// URL-ish / path-ish tokens: high-entropy by nature, but not secrets.
const URLISH = /:\/\/|^(?:https?|ftp|ws|wss|file):|^www\.|\.[a-z]{2,5}(?:[/?#]|$)|^[~./]/i;

/** Shannon entropy in bits/char. */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// A credential is drawn from a machine charset (base64/hex/url-safe). Natural
// language — especially CJK/other non-Latin scripts — is also high-entropy per
// char but is NOT a secret, so require the token to be secret-shaped first.
const SECRET_CHARSET = /^[A-Za-z0-9_\-./+=~]+$/;

/** A long, high-entropy, machine-charset token is a likely secret even without a known prefix. */
export function looksHighEntropy(token: string): boolean {
  return token.length >= 24 && SECRET_CHARSET.test(token) && shannonEntropy(token) >= 4.0;
}

function redact(secret: string): string {
  if (secret.length <= 8) return "****";
  return `${secret.slice(0, 4)}…${secret.slice(-2)}`;
}

/** Find secrets in an arbitrary text blob. Returns redacted evidence. */
export function detectSecrets(text: string): SecretMatch[] {
  if (!text) return [];
  const out: SecretMatch[] = [];
  const seen = new Set<string>();

  for (const { kind, regex } of PATTERNS) {
    // Fresh lastIndex each call since patterns are global.
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      const raw = m[0];
      const key = `${kind}:${raw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ kind, match: redact(raw) });
    }
  }

  // Generic high-entropy fallback over whitespace/quote-delimited tokens.
  for (const token of text.split(/[\s"'`,;()<>{}\[\]]+/)) {
    if (!looksHighEntropy(token)) continue;
    if (URLISH.test(token)) continue; // URLs/paths are high-entropy but not secrets
    const key = `entropy:${token}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ kind: "High-Entropy String", match: redact(token) });
  }

  return out;
}
