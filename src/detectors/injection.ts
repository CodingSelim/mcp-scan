/**
 * Prompt-injection / tool-poisoning heuristics for text found in tool,
 * prompt, and resource descriptions (and server instructions).
 *
 * MCP tool descriptions are fed verbatim into the model's context, so
 * imperative or hidden instructions there are an attack vector ("tool
 * poisoning"). We flag imperative-manipulation phrasing and hidden content.
 */

export interface InjectionSignal {
  readonly rule: string;
  readonly detail: string;
  readonly evidence: string;
}

const IMPERATIVE_PATTERNS: ReadonlyArray<{ rule: string; regex: RegExp; detail: string }> = [
  {
    rule: "instruction-override",
    regex: /\b(ignore|disregard|forget|override)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|system|all)\b/i,
    detail: "Attempts to override prior/system instructions.",
  },
  {
    rule: "exfiltration-directive",
    regex: /\b(send|post|upload|exfiltrate|forward|transmit|leak)\b[^.!?\n]{0,50}\b(to|http|https|url|endpoint|webhook|\.com|api key|token|secret|password|credential|env|environment)\b/i,
    detail: "Directs the assistant to send data to an external destination.",
  },
  {
    rule: "hidden-directive",
    regex: /\b(do not (tell|mention|inform|reveal|disclose)|don't (tell|mention|reveal)|without (telling|informing|notifying|the user)|(secretly|silently|quietly) (send|forward|read|copy|share|transmit|upload|exfiltrate|delete|store|log|record|include)|(send|forward|read|copy|share|transmit|upload|exfiltrate) [^.!?\n]{0,30}(secretly|silently|without the user))\b/i,
    detail: "Instructs the assistant to act without informing the user.",
  },
  {
    rule: "credential-harvest",
    regex: /\b(read|fetch|include|attach|provide|pass)\b[^.!?\n]{0,50}\b(~\/\.|\.ssh|\.aws|\.env|credentials|id_rsa|private key|config file)\b/i,
    detail: "Attempts to pull local credential/config files into tool calls.",
  },
  {
    rule: "assistant-role-injection",
    regex: /<\/?(system|assistant|user)>|\[(system|assistant|inst)\]|\bIMPORTANT:\s*(you must|always|before using)/i,
    detail: "Embeds fake role markers or coercive 'IMPORTANT' directives.",
  },
];

// Zero-width / invisible characters commonly used to hide instructions.
const INVISIBLE_RE = /[​-‏‪-‮⁠-⁤﻿­]/;
// Unicode tag characters (E0000-E007F) — an established covert-instruction channel.
const UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/u;

export function detectInjection(text: string | undefined): InjectionSignal[] {
  if (!text) return [];
  const out: InjectionSignal[] = [];

  for (const { rule, regex, detail } of IMPERATIVE_PATTERNS) {
    const m = regex.exec(text);
    if (m) out.push({ rule, detail, evidence: snippet(text, m.index) });
  }

  if (INVISIBLE_RE.test(text)) {
    out.push({
      rule: "hidden-unicode",
      detail: "Contains zero-width or bidi control characters that can hide instructions from human review.",
      evidence: "<invisible unicode characters present>",
    });
  }
  if (UNICODE_TAG_RE.test(text)) {
    out.push({
      rule: "unicode-tag-smuggling",
      detail: "Contains Unicode Tag block characters used to smuggle covert instructions.",
      evidence: "<unicode tag characters present>",
    });
  }

  return out;
}

function snippet(text: string, index: number): string {
  const start = Math.max(0, index - 10);
  const end = Math.min(text.length, index + 90);
  const s = text.slice(start, end).replace(/\s+/g, " ").trim();
  return (start > 0 ? "…" : "") + s + (end < text.length ? "…" : "");
}
