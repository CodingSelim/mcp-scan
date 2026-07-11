import type { Check, Finding, ScanContext } from "../types.js";

// Version strings that are absent, mutable, or a placeholder — nothing you
// can pin or verify against a registry artifact.
const UNPINNED_VERSION = /^(|0\.0\.0|latest|dev|development|unknown|snapshot|nightly|main|master)$/i;
// Non-ASCII letters in a server name: a classic homoglyph impersonation trick
// (e.g. Cyrillic 'а' standing in for Latin 'a').
const NON_ASCII_LETTER = /[^\x00-\x7F]/;

/**
 * Supply-chain & integrity signals — OWASP MCP04.
 *
 * A passive scanner can't verify a package registry, but the server's own
 * self-reported identity carries integrity signals: an unpinned/placeholder
 * version can't be pinned or verified, and a homoglyph in the server name is
 * a hallmark of a shadow / impersonation server.
 */
export const supplyChainCheck: Check = {
  id: "supply-chain",
  name: "Supply-chain & integrity signals",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const info = ctx.serverInfo;
    if (!info) return findings; // nothing self-reported to reason about

    const version = (info.version ?? "").trim();
    if (UNPINNED_VERSION.test(version)) {
      findings.push({
        category: "supply-chain",
        owasp: "MCP04",
        rule: "unpinned-version",
        severity: "low",
        title: "Server reports no pinned version",
        description: `The server advertises version "${version || "(none)"}", which can't be pinned or verified against a published artifact. Without a stable version, you can't detect a tampered or silently-swapped server between sessions.`,
        location: "server",
        remediation:
          "Publish and report an immutable semantic version, pin it in your MCP config, and verify the artifact hash on install.",
        evidence: `name=${info.name ?? "?"} version=${version || "(none)"}`,
      });
    }

    if (info.name && NON_ASCII_LETTER.test(info.name)) {
      findings.push({
        category: "supply-chain",
        owasp: "MCP09",
        rule: "homoglyph-server-name",
        severity: "medium",
        title: "Server name contains non-ASCII look-alike characters",
        description:
          "The server's advertised name contains non-ASCII characters that can visually impersonate a trusted server (homoglyph attack). A user comparing names by eye may connect to a shadow server believing it is the real one.",
        location: "server",
        remediation:
          "Verify the exact byte-level identity of the server you connect to; reject names containing mixed scripts or non-ASCII homoglyphs.",
        evidence: `name=${JSON.stringify(info.name)}`,
      });
    }

    return findings;
  },
};
