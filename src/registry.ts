import type { Check, Finding, ScanContext } from "./types.js";
import { mcp01Auth } from "./checks/mcp01-auth.js";
import { mcp02Transport } from "./checks/mcp02-transport.js";
import { mcp03Poisoning } from "./checks/mcp03-poisoning.js";
import { mcp04CommandInjection } from "./checks/mcp04-command-injection.js";
import { mcp05Ssrf } from "./checks/mcp05-ssrf.js";
import { mcp06ResourceAccess } from "./checks/mcp06-resource-access.js";
import { mcp07Secrets } from "./checks/mcp07-secrets.js";
import { mcp08Permissions } from "./checks/mcp08-permissions.js";

/** All checks, in reporting order. */
export const ALL_CHECKS: readonly Check[] = [
  mcp01Auth,
  mcp02Transport,
  mcp03Poisoning,
  mcp04CommandInjection,
  mcp05Ssrf,
  mcp06ResourceAccess,
  mcp07Secrets,
  mcp08Permissions,
];

export interface RunChecksOutcome {
  readonly findings: Finding[];
  readonly errors: string[];
}

/**
 * Run every check in isolation. A check that throws is recorded as an error
 * but never aborts the scan.
 */
export async function runChecks(
  ctx: ScanContext,
  checks: readonly Check[] = ALL_CHECKS,
): Promise<RunChecksOutcome> {
  const findings: Finding[] = [];
  const errors: string[] = [];

  for (const check of checks) {
    try {
      const result = await check.run(ctx);
      findings.push(...result);
    } catch (err) {
      errors.push(`Check ${check.id} (${check.name}) failed: ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}
