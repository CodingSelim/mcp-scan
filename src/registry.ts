import type { Check, Finding, ScanContext } from "./types.js";
import { authnCheck } from "./checks/mcp01-auth.js";
import { transportCheck } from "./checks/mcp02-transport.js";
import { toolPoisoningCheck } from "./checks/mcp03-poisoning.js";
import { commandInjectionCheck } from "./checks/mcp04-command-injection.js";
import { ssrfCheck } from "./checks/mcp05-ssrf.js";
import { pathTraversalCheck } from "./checks/mcp06-resource-access.js";
import { secretExposureCheck } from "./checks/mcp07-secrets.js";
import { excessiveScopeCheck } from "./checks/mcp08-permissions.js";

export const ALL_CHECKS: readonly Check[] = [
  secretExposureCheck,
  excessiveScopeCheck,
  toolPoisoningCheck,
  commandInjectionCheck,
  ssrfCheck,
  pathTraversalCheck,
  authnCheck,
  transportCheck,
];

export interface RunChecksOutcome {
  readonly findings: Finding[];
  readonly errors: string[];
}

export async function runChecks(
  ctx: ScanContext,
  checks: readonly Check[] = ALL_CHECKS,
): Promise<RunChecksOutcome> {
  const findings: Finding[] = [];
  const errors: string[] = [];

  for (const check of checks) {
    try {
      findings.push(...(await check.run(ctx)));
    } catch (err) {
      errors.push(`Check ${check.id} (${check.name}) failed: ${(err as Error).message}`);
    }
  }
  return { findings, errors };
}
