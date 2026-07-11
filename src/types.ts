/**
 * Core domain types for mcp-scan.
 *
 * Everything here is immutable-by-convention: checks return new Finding
 * objects and never mutate the ScanContext they receive.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

/** Numeric weight per severity, used for the aggregate risk score. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

/** OWASP MCP Top 10 (2026) reference ids used to tag findings. */
export type OwaspMcpId =
  | "MCP01" // Missing / broken authentication
  | "MCP02" // Insecure transport
  | "MCP03" // Tool poisoning / description injection
  | "MCP04" // Command / code injection surface
  | "MCP05" // Server-side request forgery (SSRF)
  | "MCP06" // Unrestricted resource / file access
  | "MCP07" // Sensitive data / secret leakage
  | "MCP08"; // Excessive tool permissions

export interface Finding {
  /** Stable check id, e.g. "MCP03". */
  readonly checkId: OwaspMcpId;
  /** Short machine slug for the specific finding, e.g. "tool-description-injection". */
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  /** Human-readable explanation of what was found and why it matters. */
  readonly description: string;
  /** Where it was found: a tool name, resource uri, "server", "transport", etc. */
  readonly location: string;
  /** Concrete remediation guidance. */
  readonly remediation: string;
  /** Optional supporting evidence (matched string, snippet). Truncated for display. */
  readonly evidence?: string;
}

export interface ToolInfo {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
}

export interface PromptInfo {
  readonly name: string;
  readonly description?: string;
  readonly arguments?: ReadonlyArray<{ name: string; description?: string }>;
}

export interface ResourceInfo {
  readonly uri: string;
  readonly name?: string;
  readonly description?: string;
  readonly mimeType?: string;
}

export interface ResourceTemplateInfo {
  readonly uriTemplate: string;
  readonly name?: string;
  readonly description?: string;
}

/** Transport-level facts a check may reason about. */
export interface TransportInfo {
  readonly kind: "stdio" | "http";
  /** For http targets, the raw url string. */
  readonly url?: string;
  /** Whether the server required any credential to complete the handshake. */
  readonly authRequired: boolean;
  /** True when an unauthenticated handshake succeeded against an http target. */
  readonly unauthenticatedHandshakeSucceeded?: boolean;
}

/**
 * Everything a check needs to reason about a target, gathered once during
 * connection so checks stay pure and fast.
 */
export interface ScanContext {
  readonly target: string;
  readonly transport: TransportInfo;
  readonly serverInfo?: { name?: string; version?: string };
  readonly instructions?: string;
  readonly tools: ReadonlyArray<ToolInfo>;
  readonly prompts: ReadonlyArray<PromptInfo>;
  readonly resources: ReadonlyArray<ResourceInfo>;
  readonly resourceTemplates: ReadonlyArray<ResourceTemplateInfo>;
}

/** A single, independently-runnable security check. */
export interface Check {
  readonly id: OwaspMcpId;
  readonly name: string;
  run(ctx: ScanContext): Finding[] | Promise<Finding[]>;
}

export interface ScanResult {
  readonly target: string;
  readonly serverInfo?: { name?: string; version?: string };
  readonly findings: ReadonlyArray<Finding>;
  readonly score: number; // 0-100, higher = worse
  readonly grade: "A" | "B" | "C" | "D" | "F";
  readonly counts: Record<Severity, number>;
  readonly stats: {
    tools: number;
    prompts: number;
    resources: number;
    resourceTemplates: number;
  };
  readonly errors: ReadonlyArray<string>;
}
