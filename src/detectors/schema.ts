/**
 * Helpers for reasoning about JSON-Schema tool input definitions:
 * walking properties and classifying parameters by risk.
 */

export interface ParamInfo {
  readonly name: string;
  readonly type: string;
  readonly description: string;
  readonly constrained: boolean; // has enum / format / pattern
}

interface JsonSchemaLike {
  type?: string;
  properties?: Record<string, JsonSchemaLike>;
  items?: JsonSchemaLike;
  enum?: unknown[];
  format?: string;
  pattern?: string;
  description?: string;
}

/** Flatten a tool inputSchema's top-level + nested object properties. */
export function extractParams(schema: unknown): ParamInfo[] {
  const s = schema as JsonSchemaLike | undefined;
  if (!s || typeof s !== "object" || !s.properties) return [];
  const out: ParamInfo[] = [];

  const walk = (props: Record<string, JsonSchemaLike>, prefix: string): void => {
    for (const [name, def] of Object.entries(props)) {
      const full = prefix ? `${prefix}.${name}` : name;
      const type = def?.type ?? "unknown";
      out.push({
        name: full,
        type: String(type),
        description: def?.description ?? "",
        constrained: Boolean(def?.enum || def?.format || def?.pattern),
      });
      if (def?.type === "object" && def.properties) walk(def.properties, full);
    }
  };

  walk(s.properties, "");
  return out;
}

const URL_PARAM_RE = /\b(url|uri|href|endpoint|webhook|callback|host|hostname|link|address|fetch|src|target)\b/i;
const CMD_PARAM_RE = /\b(cmd|command|exec|shell|script|bash|sh|run|eval|code|program|args?)\b/i;
// "location" is intentionally excluded. It is far more often a geographic or
// URL locus than a filesystem path, and was a false-positive magnet.
const PATH_PARAM_RE = /\b(path|file|filename|filepath|filePath|dir|directory|folder)\b/i;
const QUERY_PARAM_RE = /\b(query|sql|statement|filter|q)\b/i;

export const isUrlParam = (p: ParamInfo): boolean => URL_PARAM_RE.test(p.name);
export const isCommandParam = (p: ParamInfo): boolean => CMD_PARAM_RE.test(p.name);
export const isPathParam = (p: ParamInfo): boolean => PATH_PARAM_RE.test(p.name);
export const isQueryParam = (p: ParamInfo): boolean => QUERY_PARAM_RE.test(p.name);

const EXEC_DESC_RE = /\b(execute|run|shell|command line|terminal|spawn|subprocess|system call|arbitrary code)\b/i;
export const descriptionSuggestsExec = (text: string): boolean => EXEC_DESC_RE.test(text);
