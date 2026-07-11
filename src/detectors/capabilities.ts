/**
 * Capability classification for the "lethal trifecta" analysis (Simon
 * Willison's framing): an agent is exploitable when one trust boundary
 * combines access to private data, exposure to untrusted content, and the
 * ability to exfiltrate externally. An MCP server aggregates many tools
 * behind one boundary, so we classify each tool and roll them up.
 *
 * The classification is capability-shaped rather than keyword-matched. A
 * local file write is not exfiltration, and a local file read is not an
 * injection carrier. That distinction is what stops a plain filesystem
 * server from tripping the trifecta while a web-plus-data-plus-send server
 * does.
 */

import type { ToolInfo } from "../types.js";
import { extractParams, isUrlParam, isPathParam, isQueryParam } from "./schema.js";

export interface ToolCapabilities {
  readonly readsPrivate: boolean;
  readonly ingestsUntrusted: boolean;
  readonly exfiltrates: boolean;
}

// A read verb sitting next to a private data-store. Requiring the two within
// 24 characters means an incidental "get your API key at ..." in prose does
// not count as data access, and a web-search "query" does not either.
const PRIVATE_READ =
  /\b(read|get|list|fetch|query|search|load|export|dump|show|view|find|retrieve|download|scan)\b[^.!?\n]{0,24}\b(files?|documents?|emails?|e-mails?|inbox|mailbox|messages?|dms?|chats?|contacts?|calendars?|events?|notes?|notebooks?|databases?|tables?|rows?|records?|repos?|repositor(?:y|ies)|commits?|history|conversations?|drive|sheets?|spreadsheets?|notion|jira|confluence|salesforce|customers?|invoices?|payments?|memory|knowledge base)\b/i;
// A query param only implies private-data access when it targets a datastore.
const DB_QUERY_CONTEXT = /\b(sql|database|\bdb\b|table|schema|dataset|records?)\b/i;

// Signals that a tool pulls in externally-authored (attacker-influenceable) content.
const UNTRUSTED_NOUN =
  /\b(url|uri|http|https|web|website|webpage|page|site|link|internet|browse|browser|scrape|crawl|spider|rss|feed|external|remote|issue|issues|pull request|comment|comments|review|ticket|webhook|inbound)\b/i;
const UNTRUSTED_VERB = /\b(fetch|scrape|crawl|browse|open|download|read|get|load|render|extract)\b/i;

// Verbs that send data somewhere.
const SEND_VERB =
  /\b(send|post|put|upload|publish|share|email|e-?mail|tweet|message|notify|forward|sync|push|submit|dispatch|deliver|transmit|export|write)\b/i;
// Destinations that are external (network), not local.
const EXTERNAL_NOUN =
  /\b(url|uri|http|https|webhook|email|e-?mail|smtp|slack|discord|telegram|teams|sms|api|endpoint|channel|recipient|inbox|remote|s3|bucket|cloud|external)\b/i;

function classify(tool: ToolInfo): ToolCapabilities {
  const hay = `${tool.name} ${tool.description ?? ""}`;
  const params = extractParams(tool.inputSchema);
  const hasUrlParam = params.some(isUrlParam);
  const hasPathParam = params.some(isPathParam);
  const hasQueryParam = params.some(isQueryParam);

  const readsPrivate =
    PRIVATE_READ.test(hay) || hasPathParam || (hasQueryParam && DB_QUERY_CONTEXT.test(hay));

  // Ingestion of untrusted content: a URL/web fetch, or reading externally
  // authored artifacts (issues, comments, emails, feeds).
  const ingestsUntrusted =
    (hasUrlParam && UNTRUSTED_VERB.test(hay)) ||
    (UNTRUSTED_VERB.test(hay) && UNTRUSTED_NOUN.test(hay)) ||
    hasUrlParam; // an arbitrary-URL fetch is the canonical injection carrier

  // External exfiltration: an explicit send to a network destination, or an
  // arbitrary-URL fetch, since data can ride out in the query string of a GET.
  const exfiltrates =
    (SEND_VERB.test(hay) && (EXTERNAL_NOUN.test(hay) || hasUrlParam)) ||
    (hasUrlParam && UNTRUSTED_VERB.test(hay));

  return { readsPrivate, ingestsUntrusted, exfiltrates };
}

export interface ServerCapabilityRollup {
  readonly readsPrivate: string[];
  readonly ingestsUntrusted: string[];
  readonly exfiltrates: string[];
}

/** Roll per-tool capabilities up to the server, tracking which tools contribute each. */
export function rollupCapabilities(tools: readonly ToolInfo[]): ServerCapabilityRollup {
  const readsPrivate: string[] = [];
  const ingestsUntrusted: string[] = [];
  const exfiltrates: string[] = [];
  for (const tool of tools) {
    const c = classify(tool);
    if (c.readsPrivate) readsPrivate.push(tool.name);
    if (c.ingestsUntrusted) ingestsUntrusted.push(tool.name);
    if (c.exfiltrates) exfiltrates.push(tool.name);
  }
  return { readsPrivate, ingestsUntrusted, exfiltrates };
}

export { classify as classifyTool };
