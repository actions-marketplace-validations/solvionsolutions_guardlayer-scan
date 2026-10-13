import type {
  Finding,
  Grade,
  GateStatus,
  Rule,
  ScanFile,
  ScanReport,
  Severity,
} from "./types";
import { isScannable, languageOf } from "./helpers";
import { buildScanFilter } from "./ignore";
import { supabaseRules } from "./rules/supabase";
import { nextjsRules } from "./rules/nextjs";
import { generalRules } from "./rules/general";
import { mcpRules } from "./rules/mcp";

export const ENGINE_VERSION = "0.1.0";

export const ALL_RULES: Rule[] = [
  ...supabaseRules,
  ...nextjsRules,
  ...generalRules,
  ...mcpRules,
];

/** Single source of truth for "how many checks GuardLayer runs" — use this in
 *  UI/copy instead of a hardcoded number so adding a rule never leaves a stale
 *  "20 checks" claim anywhere. */
export const RULE_COUNT = ALL_RULES.length;

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  warning: 8,
  info: 2,
};

export interface RunScanOptions {
  /** Optional label for the report (repo/upload name). */
  name?: string;
  /** Pre-generated id (so the caller controls persistence keys). */
  id: string;
  /** Wall-clock now as ISO — passed in because Date.now is constrained in some envs. */
  now: string;
  /** Contents of a `.guardlayerignore` (gitignore syntax) to exclude fixture/
   *  test paths from the scan. Vendor/build dirs are always excluded. */
  ignoreContent?: string | null;
}

/** Resolve a rule match into a full Finding. */
function toFinding(rule: Rule, file: ScanFile, m: {
  line: number;
  column?: number;
  snippet: string;
  message?: string;
  recommendation?: string;
  severity?: Severity;
}): Finding {
  return {
    // Include column + a snippet slice so two distinct matches on the same
    // line (e.g. two different secrets) stay separate findings.
    id: `${rule.id}:${file.path}:${m.line}:${m.column ?? 0}:${(m.snippet || "").slice(0, 32)}`,
    ruleId: rule.id,
    title: rule.title,
    // A rule may lower (or raise) the severity of one match; the finding id
    // does not include it, so a re-graded match keeps its identity.
    severity: m.severity ?? rule.severity,
    category: rule.category,
    message: m.message ?? rule.message,
    recommendation: m.recommendation ?? rule.recommendation,
    cwe: rule.cwe,
    reference: rule.reference,
    file: file.path,
    line: m.line,
    column: m.column,
    snippet: m.snippet,
    aiFix: null,
  };
}

function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/**
 * Core synchronous scan. Pure function over the supplied files — no I/O.
 * Returns a complete ScanReport (without AI enrichment).
 */
/** Hard wall-clock budget for a single scan. A pathological input degrades to
 *  partial results instead of freezing the Node event loop for all users. */
const SCAN_BUDGET_MS = 4000;

export function runScan(files: ScanFile[], opts: RunScanOptions): ScanReport {
  const started = performanceNow();

  const allowed = buildScanFilter(opts.ignoreContent);
  const scannable = files.filter((f) => isScannable(f.path) && allowed(f.path));
  const findings: Finding[] = [];
  const perFileCount = new Map<string, number>();
  const seen = new Set<string>();
  let truncated = false;

  outer: for (const file of scannable) {
    for (const rule of ALL_RULES) {
      // Budget check between rules — caps the blast radius of any one
      // super-linear rule on a hostile input.
      if (performanceNow() - started > SCAN_BUDGET_MS) {
        truncated = true;
        break outer;
      }
      if (rule.appliesTo && !rule.appliesTo(file)) continue;
      let matches;
      try {
        matches = rule.scan(file);
      } catch (err) {
        // A single bad rule must never break a scan.
        console.error(`[scanner] rule ${rule.id} threw on ${file.path}:`, err);
        continue;
      }
      for (const m of matches) {
        if (m.line < 1) continue;
        const finding = toFinding(rule, file, m);
        if (seen.has(finding.id)) continue;
        seen.add(finding.id);
        findings.push(finding);
        perFileCount.set(file.path, (perFileCount.get(file.path) ?? 0) + 1);
      }
    }
  }

  // Order: severity desc, then file, then line.
  const sevRank: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  findings.sort(
    (a, b) =>
      sevRank[a.severity] - sevRank[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line
  );

  const critical = findings.filter((f) => f.severity === "critical").length;
  const warning = findings.filter((f) => f.severity === "warning").length;
  const info = findings.filter((f) => f.severity === "info").length;

  // WHY: the score reflects distinct problems, not raw instance count. One
  // warning rule repeated 149 times is one thing to fix, and must not score
  // the same F as a leaked live key. Each (ruleId, severity) group costs its
  // weight once, +25% per extra instance, capped at 2x. Grouping includes
  // severity because a rule can re-grade single matches. The merge gate uses
  // the counts below, never this score.
  const groups = new Map<string, { severity: Severity; count: number }>();
  for (const f of findings) {
    const key = `${f.ruleId}\u0000${f.severity}`;
    const g = groups.get(key);
    if (g) g.count += 1;
    else groups.set(key, { severity: f.severity, count: 1 });
  }
  let penalty = 0;
  for (const { severity, count } of groups.values()) {
    const w = SEVERITY_WEIGHT[severity];
    penalty += Math.min(2 * w, w + 0.25 * w * (count - 1));
  }
  // Rounded: the 25% steps can be fractional (e.g. 31.25), but score is an
  // int column in public.scans and is shown as "N/100" everywhere.
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const blocked = critical > 0;
  const status: GateStatus = blocked
    ? "block"
    : warning > 0
      ? "warn"
      : "pass";

  const fileList = scannable.map((f) => ({
    path: f.path,
    language: languageOf(f.path),
    findings: perFileCount.get(f.path) ?? 0,
  }));

  return {
    id: opts.id,
    createdAt: opts.now,
    name: opts.name,
    summary: {
      filesScanned: scannable.length,
      totalFindings: findings.length,
      critical,
      warning,
      info,
      score,
      grade: gradeFor(score),
      blocked,
      status,
    },
    findings,
    files: fileList,
    meta: {
      engineVersion: ENGINE_VERSION,
      durationMs: Math.max(0, performanceNow() - started),
      claudeEnriched: false,
      truncated,
    },
  };
}

/** performance.now() with a safe fallback. */
function performanceNow(): number {
  try {
    if (typeof performance !== "undefined" && performance.now) {
      return performance.now();
    }
  } catch {
    /* ignore */
  }
  return 0;
}

export type { ScanFile, ScanReport, Finding, Severity } from "./types";
