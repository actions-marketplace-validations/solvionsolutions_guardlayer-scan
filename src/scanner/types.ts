/**
 * GuardLayer scanner — shared types.
 *
 * Severities mirror the product spec (KRITISK / VARNING / INFO):
 *   - "critical": blocks merge / deploy
 *   - "warning":  should fix, does not block
 *   - "info":     advisory, low confidence or low impact
 */

export type Severity = "critical" | "warning" | "info";

export type Category = "supabase" | "nextjs" | "general" | "mcp";

/** A file submitted for scanning. */
export interface ScanFile {
  /** Relative path, e.g. "app/api/users/route.ts". */
  path: string;
  /** Raw file contents. */
  content: string;
}

/** A single match a rule produced inside a file. */
export interface RuleMatch {
  line: number; // 1-based
  column?: number; // 1-based
  snippet: string; // the offending line (trimmed, capped)
  /** Optional per-match overrides of the rule defaults. */
  message?: string;
  recommendation?: string;
  /** Resolved in toFinding only; everything downstream reads finding.severity. */
  severity?: Severity;
}

/** A scanning rule. */
export interface Rule {
  id: string; // e.g. "supabase/service-role-in-public-env"
  title: string; // short human label
  severity: Severity;
  category: Category;
  /** Why this matters / how to fix — default for every match. */
  message: string;
  recommendation: string;
  cwe?: string; // e.g. "CWE-798"
  reference?: string; // doc link
  /** Restrict the rule to relevant files (extension/path). */
  appliesTo?: (file: ScanFile) => boolean;
  /** Produce matches for a single file. */
  scan: (file: ScanFile) => RuleMatch[];
}

/** A concrete finding (a rule match, resolved against the rule). */
export interface Finding {
  id: string; // stable: ruleId + file + line
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  message: string;
  recommendation: string;
  cwe?: string;
  reference?: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  /** Optional Claude-generated explanation + fix (when configured). */
  aiFix?: { explanation: string; fix: string } | null;
}

export type Grade = "A" | "B" | "C" | "D" | "F";
export type GateStatus = "pass" | "warn" | "block";

export interface ScanReport {
  id: string;
  createdAt: string; // ISO
  name?: string; // optional label (e.g. repo or upload name)
  summary: {
    filesScanned: number;
    totalFindings: number;
    critical: number;
    warning: number;
    info: number;
    score: number; // 0-100
    grade: Grade;
    blocked: boolean; // any critical finding
    status: GateStatus;
  };
  findings: Finding[];
  files: { path: string; language: string; findings: number }[];
  meta: {
    engineVersion: string;
    durationMs: number;
    claudeEnriched: boolean;
    /** True when results are partial: the scan hit its wall-clock budget, or
     *  (full-repo scans) GitHub truncated the tree, the file cap was hit, or a
     *  file couldn't be read. */
    truncated?: boolean;
  };
}
