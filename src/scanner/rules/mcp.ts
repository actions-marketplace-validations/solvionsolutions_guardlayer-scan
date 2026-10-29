import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  looksLikePlaceholder,
  matchAll,
  matchLines,
  lineAt,
  columnAt,
  snippetAt,
} from "../helpers";

/**
 * MCP / AI-agent config rules.
 *
 * The big agent footgun is the "lethal trifecta": an agent that has (1) access
 * to private data, (2) exposure to untrusted input, and (3) a way to act/
 * exfiltrate. Statically we can catch (1) — an over-privileged agent — and the
 * secrets people routinely commit into agent config files.
 */

/** A known MCP config filename, or any JSON/YAML that declares an `mcpServers`
 *  block (the canonical MCP key used by Claude Desktop, Cursor, Cline, etc.). */
const MCP_FILE =
  /(^|[/\\])(\.?mcp(?:[._-]?config)?\.json|claude_desktop_config\.json|mcp[._-]?servers?\.json|cline_mcp_settings\.json)$/i;

const isMcpConfig = (f: ScanFile) =>
  MCP_FILE.test(f.path) ||
  (/\.(jsonc?|ya?ml)$/i.test(f.path) && /["']?mcpServers["']?\s*:/.test(f.content));

const DB_URL_WITH_PW =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|mssql|sqlserver):\/\/[^:@\s/"']+:([^@\s/"']+)@/gi;

/** A CLI flag whose VALUE is a credential. Anchoring on the flag name — never on
 *  the value's entropy — is what keeps the args rule precise. */
const SECRET_FLAG =
  /^--?((?:[a-z0-9]+[-_])?(?:api[-_]?key|apikey|auth[-_]?token|access[-_]?token|token|secret|password|passwd|key))(?:=([\s\S]*))?$/i;
/** A flag whose value is public by definition — `--public-key` is not a leak. */
const PUBLIC_FLAG = /public/i;
/** A path, not a secret: `--key-file ./certs/client.pem`. The single biggest
 *  false-positive source for a `--key`-style flag. */
const PATHISH = /[\/\\]|\.(pem|key|crt|cer|json|env|p12|pfx|txt)$/i;
/** `${VAR}` / `$VAR` / `%VAR%` — an environment reference is the CORRECT
 *  pattern and must never be flagged. */
const ENV_REF = /^[$%{]/;
/** Provider-format secrets already owned by general/hardcoded-secret. */
const PROVIDER_FORMAT =
  /^(sk-|sk_live_|rk_live_|gh[opusr]_|github_pat_|AKIA|AIza|xox[baprs]-|SG\.|sb_secret_)/;
/** Public-by-design key prefixes. */
const PUBLIC_PREFIX = /^(pk_|sb_publishable_|pub_)/;

/** A GitHub Actions workflow file. */
const IS_WORKFLOW = /\.github[\/\\]workflows[\/\\][^\/\\]+\.ya?ml$/i;

/** Vendor AI coding-agent actions. An explicit, verified allow-list — NOT a
 *  fuzzy match on "ai"/"agent" — so a workflow running none of these exits
 *  immediately and the false-positive surface stays limited to repos that
 *  actually run an agent in CI. */
const AGENT_ACTION =
  /uses:\s*["']?(?:anthropics\/claude-code-action|google-github-actions\/run-gemini-cli|openai\/codex-action)\b/i;

/** Workflow events an unprivileged member of the public can raise. `pull_request`
 *  is deliberately EXCLUDED: fork pull requests do not receive secrets, so it
 *  does not carry the same risk. */
const UNTRUSTED_TRIGGER =
  /^\s{0,8}(?:-\s*)?(?:issue_comment|issues|pull_request_target)\s*:?\s*$|\bon\s*:\s*(?:\[[^\]\n]{0,160})?\b(?:issue_comment|issues|pull_request_target)\b/m;

/** Indicators of compromise for KNOWN-malicious MCP servers. Exact, published
 *  IOCs only — never heuristics — so a hit is never a false positive.
 *  Deadbugz (Pillar Security, 2026-08-12): a "productivity-suite" MCP server
 *  added to repos via drive-by pull requests (23 PRs in 74 minutes) that, after
 *  three tool calls, instructs the agent to hunt for SSH keys, AWS credentials,
 *  shell history and Kubernetes config. */
const MALICIOUS_MCP_IOCS: { re: RegExp; campaign: string; source: string }[] = [
  {
    re: /productivity-suite-mcp\.onrender\.com|promo-surname-xml-quantum\.trycloudflare\.com|\.deadbug-mcp\.py\b|zellkernel\/productivity-suite-mcp/gi,
    campaign: "Deadbugz",
    source:
      "https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign",
  },
];

/** Supabase MCP feature groups that can CHANGE something. If a server is
 *  explicitly limited to feature groups outside this set (e.g. docs only), it
 *  has no write capability and must not be flagged as "not read-only". */
const SUPABASE_MUTATING_FEATURES = /\b(database|functions|storage|branching|account)\b/i;

/** A restriction on WHO may trigger the job — the documented mitigation. */
const ACTOR_GATE =
  /author_association|github\.actor\s*[=!]=|contains\s*\(\s*fromJSON|\bpermission\s*==\s*['"](?:admin|write)['"]/i;

export const mcpRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — service_role key handed to an AI agent (the lethal trifecta)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/service-role-in-config",
    title: "service_role key exposed to an AI agent",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-269",
    message:
      "An MCP server / AI agent is configured with the Supabase service_role key, which bypasses Row Level Security. An agent that also sees untrusted input (the 'lethal trifecta') can be prompt-injected into reading or modifying your entire database.",
    recommendation:
      "Never hand an agent the service_role key. Give it a scoped key / a dedicated DB role with RLS enforced, and put any privileged action behind a narrow tool the agent can't be tricked into calling with arbitrary arguments.",
    appliesTo: isMcpConfig,
    scan: (f) => matchAll(f, /SUPABASE_SERVICE_ROLE_KEY|\bservice_role\b/gi),
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — a secret hardcoded into an agent config file
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/secret-in-config",
    title: "Hardcoded secret in an MCP / agent config",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-798",
    message:
      "A credential is hardcoded in an MCP server / AI-agent config. These files get committed, so the value is exposed to anyone with repo access — and to the agent itself.",
    recommendation:
      "Reference the value from an environment variable instead (e.g. \"env\": { \"X\": \"${X}\" }), keep the real secret in an untracked .env, and rotate anything already committed.",
    appliesTo: isMcpConfig,
    scan: (f) => {
      const out: RuleMatch[] = [];

      // (a) a database connection string with an inline password
      const re = new RegExp(DB_URL_WITH_PW.source, "gi");
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(f.content)) !== null) {
        if (++guard > 1000) break;
        const pw = m[1];
        if (looksLikePlaceholder(pw) || pw.length < 4) continue;
        if (/^[$%{]/.test(pw)) continue; // ${VAR} / %VAR% reference, not hardcoded
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: "Database connection string with an inline password.",
        });
      }

      // (b) a credential-named field assigned a hardcoded literal value
      out.push(
        ...matchLines(f, (line) => {
          // Keys general/assigned-secret-literal already covers (secret/token/
          // password/api_key) are left to that rule — we catch the gaps it
          // misses in agent configs: *_key, PAT, credentials, DSN.
          const mm = line.match(
            /["']?([A-Za-z0-9_]*(?:[_-]key|pat|credentials?|dsn))["']?\s*:\s*["']([^"']{12,})["']/i
          );
          if (!mm) return null;
          const value = mm[2];
          if (looksLikePlaceholder(value)) return null;
          if (/\s/.test(value)) return null; // prose / help text, not a token
          if (/^[$%{]/.test(value)) return null; // ${VAR} reference
          if (/^(pk_|sb_publishable_|pub_)/.test(value)) return null; // public keys
          // Provider-format secrets are caught by general/hardcoded-secret — don't
          // double-flag them here.
          if (/^(sk-|sk_live_|rk_live_|gh[opusr]_|github_pat_|AKIA|AIza|xox[baprs]-|SG\.|sb_secret_)/.test(value)) {
            return null;
          }
          // Require some entropy so a plain word isn't flagged.
          if (!/[0-9]/.test(value) && !/[A-Z]/.test(value) && value.length < 24) {
            return null;
          }
          return {
            column: (mm.index ?? 0) + 1,
            message: `Hardcoded credential assigned to "${mm[1]}".`,
          };
        })
      );

      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — a secret passed to an MCP server as a COMMAND-LINE ARGUMENT
  // (the sibling rule above only sees the `env` object form)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/secret-in-args",
    title: "Hardcoded secret in MCP server arguments",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-798",
    message:
      "An MCP server is launched with a credential passed directly as a command-line argument. Quickstart docs routinely show keys inline in `args`, so these configs get committed — exposing the value to anyone with repo access, and to the agent itself.",
    recommendation:
      'Pass the value by environment reference instead (e.g. "env": { "API_KEY": "${API_KEY}" }, or --api-key "${API_KEY}"), keep the real secret in an untracked .env, and rotate anything already committed.',
    appliesTo: isMcpConfig,
    scan: (f) => {
      // JSON only — a YAML MCP config would need a real parser, and guessing is
      // how a precise rule turns noisy.
      if (!/\.jsonc?$/i.test(f.path)) return [];
      let cfg: { mcpServers?: Record<string, unknown> };
      try {
        cfg = JSON.parse(f.content);
      } catch {
        return [];
      }
      const servers = cfg?.mcpServers;
      if (!servers || typeof servers !== "object") return [];
      const out: RuleMatch[] = [];
      for (const [name, entry] of Object.entries(servers)) {
        if (name === "__proto__") continue;
        const args = (entry as { args?: unknown })?.args;
        if (!Array.isArray(args)) continue;
        for (let i = 0; i < args.length; i++) {
          const a = args[i];
          if (typeof a !== "string") continue;
          const fm = SECRET_FLAG.exec(a);
          if (!fm) continue;
          if (PUBLIC_FLAG.test(fm[1])) continue; // --public-key et al
          // `--token=value` carries its own value; `--token value` takes the next.
          const value = fm[2] !== undefined ? fm[2] : args[i + 1];
          if (typeof value !== "string" || value.length < 12) continue;
          if (ENV_REF.test(value)) continue; // ${VAR} — the correct pattern
          if (PATHISH.test(value)) continue; // --key-file ./certs/x.pem
          if (looksLikePlaceholder(value)) continue;
          if (PUBLIC_PREFIX.test(value)) continue;
          if (PROVIDER_FORMAT.test(value)) continue; // general/hardcoded-secret owns these
          // Require credential-like structure, not a plain word.
          if (!/[0-9]/.test(value) && !/[A-Z]/.test(value) && value.length < 24) {
            continue;
          }
          const idx = f.content.indexOf(value);
          out.push({
            line: idx >= 0 ? lineAt(f.content, idx) : 1,
            column: idx >= 0 ? columnAt(f.content, idx) : undefined,
            snippet: idx >= 0 ? snippetAt(f.content, idx) : a,
            message: `MCP server "${name}" passes a hardcoded credential as a command-line argument (${fm[1]}).`,
          });
        }
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — Supabase MCP server without the read-only blast-radius control
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/supabase-agent-not-read-only",
    title: "Supabase MCP server without read-only mode",
    severity: "warning",
    category: "mcp",
    cwe: "CWE-269",
    message:
      "An MCP server connects an AI agent to Supabase with write access — read-only mode is not enabled. Supabase recommends read-only by default: it disables every mutating tool and runs execute_sql as a read-only Postgres user. Without it, the agent can run arbitrary DDL/DML. This flags the missing restriction in your CONFIG; it does not detect prompt injection or how the agent behaves at runtime.",
    recommendation:
      "Add the --read-only flag (or read_only=true) to the Supabase MCP server, and scope it to a single project with --project-ref so a mistake cannot reach your other projects.",
    reference:
      "https://supabase.com/docs/guides/observability/automate-with-agents",
    appliesTo: isMcpConfig,
    scan: (f) => {
      if (!/\.jsonc?$/i.test(f.path)) return [];
      let cfg: { mcpServers?: Record<string, unknown> };
      try {
        cfg = JSON.parse(f.content);
      } catch {
        return [];
      }
      const servers = cfg?.mcpServers;
      if (!servers || typeof servers !== "object") return [];
      const out: RuleMatch[] = [];
      for (const [name, entry] of Object.entries(servers)) {
        if (name === "__proto__") continue;
        const blob = JSON.stringify(entry ?? null);
        // Identify the Supabase server POSITIVELY — never by the config key name,
        // which the user picks freely.
        if (!/mcp\.supabase\.com|@supabase\/mcp-server-supabase/i.test(blob)) {
          continue;
        }
        // Note `read_only=false` must NOT suppress — only an explicit true does.
        if (/read_only\s*=\s*true|"read_?only"\s*:\s*true|--read-only\b/i.test(blob)) {
          continue;
        }
        // Explicitly limited to non-mutating feature groups (e.g.
        // `?features=docs` or `--features=docs,debugging`) -> no write capability.
        const features = /(?:[?&]|--)features[=\s"',]+([a-z_,\s]+)/i.exec(blob);
        if (features && !SUPABASE_MUTATING_FEATURES.test(features[1])) continue;
        const idx = f.content.indexOf(`"${name}"`);
        out.push({
          line: idx >= 0 ? lineAt(f.content, idx) : 1,
          snippet: idx >= 0 ? snippetAt(f.content, idx) : `"${name}"`,
          message: `MCP server "${name}" connects to Supabase with write access (no read-only restriction).`,
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — AI coding agent in CI, startable by any member of the public
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/agent-workflow-untrusted-trigger",
    title: "AI agent workflow triggerable by anyone",
    severity: "warning",
    category: "mcp",
    cwe: "CWE-269",
    message:
      "This workflow runs an AI coding agent on an event any GitHub user can raise (an issue, an issue comment, or pull_request_target), with no restriction on who may trigger it. The job holds the repository token and your provider secrets, so anyone on the internet can start it. This flags the workflow CONFIGURATION — it does not detect prompt injection or what the agent does at runtime.",
    recommendation:
      "Gate the job on the actor, e.g. if: github.event.comment.author_association == 'OWNER' (or MEMBER / COLLABORATOR). Keep permissions least-privilege, and prefer a manual workflow_dispatch trigger for anything that can write to the repository.",
    reference:
      "https://www.microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case/",
    appliesTo: (f) => IS_WORKFLOW.test(f.path),
    scan: (f) => {
      // Precision anchor first: no known agent action -> not our business.
      const agent = AGENT_ACTION.exec(f.content);
      if (!agent) return [];
      if (!UNTRUSTED_TRIGGER.test(f.content)) return [];
      if (ACTOR_GATE.test(f.content)) return []; // documented mitigation present
      return [
        {
          line: lineAt(f.content, agent.index),
          column: columnAt(f.content, agent.index),
          snippet: snippetAt(f.content, agent.index),
        },
      ];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — agent config references a KNOWN-malicious MCP server (exact IOC)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "mcp/known-malicious-server",
    title: "Known-malicious MCP server in agent config",
    severity: "critical",
    category: "mcp",
    cwe: "CWE-506",
    message:
      "This agent config references an MCP server that matches a published indicator of compromise for an active supply-chain campaign. Configs like this are being added to repositories through drive-by pull requests. Note: this is an exact match against known IOCs — GuardLayer does not (and statically cannot) detect malicious MCP servers in general.",
    recommendation:
      "Remove the server from the config and do not merge the change that added it. If an agent has already run with it, treat the machine as compromised: rotate SSH keys, cloud (AWS) credentials, Kubernetes configs and any tokens in shell history, then review what the agent executed.",
    appliesTo: (f) =>
      isMcpConfig(f) ||
      (/\.toml$/i.test(f.path) && /^\s*\[mcp_servers[.\]]/m.test(f.content)),
    scan: (f) => {
      const out: RuleMatch[] = [];
      for (const ioc of MALICIOUS_MCP_IOCS) {
        out.push(
          ...matchAll(f, ioc.re, () => ({
            message: `Matches a published indicator of compromise for the ${ioc.campaign} malicious MCP server campaign (${ioc.source}).`,
          }))
        );
      }
      return out;
    },
  },
];
