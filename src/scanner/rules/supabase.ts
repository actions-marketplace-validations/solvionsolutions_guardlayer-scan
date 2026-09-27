import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  isClientComponent,
  isEdgeFunction,
  isSql,
  matchAll,
  matchLines,
  snippetAt,
  lineAt,
  columnAt,
  stripSqlComments,
  sqlStatementEnd,
} from "../helpers";

const isJsLike = (f: ScanFile) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path);

// Postgres schemas Supabase manages internally — not exposed via PostgREST.
const INTERNAL_SCHEMAS = new Set([
  "auth",
  "storage",
  "extensions",
  "graphql",
  "graphql_public",
  "realtime",
  "vault",
  "pgsodium",
  "supabase_functions",
  "net",
  "cron",
]);

const unquote = (s: string) => s.replace(/["']/g, "").toLowerCase();

export const supabaseRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — service role key shipped to the client via NEXT_PUBLIC_
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/service-role-in-public-env",
    title: "Service role key exposed to the client",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-200",
    message:
      "A Supabase service_role key is referenced through a NEXT_PUBLIC_ variable. NEXT_PUBLIC_ values are inlined into the browser bundle, so this key — which bypasses every RLS policy — would be public.",
    recommendation:
      "Never prefix the service role key with NEXT_PUBLIC_. Read it only in server code via process.env.SUPABASE_SERVICE_ROLE_KEY, and rotate the key immediately since it has been exposed.",
    appliesTo: (f) => isJsLike(f) || /\.env/.test(f.path),
    scan: (f) =>
      matchAll(
        f,
        /NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SERVICE_KEY|SECRET)[A-Z0-9_]*/g
      ),
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — service role key used inside a client component
  // (line-level comment skip so a defensive comment isn't flagged)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/service-role-key-in-client",
    title: "Service role key used in client-side code",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-200",
    message:
      "The Supabase service_role key is referenced in a file that runs in the browser. The service role bypasses Row Level Security and must never leave the server.",
    recommendation:
      "Move all service-role usage into a server context (Route Handler, Server Action, or server-only module). On the client use only the anon key, protected by RLS.",
    appliesTo: (f) => isJsLike(f),
    scan: (f) => {
      if (!isClientComponent(f.content)) return [];
      return matchLines(f, (line) => {
        const idx = line.search(/SUPABASE_SERVICE_ROLE_KEY|service[_-]?role[_-]?key/i);
        if (idx === -1) return null;
        const trimmed = line.trim();
        // Skip comment lines / JSDoc that merely mention the term.
        if (
          trimmed.startsWith("//") ||
          trimmed.startsWith("*") ||
          trimmed.startsWith("/*")
        ) {
          return null;
        }
        const commentIdx = line.indexOf("//");
        if (commentIdx !== -1 && commentIdx < idx) return null; // match is inside a trailing comment
        return { column: idx + 1 };
      });
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — hardcoded service_role JWT
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/service-role-jwt-literal",
    title: "Hardcoded service_role JWT",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-798",
    message:
      'A literal JWT whose payload contains "service_role" is embedded in source. Anyone with this token has full, RLS-bypassing access to the database.',
    recommendation:
      "Remove the token from source, load it from a server-side environment variable, and rotate the key in the Supabase dashboard.",
    scan: (f) =>
      matchAll(
        f,
        /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]*(c2VydmljZV9yb2xl|service_role)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{6,}/g
      ),
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — public storage bucket (JS API + SQL migration)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/public-storage-bucket",
    title: "Public storage bucket",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-732",
    message:
      "A storage bucket is created or updated as public. Every object in a public bucket is readable by anyone with the URL, with no authentication.",
    recommendation:
      "Set public: false and serve files through signed URLs (createSignedUrl) or RLS-protected access. Only keep a bucket public for genuinely public assets.",
    appliesTo: (f) => isJsLike(f) || isSql(f.path),
    scan: (f) => {
      if (isSql(f.path)) {
        const out: RuleMatch[] = [];
        // insert into storage.buckets (..., public) values (..., true)
        out.push(
          ...matchAll(
            f,
            /insert\s+into\s+storage\.buckets\b[\s\S]{0,400}?\btrue\b/gi
          )
        );
        // update storage.buckets set public = true
        out.push(
          ...matchAll(
            f,
            /update\s+storage\.buckets\s+set\b[\s\S]{0,160}?\bpublic\b\s*=\s*true/gi
          )
        );
        return out;
      }
      return matchAll(
        f,
        /(?:createBucket|updateBucket)\s*\(\s*[^)]*?public\s*:\s*true/g
      );
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — RLS explicitly disabled
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/rls-explicitly-disabled",
    title: "Row Level Security disabled",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-285",
    message:
      "A table has Row Level Security turned OFF. With RLS disabled, the anon and authenticated roles can read and write every row in the table.",
    recommendation:
      "Re-enable RLS (ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;) and add policies that scope access with auth.uid().",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => matchAll(f, /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi),
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — public table created without enabling RLS (schema/quote aware)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/rls-missing-on-table",
    title: "Table created without enabling RLS",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-285",
    message:
      "A public table is created but RLS is never enabled for it in this migration. This is the exact gap behind the largest study of its kind: UpGuard found 16,326 Supabase databases exposing readable tables to the open web (2026-09-25), over half showing signs of personal data. Tables created through the Supabase Dashboard get RLS enabled by default — tables created with SQL do NOT, and AI coding agents create tables with SQL. Without RLS, an exposed table can be read and written by anyone holding the public anon key.",
    recommendation:
      "Add ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; plus access policies right after the CREATE TABLE. If RLS is enabled in a different migration file, this warning is expected — the scanner reads one file at a time and cannot see it.",
    reference:
      "https://techcrunch.com/2026/09/25/some-supabase-customers-are-publicly-exposing-reams-of-peoples-data-to-the-web/",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      const matches: RuleMatch[] = [];
      // Tables that DO get RLS enabled, keyed schema.table (quote-tolerant).
      const enabled = new Set<string>();
      const alterRe =
        /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
      let am: RegExpExecArray | null;
      while ((am = alterRe.exec(f.content)) !== null) {
        const schema = am[1] ? unquote(am[1]) : "public";
        const table = unquote(am[2]);
        enabled.add(`${schema}.${table}`);
      }

      const createRe =
        /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)/gi;
      let cm: RegExpExecArray | null;
      while ((cm = createRe.exec(f.content)) !== null) {
        const schema = cm[1] ? unquote(cm[1]) : "public";
        const table = unquote(cm[2]);
        if (schema !== "public") continue; // non-public schemas aren't exposed
        if (INTERNAL_SCHEMAS.has(schema)) continue;
        if (table.startsWith("_")) continue;
        if (!enabled.has(`${schema}.${table}`)) {
          matches.push({
            line: lineAt(f.content, cm.index),
            snippet: snippetAt(f.content, cm.index),
            message: `Table "${table}" is created but RLS is never enabled for it in this file.`,
          });
        }
      }
      return matches;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — overly permissive policy (USING (true) / WITH CHECK (true))
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/policy-using-true",
    title: "Overly permissive RLS policy",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-285",
    message:
      "An RLS policy uses USING (true) / WITH CHECK (true), which grants access to every row regardless of who is asking — effectively no protection.",
    recommendation:
      "Scope the policy to the requesting user, e.g. USING (auth.uid() = user_id). Reserve (true) for genuinely public, read-only data.",
    appliesTo: (f) => isSql(f.path),
    scan: (f) =>
      matchAll(
        f,
        /CREATE\s+POLICY[\s\S]{0,400}?(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/gi
      ),
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — policy whose predicate never references the current user
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/policy-no-user-scope",
    title: "RLS policy without user scoping",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-285",
    message:
      "An RLS policy defines a predicate that references none of auth.uid(), auth.jwt(), or auth.role(). It may grant broader access than intended.",
    recommendation:
      "Scope the policy to the requesting user/role, e.g. USING (auth.uid() = user_id). If the data is intentionally public, make that explicit and document it.",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /CREATE\s+POLICY\b[\s\S]{0,600}?;/gi;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(f.content)) !== null) {
        if (++guard > 500) break;
        const stmt = m[0];
        if (!/\bUSING\b|\bWITH\s+CHECK\b/i.test(stmt)) continue; // no predicate
        if (/auth\.(uid|jwt|role)\s*\(/i.test(stmt)) continue; // properly scoped
        // (true) policies are already covered by policy-using-true.
        if (/(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i.test(stmt)) continue;
        out.push({
          line: lineAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — RLS policy that decides access from user-EDITABLE metadata
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/rls-policy-user-metadata",
    title: "RLS policy trusts user-editable metadata",
    severity: "critical",
    category: "supabase",
    cwe: "CWE-639",
    message:
      "An RLS policy makes its access decision from user_metadata (auth.users.raw_user_meta_data). That field is writable by the end user via supabase.auth.updateUser({ data: … }), so any authenticated user can set whatever value the policy checks and grant themselves access — e.g. updateUser({ data: { is_admin: true } }).",
    recommendation:
      "Never read user_metadata in a policy. Use app_metadata / raw_app_meta_data, which the user cannot write — or better, keep the role/tenant in a table your server controls and join against it, e.g. USING (EXISTS (SELECT 1 FROM public.memberships m WHERE m.user_id = auth.uid() AND m.org_id = org_id)).",
    reference:
      "https://supabase.github.io/splinter/0015_rls_references_user_metadata/",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      const out: RuleMatch[] = [];
      // Comment-stripped copy: a migration is allowed to WARN about this
      // footgun in prose without tripping the rule. Line-preserving, so
      // offsets still map onto the original content.
      const src = stripSqlComments(f.content);
      const re = /CREATE\s+POLICY\b/gi;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(src)) !== null) {
        if (++guard > 500) break;
        const end = sqlStatementEnd(src, m.index);
        const stmt = src.slice(m.index, end);
        // `user_metadata` / `raw_user_meta_data` only. The safe counterparts
        // (app_metadata / raw_app_meta_data) are distinct tokens — no substring
        // collision — and a bare `metadata` is deliberately NOT matched.
        const hit = /\buser_metadata\b|\braw_user_meta_data\b/i.exec(stmt);
        if (!hit) continue;
        const idx = m.index + hit.index;
        out.push({
          line: lineAt(f.content, idx),
          column: columnAt(f.content, idx),
          snippet: snippetAt(f.content, idx),
        });
        re.lastIndex = end;
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — edge function with no real auth validation
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/edge-function-no-auth",
    title: "Edge function without auth validation",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-306",
    message:
      "This Supabase Edge Function handles requests but never reads and verifies the Authorization header. Edge functions are publicly invocable by default.",
    recommendation:
      "Read the Authorization header and verify the JWT (supabase.auth.getUser(token)) before doing any work, or set verify_jwt = true in the function config.",
    appliesTo: (f) => isEdgeFunction(f.path) && isJsLike(f),
    scan: (f) => {
      const handlesRequests =
        /Deno\.serve|serve\s*\(|export\s+default\s+async/.test(f.content);
      if (!handlesRequests) return [];
      // Require BOTH an Authorization header read AND a verification call —
      // a bare mention of "authorization" or an unrelated db.getUser() is not
      // proof of authentication.
      const readsAuthHeader =
        /headers\.get\(\s*['"]authorization['"]\s*\)|headers\[\s*['"]authorization['"]\s*\]/i.test(
          f.content
        );
      const verifies =
        /auth\.getUser\s*\(|verify_jwt|jwtVerify|jose|createRemoteJWKSet/.test(
          f.content
        );
      const hasAuth = (readsAuthHeader && verifies) || /verify_jwt\s*[:=]\s*true/i.test(f.content);
      if (!hasAuth) {
        return [
          {
            line: 1,
            snippet: snippetAt(f.content, 0),
            message:
              "Edge function handles requests but does not read and verify the Authorization header.",
          },
        ];
      }
      return [];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — getSession() trusted in server code (does NOT verify the JWT)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/getsession-server-trust",
    title: "getSession() trusted in server code",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-287",
    message:
      "supabase.auth.getSession() is called in server middleware. On the server it reads the session straight from the request cookies WITHOUT verifying the JWT, so a forged cookie can spoof it. Supabase's guidance is to use getUser() (or getClaims()) — which revalidates the token with the Auth server — for any authorization decision.",
    recommendation:
      "In server code (middleware, route handlers, server actions) authorize with supabase.auth.getUser() — it revalidates the JWT — not getSession(). getSession() is fine on the client, where the session is already trusted.",
    appliesTo: (f) =>
      isJsLike(f) && /(^|[\/\\])middleware\.(ts|js)$/.test(f.path),
    scan: (f) => {
      // Server-only footgun; a client component using getSession is fine.
      if (isClientComponent(f.content)) return [];
      if (!/\.auth\.getSession\s*\(/.test(f.content)) return [];
      // If the file ALSO revalidates with getUser()/getClaims(), it's doing the
      // right thing — the getSession call isn't the trust boundary.
      if (/\.auth\.getUser\s*\(|\.auth\.getClaims\s*\(|\bgetClaims\s*\(/.test(f.content)) {
        return [];
      }
      const m = /\.auth\.getSession\s*\(/.exec(f.content);
      const idx = m ? m.index : 0;
      return [{ line: lineAt(f.content, idx), snippet: snippetAt(f.content, idx) }];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — public table explicitly GRANTed to the anon role without RLS
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/grant-to-anon",
    title: "Table granted to the anon role without RLS",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-732",
    message:
      "A public table is GRANTed to the anon (unauthenticated) role but RLS is never enabled for it in this migration. Since the 2026 Supabase change, tables reach the Data API only via explicit grants — so this GRANT hands every anonymous visitor direct access with no policy in front of it.",
    recommendation:
      "Enable RLS on the table (ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;) and add scoped policies, or revoke the grant from anon. Only keep an anon grant for genuinely public data that is still RLS-protected.",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      const out: RuleMatch[] = [];

      // Tables that DO get RLS enabled in this file, keyed schema.table.
      const enabled = new Set<string>();
      const alterRe =
        /ALTER\s+TABLE\s+(?:ONLY\s+)?(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
      let am: RegExpExecArray | null;
      while ((am = alterRe.exec(f.content)) !== null) {
        const schema = am[1] ? unquote(am[1]) : "public";
        enabled.add(`${schema}.${unquote(am[2])}`);
      }

      // GRANT <privs> ON [TABLE] <schema.table> ... TO ... anon
      // Bounded, lazy quantifiers => ReDoS-safe. Negative lookahead skips
      // ON SCHEMA/FUNCTION/SEQUENCE/DATABASE and ON ALL TABLES.
      const grantRe =
        /\bGRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|ALL)(?:\s+PRIVILEGES)?[\s\S]{0,120}?\bON\s+(?:TABLE\s+)?(?!SCHEMA\b|FUNCTION\b|SEQUENCE\b|DATABASE\b|ALL\b)(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)[\s\S]{0,160}?\bTO\b[\s\S]{0,160}?\banon\b/gi;
      let gm: RegExpExecArray | null;
      let guard = 0;
      while ((gm = grantRe.exec(f.content)) !== null) {
        if (++guard > 500) break;
        const schema = gm[1] ? unquote(gm[1]) : "public";
        const table = unquote(gm[2]);
        if (schema !== "public") continue; // only the Data-API-exposed schema
        if (INTERNAL_SCHEMAS.has(schema)) continue;
        if (table.startsWith("_")) continue;
        if (enabled.has(`${schema}.${table}`)) continue; // RLS present -> not a finding
        out.push({
          line: lineAt(f.content, gm.index),
          snippet: snippetAt(f.content, gm.index),
          message: `Table "${table}" is granted to anon but RLS is never enabled for it in this file.`,
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — SECURITY DEFINER function with an unpinned search_path
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/security-definer-mutable-search-path",
    title: "SECURITY DEFINER function without a fixed search_path",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-426",
    message:
      "A SECURITY DEFINER function runs with the privileges of the user who created it, but its search_path is inherited from the caller. Anyone who can create objects in a schema on that search_path can make the function resolve to a table or function they control, and it will run with elevated privileges.",
    recommendation:
      "Pin the search_path on the function: add `set search_path = ''` to the definition (or `ALTER FUNCTION <name> SET search_path = '';`) and fully qualify every object reference inside it, e.g. public.profiles instead of profiles.",
    reference:
      "https://supabase.github.io/splinter/0011_function_search_path_mutable/",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      const src = stripSqlComments(f.content);
      const out: RuleMatch[] = [];

      // Functions pinned via a separate ALTER FUNCTION statement are fine.
      const altered = new Set<string>();
      const altRe =
        /ALTER\s+FUNCTION\s+(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)[\s\S]{0,300}?\bSET\s+search_path\b/gi;
      let am: RegExpExecArray | null;
      let aGuard = 0;
      while ((am = altRe.exec(src)) !== null) {
        if (++aGuard > 300) break;
        altered.add(unquote(am[2]));
      }

      const re =
        /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:(["']?[a-z0-9_]+["']?)\s*\.\s*)?(["']?[a-z0-9_]+["']?)/gi;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(src)) !== null) {
        if (++guard > 200) break;
        // Dollar-quote-aware statement end, so options placed AFTER the body
        // (`AS $$…$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''`)
        // are still inside the window.
        const end = sqlStatementEnd(src, m.index);
        const stmt = src.slice(m.index, end);
        re.lastIndex = end;

        // Invoker-rights functions don't carry the privilege-escalation risk —
        // restricting to SECURITY DEFINER is what keeps this rule precise.
        if (!/\bSECURITY\s+DEFINER\b/i.test(stmt)) continue;
        if (/\bSET\s+search_path\b/i.test(stmt)) continue;
        const schema = m[1] ? unquote(m[1]) : "public";
        if (INTERNAL_SCHEMAS.has(schema)) continue;
        const name = unquote(m[2]);
        if (altered.has(name)) continue;

        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: `SECURITY DEFINER function "${name}" does not pin its search_path.`,
        });
      }
      return out;
    },
  },
];
