import type { Rule, RuleMatch, ScanFile, Severity } from "../types";
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
  stripSqlCommentsQuoted,
  stripSqlCommentsQuoteAware,
  sqlStatementEnd,
  isTestPath,
  stripJsComments,
  blankJsCommentLines,
  middlewareFileKind,
  isNextProxyCode,
  isProxyEntryPath,
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

// ════════════════════════════════════════════════════════════════════════
// supabase/security-definer-mutable-search-path — internals
// ════════════════════════════════════════════════════════════════════════

// A real pin: SET search_path {TO|=} <anything but DEFAULT>, or FROM CURRENT.
// Also accepts pg_dump's quoted "search_path".
// DEFAULT removes the function-local setting (same as RESET), so it is NOT a pin.
const SEARCH_PATH_PIN_RE =
  /\bSET\s+"?search_path"?\s*(?:(?:TO|=)(?!\s*DEFAULT\b)|FROM\s+CURRENT\b)/i;

/** Number of input params in the parenthesised list at/after `from` (OUT params excluded,
 *  commas inside '…' literals and nested parens ignored). null = no list / unbalanced / >4000 chars.
 *  Used to tell overloads apart: an ALTER of foo(text, text, text) must not
 *  count as a pin for a new foo(text, text, text, text). */
function paramArity(src: string, from: number): number | null {
  let i = from;
  while (i < src.length && /\s/.test(src[i])) i++;
  if (src[i] !== "(") return null;
  let depth = 0;
  let cur = "";
  let n = 0;
  let inStr = false;
  const limit = Math.min(src.length, i + 4000);
  for (let j = i; j < limit; j++) {
    const ch = src[j];
    // A DEFAULT 'a,b' literal must not split a parameter.
    if (ch === "'") {
      inStr = !inStr;
      cur += ch;
      continue;
    }
    if (inStr) {
      cur += ch;
      continue;
    }
    if (ch === "(") {
      depth++;
      if (depth === 1) continue;
    }
    if (ch === ")") {
      depth--;
      if (depth === 0) {
        if (cur.trim() && !/^OUT\s/i.test(cur.trim())) n++;
        return n;
      }
    }
    // Only depth-1 commas separate parameters: numeric(10,2) is one type.
    if (ch === "," && depth === 1) {
      if (cur.trim() && !/^OUT\s/i.test(cur.trim())) n++;
      cur = "";
      continue;
    }
    cur += ch;
  }
  return null;
}

// Words a guard body can contain without resolving any object through
// search_path: plpgsql keywords, RAISE levels, and trigger variables.
const NO_LOOKUP_WORDS = new Set([
  "begin",
  "end",
  "raise",
  "exception",
  "notice",
  "warning",
  "info",
  "log",
  "debug",
  "return",
  "new",
  "old",
  "null",
  "tg_op",
  "tg_name",
  "tg_table_name",
  "tg_table_schema",
  "tg_when",
  "tg_level",
  "tg_relname",
]);

/** True only when the dollar-quoted BODY (the one after AS) resolves no names at all.
 *  An append-only trigger that only RAISEs cannot be hijacked through
 *  search_path, because there is nothing in it to resolve. Anything else (a
 *  table, a function call, an operator) keeps the finding. */
function bodyHasNoLookups(stmt: string): boolean {
  // Anchor on AS: a $…$ parameter DEFAULT is not the body.
  const open = /\bAS\s+(\$[A-Za-z0-9_]{0,63}\$)/i.exec(stmt);
  // Single-quoted / BEGIN ATOMIC body: keep firing.
  if (!open) return false;
  const tag = open[1];
  const start = open.index + open[0].length;
  const close = stmt.indexOf(tag, start);
  if (close === -1) return false;
  let body = stmt.slice(start, close);
  if (body.length > 2000) return false;
  body = body.replace(/'[^']*'/g, " ");
  const words = body.match(/[A-Za-z_][A-Za-z0-9_$]*/g) ?? [];
  if (words.length === 0) return false;
  if (!words.every((w) => NO_LOOKUP_WORDS.has(w.toLowerCase()))) return false;
  // Any operator, dot, paren, quote or $ keeps the finding: operators and
  // casts resolve through search_path too.
  return /^[\s;,]*$/.test(body.replace(/[A-Za-z_][A-Za-z0-9_$]*/g, " "));
}

// ════════════════════════════════════════════════════════════════════════
// supabase/policy-no-user-scope — internals (used by that rule only)
//
// The rule fires on a CREATE POLICY whose predicate never identifies the
// caller. The naive "no auth.uid()/jwt()/role() in the text" test fired on
// 1,736 policies across 55 real repos, mostly on policies that DO scope the
// caller — through a membership helper (is_project_member(id)), a pg_dump
// quoted "auth"."uid"(), JWT claims, a deny-all (false), or a RESTRICTIVE
// guard. Everything below exists to recognise those shapes WITHOUT silencing
// a policy that is genuinely open. Strictly per-file: no cross-file state.
// Every regex is bounded; the AND/OR walk is a capped char loop; helper trust
// is memoised per file.
// ════════════════════════════════════════════════════════════════════════

// Expressions that identify the requesting end user. uid/jwt are
// quote-tolerant ("auth"."uid"() is how pg_dump / `supabase db pull` writes
// it). The UNQUOTED auth.role( skip is kept exactly as before. Deliberately
// NOT here: auth.email, quoted "auth"."role", current_user, session_user —
// in Supabase current_user/session_user are the SHARED Postgres role
// (anon / authenticated), not the end user, so they scope nothing.
const IDENTITY_RE =
  /"?\bauth"?\s{0,4}\.\s{0,4}"?(?:uid|jwt)"?\s{0,4}\(|\bauth\.role\s*\(|\bcurrent_setting\s{0,4}\(\s{0,4}'request\.jwt/i;

// A request header that carries a SECRET (x-share-token, x-api-key, …) — only
// accepted inside a helper body defined in the same file. A plain identifier
// header (x-tenant-id) is client-chosen and stays untrusted.
const CRED_HDR_RE =
  /\bcurrent_setting\s{0,4}\(\s{0,4}'request\.headers'[^;]{0,80}?->>\s{0,4}'[a-z0-9_-]{0,40}(?:token|secret|signature|api[_-]?key)[a-z0-9_-]{0,20}'/i;

// Schema-qualified calls into these schemas are platform builtins
// (storage.foldername(), realtime.topic(), …), never an access helper.
const SCHEMA_SKIP = new Set([
  "auth",
  "storage",
  "pg_catalog",
  "extensions",
  "realtime",
  "information_schema",
]);

// A bare (unqualified) call to one of these is SQL syntax, a builtin, or a
// cast — NOT an access helper. Without this list `lower(coalesce(status,''))`
// or `exists (select …)` would read as "delegates to a helper".
const NON_HELPER = new Set(
  (
    // SQL / PL/pgSQL keywords that can precede "("
    "and or not in is as on any all some exists using check select from where when then else case end like ilike similar between array row values filter over cast join lateral distinct " +
    "to by having limit offset union intersect except within group table setof returns return if elsif while perform into window partition range rows nulls collate escape overlaps unique primary references default " +
    // builtins
    "now coalesce nullif greatest least lower upper trim btrim ltrim rtrim length char_length character_length octet_length bit_length substring substr left right position strpos split_part replace translate reverse repeat initcap regexp_replace regexp_match regexp_matches regexp_like regexp_count regexp_substr regexp_instr regexp_split_to_array regexp_split_to_table concat concat_ws format md5 sha224 sha256 sha384 sha512 abs round floor ceil ceiling trunc mod power sqrt sign div random " +
    "date_trunc date_bin extract date_part to_char to_date to_timestamp to_number age make_date make_time make_timestamp make_timestamptz make_interval justify_interval timezone clock_timestamp statement_timestamp transaction_timestamp isfinite " +
    "array_length array_lower array_upper array_ndims array_dims cardinality unnest array_position array_positions array_to_string string_to_array array_agg array_append array_prepend array_cat array_remove array_replace string_agg " +
    "jsonb_array_length json_array_length jsonb_typeof json_typeof jsonb_exists jsonb_exists_any jsonb_exists_all jsonb_build_object json_build_object jsonb_build_array json_build_array jsonb_extract_path jsonb_extract_path_text json_extract_path json_extract_path_text jsonb_array_elements jsonb_array_elements_text json_array_elements json_array_elements_text jsonb_object_keys jsonb_each jsonb_each_text jsonb_path_exists jsonb_path_match jsonb_path_query jsonb_strip_nulls jsonb_set to_json to_jsonb row_to_json jsonb_agg json_agg " +
    "count sum min max avg bool_and bool_or every gen_random_uuid uuid_generate_v4 encode decode digest hmac crypt gen_salt starts_with lpad rpad quote_ident quote_literal quote_nullable num_nulls num_nonnulls " +
    "tstzrange tsrange daterange int4range int8range numrange isempty lower_inf upper_inf to_tsvector to_tsquery plainto_tsquery phraseto_tsquery websearch_to_tsquery ts_rank similarity word_similarity " +
    "current_setting set_config current_schema current_schemas current_database current_catalog inet_client_addr inet_server_addr version txid_current pg_trigger_depth pg_has_role has_table_privilege has_column_privilege has_schema_privilege has_function_privilege has_any_column_privilege " +
    // type names (casts)
    "text varchar char character numeric decimal int int2 int4 int8 integer bigint smallint real float float4 float8 bool boolean uuid date time timetz timestamp timestamptz interval json jsonb bytea inet cidr citext"
  ).split(/\s+/)
);

// [schema.]name( — quote-tolerant. Global + stateful, so a FRESH instance is
// built per use (a shared /g regex would leak lastIndex between calls).
const CALL_RE_SRC =
  '(?:\\b([a-z_][a-z0-9_]{0,62})"?\\s{0,4}\\.\\s{0,4}"?)?\\b([a-z_][a-z0-9_]{0,62})"?\\s{0,4}\\(';

// An atom that INVERTS a helper (NOT helper(), helper() = false, IS FALSE,
// IS NOT TRUE, IS NULL, IS DISTINCT FROM) grants the complement — e.g. "every
// non-banned user may edit every row". Tested on the depth-0 text only.
const NEGATING_RE =
  /^\s{0,8}not\b|\bis\s{1,8}not\s{1,8}true\b|\bis\s{1,8}false\b|=\s{0,8}false\b|\bis\s{1,8}null\b|\bis\s{1,8}distinct\s{1,8}from\b/i;

// zero_arg_helper() IS NOT NULL — on a WRITE that means "any user who has an
// org may change every row", which is not scoping.
const ZERO_ARG_NOT_NULL_RE =
  /\b[a-z_][a-z0-9_]{0,62}"?\s{0,4}\(\s{0,4}\)\s{0,4}(?:::\s{0,4}[a-z_][a-z0-9_]{0,40}\s{0,4})?is\s{1,8}not\s{1,8}null\b/i;

// "CREATE POLICY <name>" — stripped before every test, so identity text that
// only appears in the policy NAME ("owner only (auth.uid() = user_id)")
// cannot scope the predicate.
const HEAD_RE = /^CREATE\s+POLICY\s+(?:"[^"]{0,200}"|[a-z0-9_$%]{1,80})/i;

// Hand-off to supabase/policy-using-true: a (true) within 400 chars of CREATE
// POLICY. Keep in lockstep with its matcher. It is tested on BOTH the raw text
// (the original contract: a (true) further out, or hidden behind a comment
// inside the parens, keeps firing here) AND that rule's own view
// (stripSqlCommentsQuoted: comments blanked, literals kept), so a (true) that
// exists only inside a comment, which that rule no longer reports, is judged
// here. Both rules may report a policy; never neither. The only (true)
// policies that rule skips are AS RESTRICTIVE and bypass-only
// (TO service_role…), which grant nothing.
const HANDOFF_RE =
  /^CREATE\s+POLICY[\s\S]{0,400}?(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i;

// Public-content SELECT filtered by an explicit publication flag (whitespace
// collapsed, quotes dropped, lowercased). is_active / active / approved /
// status = 'active' are deliberately NOT publication flags.
const PUB_RE =
  /^using ?\({1,2} ?(?:[a-z0-9_]{1,63} ?\. ?)?(?:(?:is_)?published ?(?:=|is) ?true|is_public ?(?:=|is) ?true|is_draft ?(?:=|is) ?false|(?:status|visibility) ?= ?'(?:published|public)'(?:::[a-z_]{1,40})?) ?\){1,2} ?;?$/;

/** Names of the (possible) access helpers called in `text`, lowercase. */
function helperCalls(text: string): string[] {
  const re = new RegExp(CALL_RE_SRC, "gi");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(text)) !== null) {
    if (++guard > 200) break;
    const fn = m[2].toLowerCase();
    if (m[1]) {
      // schema.fn( — a user-defined schema is a helper; platform schemas aren't.
      if (SCHEMA_SKIP.has(m[1].toLowerCase())) continue;
      out.push(fn);
      continue;
    }
    if (!NON_HELPER.has(fn)) out.push(fn);
  }
  return out;
}

/**
 * Functions DEFINED in this file: lowercase name -> body text (overloads
 * append). The "CREATE … FUNCTION name(" prefix is dropped so the helper's
 * own name never reads as a call it makes.
 */
function fileFunctions(src: string): Map<string, string[]> {
  const fns = new Map<string, string[]>();
  const re =
    /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:"?([a-z_][a-z0-9_]{0,62})"?\s{0,4}\.\s{0,4})?"?([a-z_][a-z0-9_]{0,62})"?\s{0,4}\(/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(src)) !== null) {
    if (++guard > 200) break;
    const name = m[2].toLowerCase();
    const win = src.slice(m.index, m.index + 20000);
    const tag = /\$[A-Za-z0-9_]{0,32}\$/.exec(win);
    const semi = win.indexOf(";");
    let text: string;
    if (tag && (semi === -1 || tag.index < semi)) {
      // Dollar-quoted body: runs to the matching closing tag (or the window).
      const close = win.indexOf(tag[0], tag.index + tag[0].length);
      text = win.slice(0, close === -1 ? win.length : close + tag[0].length);
    } else {
      text = win.slice(0, semi === -1 ? win.length : semi);
    }
    const list = fns.get(name) ?? [];
    list.push(text.slice(m[0].length));
    fns.set(name, list);
  }
  return fns;
}

/** Per-file, per-scan state. Never shared across files. */
type ScopeCtx = {
  src: string;
  fns: Map<string, string[]> | null;
  /** Depth-0 trust verdicts, per helper name. */
  memo: Map<string, boolean>;
  /** Per definition text: does it identify the caller directly, and what it calls. */
  defInfo: Map<string, { direct: boolean; calls: string[] }>;
  /** Per-statement cap on scoped() calls. */
  budget: number;
  isWrite: boolean;
};

const fnsOf = (ctx: ScopeCtx) => (ctx.fns ??= fileFunctions(ctx.src));

// Pure cache of the per-body regex work — same answers, but a file with many
// helpers that call each other can't make the DFS re-scan 20 KB bodies.
function defInfoOf(ctx: ScopeCtx, text: string) {
  let info = ctx.defInfo.get(text);
  if (!info) {
    info = {
      direct: IDENTITY_RE.test(text) || CRED_HDR_RE.test(text),
      calls: helperCalls(text),
    };
    ctx.defInfo.set(text, info);
  }
  return info;
}

/**
 * May this helper encode the caller's identity? A helper NOT defined in this
 * file lives in another migration and is trusted. One defined here must reach
 * auth.uid()/jwt() (or a secret-bearing header) itself or through another
 * helper, within depth 3 — a same-file is_admin() that never looks at the
 * caller grants everyone.
 */
function trusted(
  ctx: ScopeCtx,
  name: string,
  depth = 0,
  seen: Set<string> = new Set()
): boolean {
  const fns = fnsOf(ctx);
  const defs = fns.get(name);
  if (!defs) return true;
  const memo = ctx.memo.get(name);
  if (memo !== undefined) return memo;
  let r = false;
  // A cycle or a chain deeper than 3 is not proof of scoping.
  if (depth <= 3 && !seen.has(name)) {
    seen.add(name);
    outer: for (const text of defs) {
      const info = defInfoOf(ctx, text);
      if (info.direct) {
        r = true;
        break;
      }
      for (const c of info.calls) {
        if (c !== name && trusted(ctx, c, depth + 1, seen)) {
          r = true;
          break outer;
        }
      }
    }
  }
  if (depth === 0) ctx.memo.set(name, r);
  return r;
}

const hasTrustedHelper = (ctx: ScopeCtx, text: string) =>
  helperCalls(text).some((c) => trusted(ctx, c));

/** Index of the ")" balancing s[open] === "(", or -1. */
function closeParen(s: string, open: number): number {
  let d = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === "(") d++;
    else if (s[i] === ")") {
      d--;
      if (d === 0) return i;
    }
  }
  return -1;
}

/** Drop redundant outer parens: "((a and b))" -> "a and b". */
function stripWrap(e: string): string {
  let t = e.trim();
  for (let k = 0; k < 8; k++) {
    if (!(t.startsWith("(") && closeParen(t, 0) === t.length - 1)) break;
    t = t.slice(1, -1).trim();
  }
  return t;
}

const isWordChar = (c: string | undefined) => !!c && /[a-z0-9_]/i.test(c);

/** Split at depth-0 occurrences of `word` (and/or), skipping '…' literals. */
function splitTop(e: string, word: string): string[] {
  const parts: string[] = [];
  const w = word.length;
  let d = 0;
  let start = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "(") d++;
    else if (c === ")") d--;
    else if (c === "'") {
      const j = e.indexOf("'", i + 1);
      if (j === -1) break;
      i = j;
    } else if (
      d === 0 &&
      e.slice(i, i + w).toLowerCase() === word &&
      !isWordChar(e[i - 1]) &&
      !isWordChar(e[i + w])
    ) {
      parts.push(e.slice(start, i));
      start = i + w;
      i += w - 1;
    }
  }
  parts.push(e.slice(start));
  return parts;
}

/** The characters of `e` outside any parentheses. */
function depth0(e: string): string {
  let d = 0;
  let out = "";
  for (const c of e) {
    if (c === "(") d++;
    else if (c === ")") d--;
    else if (d === 0) out += c;
  }
  return out;
}

/**
 * Does this predicate expression scope the caller? OR: every branch must
 * (one open branch opens the row). AND: one scoped conjunct is enough. An
 * atom is scoped by an identity call or a trusted helper — unless it is
 * negated. Anything unrecognised returns false, i.e. keeps firing.
 */
function scoped(ctx: ScopeCtx, expr: string, depth: number): boolean {
  if (++ctx.budget > 400) return false; // pathological input: keep firing
  const e = stripWrap(expr);
  if (depth > 8) return false;
  const ors = splitTop(e, "or");
  if (ors.length > 1) return ors.every((b) => scoped(ctx, b, depth + 1));
  const ands = splitTop(e, "and");
  if (ands.length > 1) return ands.some((b) => scoped(ctx, b, depth + 1));
  if (/^false$/i.test(e)) return true;
  if (IDENTITY_RE.test(e)) return true;
  if (NEGATING_RE.test(depth0(e))) return false;
  // On a SELECT, helper() IS NOT NULL is accepted like auth.uid() IS NOT NULL.
  if (ctx.isWrite && ZERO_ARG_NOT_NULL_RE.test(e)) return false;
  return hasTrustedHelper(ctx, e);
}

/**
 * Top-level USING (…) / WITH CHECK (…) bodies only. lastIndex jumps past each
 * balanced body, so a `JOIN … USING (col)` inside a subquery is never read as
 * a predicate of its own.
 */
function predicateBodies(rest: string): string[] {
  const bodies: string[] = [];
  const re = /\b(?:USING|WITH\s+CHECK)\s{0,4}\(/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(rest)) !== null) {
    if (++guard > 4) break;
    const open = m.index + m[0].length - 1;
    const close = closeParen(rest, open);
    if (close === -1) {
      bodies.push(rest.slice(open + 1));
      break;
    }
    bodies.push(rest.slice(open + 1, close));
    re.lastIndex = close + 1;
  }
  return bodies;
}

// ════════════════════════════════════════════════════════════════════════
// supabase/policy-using-true — internals (used by that rule only)
//
// A (true) predicate is not one risk but several. A WRITE (INSERT / UPDATE /
// DELETE / ALL) open to an API role lets anyone change any row: always a
// warning. A SELECT (true) is also how genuinely public reference data
// (genres, countries) is published, and reporting every one as a warning
// buried the real leaks: 529 warnings across 55 real repos. So a SELECT is
// graded per match: it stays a warning when the table looks private (by name,
// or by a PII/credential column defined in the same file), on storage.objects,
// or when the table is dynamic; otherwise it still fires, as info. Never
// silenced, except a policy that only RLS-bypassing roles use and an
// AS RESTRICTIVE one: neither can grant anything.
// Strictly per-file. Every quantifier on user text is bounded or a single
// \s+ / \s*; the CREATE TABLE scan resumes after each body (linear).
// ════════════════════════════════════════════════════════════════════════

// These roles have BYPASSRLS, so a policy that applies ONLY to them never
// runs. A custom role is NOT assumed to bypass RLS.
const RLS_BYPASS_ROLES = new Set(["service_role", "postgres", "supabase_admin"]);

// One identifier, "quoted" or bare. `%` admits EXECUTE format()'s %I / %s.
const PUT_IDENT = String.raw`(?:"[^"]{1,128}"|[\w%]{1,128})`;
// [schema.]table, captured as ONE group.
const PUT_QNAME = String.raw`(${PUT_IDENT}(?:\s*\.\s*${PUT_IDENT})?)`;

// CREATE POLICY <name> ON <qname>. A name it can't read (e.g. unquoted
// non-ASCII) makes the header null, and the rule then fires at its default.
const PUT_HDR_RE = new RegExp(
  String.raw`^CREATE\s+POLICY\s+(?:"(?:[^"]|""){1,256}"|[\w%]{1,128})\s+ON\s+` +
    PUT_QNAME,
  "i"
);

// Table names whose rows are likely private when readable WITHOUT an account.
// Tested against the bare, lowercased name (anchored, linear). Deliberately
// absent — each produced corpus false positives: members, chats, locations
// (team_members, group_chats, department_locations).
const PRIVATE_TABLE =
  /(?:^|_)(?:notes?|documents?|docs|files?|attachments?|uploads?|receipts?|contracts?|journals?|journal_entries|diar(?:y|ies)|chats?|profiles?|users?|accounts?|customers?|clients?|contacts?|employees?|staff|students?|patients?|subscribers?|waitlist|signups?|registrations?|enrollments?|applications?|applicants?|submissions?|responses?|feedback|orders?|payments?|transactions?|invoices?|purchases?|subscriptions?|payouts?|withdrawals?|deposits?|wallets?|refunds?|messages?|conversations?|leads?|bookings?|appointments?|reservations?|tokens?|secrets?|credentials?|api_keys?|keys|sessions?|notifications?|emails?|addresses|visits?|kyc|ledgers?|ledger_entries|expenses?|payroll|salaries|cash_flow|fluxo_caixa|usuarios?|clientes?|contatos?|contactos?|pedidos?|pagamentos?|pagos?|faturas?|facturas?|mensagens?|mensajes?|alunos?|pacientes?|funcionarios?|empleados?|kunden|benutzer|bestellungen|nachrichten|utilisateurs?|commandes?)$/;

// Narrower: per-owner data that EVERY signed-in account must not read. Supabase
// sign-ups are open by default, so "authenticated" usually means anyone.
const OWNER_PRIVATE_TABLE =
  /(?:^|_)(?:notes?|documents?|docs|files?|attachments?|uploads?|receipts?|contracts?|journals?|journal_entries|diar(?:y|ies)|chats?|messages?|conversations?|contacts?|leads?|submissions?|feedback|orders?|payments?|transactions?|invoices?|purchases?|payouts?|withdrawals?|wallets?|refunds?|tokens?|secrets?|credentials?|api_keys?|keys|sessions?|emails?|kyc|ledgers?|ledger_entries|expenses?|payroll|salaries|cash_flow|fluxo_caixa|pedidos?|pagamentos?|pagos?|faturas?|facturas?|mensagens?|mensajes?|bestellungen|nachrichten|commandes?)$/;

// Column names (bare, lowercased) that make a row private. Deliberately
// absent — corpus false positives: bare `address`, generic/current `token`,
// health*.
const PII_COLUMN =
  /(?:^|_)(?:e?mail|email_address|phone|phone_number|mobile|telefone|telefono|celular|whatsapp|ip|ip_address|latitude|longitude|ssn|cpf|tax_id|national_id|passport|passport_number|dob|birthdate|birth_date|date_of_birth|data_nascimento|password|password_hash|secret|client_secret|api_key|private_key|access_token|refresh_token|auth_token|session_token|reset_token|iban|card_number|account_number|home_address|shipping_address|billing_address|street_address)$/;
const CREDENTIAL_COLUMN =
  /(?:^|_)(?:password|password_hash|secret|client_secret|api_key|private_key|access_token|refresh_token|auth_token|session_token|reset_token|card_number|iban)$/;

/** Last part of a [schema.]name, unquoted and lowercased. */
const bareName = (q: string) =>
  (q.split(".").pop() ?? "").replace(/"/g, "").trim().toLowerCase().slice(0, 128);

/** Per-file facts a SELECT (true) is graded against. Never cross-file. */
type PutFacts = {
  /** table -> column names defined by CREATE TABLE / ALTER TABLE … ADD. */
  cols: Map<string, Set<string>>;
  /** table -> roles whose table-level SELECT is REVOKEd. */
  revoked: Map<string, Set<string>>;
  /** table -> roles GRANTed table-level SELECT/ALL (column grants excluded). */
  granted: Map<string, Set<string>>;
};

function putFileFacts(src: string): PutFacts {
  const cols = new Map<string, Set<string>>();
  const revoked = new Map<string, Set<string>>();
  const granted = new Map<string, Set<string>>();
  const add = (map: Map<string, Set<string>>, t: string, v: string) => {
    let s = map.get(t);
    if (!s) map.set(t, (s = new Set()));
    s.add(v);
  };
  // Fresh /g instances per call: a shared global regex would leak lastIndex.
  let m: RegExpExecArray | null;
  let guard = 0;

  const ct = new RegExp(
    String.raw`\bCREATE\s+(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
      PUT_QNAME +
      String.raw`\s*\(`,
    "gi"
  );
  while ((m = ct.exec(src)) !== null) {
    if (++guard > 2000) break;
    const t = bareName(m[1]);
    const open = m.index + m[0].length; // just after "("
    const lim = Math.min(src.length, sqlStatementEnd(src, m.index));
    let depth = 1;
    let i = open;
    for (; i < lim; i++) {
      if (src[i] === "(") depth++;
      else if (src[i] === ")" && --depth === 0) break;
    }
    // Literals collapsed first, so DEFAULT 'a, b' or CHECK (x IN ('a','b'))
    // can't read as column names.
    const body = src.slice(open, i).replace(/'(?:[^']|'')*'/g, "''");
    const cre = /(?:^|,)\s*"?([A-Za-z_][A-Za-z0-9_]{0,62})"?/g;
    let c: RegExpExecArray | null;
    while ((c = cre.exec(body)) !== null) add(cols, t, c[1].toLowerCase());
    // Resume after the body: a file of many tables is scanned once.
    ct.lastIndex = Math.max(ct.lastIndex, i);
  }

  const at = new RegExp(
    String.raw`\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + PUT_QNAME,
    "gi"
  );
  guard = 0;
  while ((m = at.exec(src)) !== null) {
    if (++guard > 2000) break;
    const t = bareName(m[1]);
    const stmt = src.slice(m.index, sqlStatementEnd(src, m.index));
    const ac =
      /\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"?([A-Za-z_][A-Za-z0-9_]{0,62})"?/gi;
    let c: RegExpExecArray | null;
    while ((c = ac.exec(stmt)) !== null) add(cols, t, c[1].toLowerCase());
  }

  const rv = new RegExp(
    String.raw`\bREVOKE\s+(?:ALL(?:\s+PRIVILEGES)?|SELECT)\s+ON\s+(?:TABLE\s+)?` +
      PUT_QNAME +
      String.raw`\s+FROM\s+([^;]{1,300})`,
    "gi"
  );
  guard = 0;
  while ((m = rv.exec(src)) !== null) {
    if (++guard > 2000) break;
    const t = bareName(m[1]);
    for (const r of m[2].split(","))
      add(revoked, t, r.replace(/"/g, "").trim().toLowerCase());
  }

  // Only a table-level SELECT/ALL re-grant undoes a REVOKE. A column grant
  // (GRANT SELECT (a, b) ON …) can't match: "(" is outside group 1.
  const gr = new RegExp(
    String.raw`\bGRANT\s+([A-Za-z,\s]{1,80}?)\s+ON\s+(?:TABLE\s+)?` +
      PUT_QNAME +
      String.raw`\s+TO\s+([^;]{1,300})`,
    "gi"
  );
  guard = 0;
  while ((m = gr.exec(src)) !== null) {
    if (++guard > 2000) break;
    if (!/\b(?:SELECT|ALL)\b/i.test(m[1])) continue;
    const t = bareName(m[2]);
    // The role is the first word of each part ("anon WITH GRANT OPTION").
    for (const r of m[3].split(","))
      add(granted, t, r.replace(/"/g, "").trim().toLowerCase().split(/\s/)[0]);
  }

  return { cols, revoked, granted };
}

/** What a (true) write policy lets its roles do, for the message. */
const PUT_WRITE_ACTION: Record<string, string> = {
  ALL: "read, insert, update and delete every row of",
  INSERT: "insert any row into",
  UPDATE: "update every row of",
  DELETE: "delete every row of",
};

// ════════════════════════════════════════════════════════════════════════
// supabase/grant-to-anon — internals (used by that rule only)
//
// The old single regex matched GRANT … anon across statement boundaries and
// ignored what the target was: 167 findings across 55 real repos, 136 of
// them a GRANT whose own TO list never named anon (the match ran on into a
// later statement); the rest were ALTER DEFAULT PRIVILEGES boilerplate,
// format() grants, security_invoker views and tables created (with RLS) in
// another file. It now reads ONE GRANT statement at a time and judges the
// target against what THIS file does to it: a table without RLS, a view that
// is not security_invoker, and a materialized view or foreign table (neither
// can ever be protected) are reported. An object the file never creates is
// left to the CREATE-site rules (rls-missing-on-table, rls-explicitly-
// disabled, policy-using-true): its RLS state is unknowable per-file. RLS
// counts however rls-missing-on-table credits it (direct ALTER, a later
// action of a multi-action ALTER, a DO-block FOREACH … ARRAY loop). A grant
// whose Data-API privileges the file later REVOKEs from the same role is not
// reported (a REVOKE in a CREATE FUNCTION body does not count: it runs only
// if called), and a GRANT that is prose in a literal (COMMENT ON … IS '…')
// is not a GRANT. A table finding is critical unless the object became a
// table only after the GRANT, or the file enables RLS on run-time-built
// names it cannot resolve (pg_tables loops): then it stays a warning.
// Strictly per-file. Every regex is a bounded single-class run or the same
// [schema.]name shape as alterRe; the GRANT loop resumes after each
// statement and every per-GRANT step is bounded, so total work stays linear
// (a hostile 1 MB file: under 0.6 s).
// ════════════════════════════════════════════════════════════════════════

// One identifier, optionally quoted; [schema.]name as TWO groups (schema,
// name). The same shape as the alterRe of rls-missing-on-table.
const GTA_ID = String.raw`(["']?[a-z0-9_]+["']?)`;
const GTA_QNAME = String.raw`(?:${GTA_ID}\s*\.\s*)?${GTA_ID}`;
const gtaKey = (s: string | undefined, t: string) =>
  `${s ? unquote(s) : "public"}.${unquote(t)}`;

// One trimmed reloption. A bare `security_invoker` means true; pg_dump writes
// "security_invoker"='true'.
const GTA_INVOKER_ON = /^"?security_invoker"?\s*(?:=\s*'?(?:true|on|1|yes)'?)?\s*$/i;
const GTA_INVOKER_OFF = /^"?security_invoker"?\s*=\s*'?(?:false|off|0|no)'?\s*$/i;

// GRANT targets that are not a single table or view: schemas, functions,
// sequences, ALTER DEFAULT PRIVILEGES … ON TABLES, ON ALL SEQUENCES IN SCHEMA.
const GTA_NON_TABLE =
  /^(?:ALL|SCHEMA|SCHEMAS|FUNCTION|FUNCTIONS|SEQUENCE|SEQUENCES|DATABASE|TABLES|ROUTINE|ROUTINES|PROCEDURE|PROCEDURES|TYPE|TYPES|DOMAIN|LANGUAGE|FOREIGN|LARGE|TABLESPACE|PARAMETER)\b/i;
const GTA_ALL_TABLES = /^ALL\s+TABLES\s+IN\s+SCHEMA\s+([\s\S]+)$/i;
// Non-global, so it can be shared: one [schema.]name and nothing else.
const GTA_OBJECT_RE = new RegExp(String.raw`^\s*${GTA_QNAME}\s*$`, "i");

type GtaKind = "table" | "view" | "matview" | "foreign";
type GtaEvent =
  | { pos: number; key: string; type: "create"; kind: GtaKind; invoker: boolean }
  | { pos: number; key: string; type: "rls" | "invoker"; on: boolean };
// firstCreate: earliest CREATE of any kind. firstTable: earliest CREATE of a
// plain table (a view dropped and recreated as a table keeps the view's
// firstCreate, but was not a table before then).
type GtaState = {
  kind?: GtaKind;
  rls: boolean;
  inv: boolean;
  firstCreate: number;
  firstTable: number;
};

// Only a table can be protected by RLS and only a view by security_invoker.
// Materialized views and foreign tables support neither.
const gtaProtected = (st: GtaState) =>
  st.kind === "table" ? st.rls : st.kind === "view" ? st.inv : false;

/** Final per-object state after every CREATE / ALTER in the file, in order. */
function gtaObjectState(src: string): Map<string, GtaState> {
  const events: GtaEvent[] = [];
  // Fresh /g instances per call: a shared global regex would leak lastIndex.
  const each = (re: RegExp, fn: (m: RegExpExecArray) => void) => {
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(src)) !== null) {
      if (++guard > 5000) break;
      fn(m);
    }
  };

  each(
    new RegExp(
      String.raw`CREATE\s+(?:(?:GLOBAL|LOCAL)\s+)?(TEMP\s+|TEMPORARY\s+|UNLOGGED\s+)?(FOREIGN\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
        GTA_QNAME,
      "gi"
    ),
    (m) => {
      // Temp tables live in pg_temp, which the Data API never exposes.
      if (m[1] && /^TEMP/i.test(m[1])) return;
      events.push({
        pos: m.index,
        key: gtaKey(m[3], m[4]),
        type: "create",
        kind: m[2] ? "foreign" : "table",
        invoker: false,
      });
    }
  );

  // The optional column list comes BEFORE the WITH clause:
  // CREATE VIEW v (a, b) WITH (security_invoker = true) AS … is valid.
  each(
    new RegExp(
      String.raw`CREATE\s+(?:OR\s+REPLACE\s+)?(TEMP\s+|TEMPORARY\s+)?(?:RECURSIVE\s+)?VIEW\s+` +
        GTA_QNAME +
        String.raw`(?:\s*\([^)]{0,2000}\))?(?:\s+WITH\s*\(([^)]{0,300})\))?`,
      "gi"
    ),
    (m) => {
      if (m[1]) return; // temp view
      events.push({
        pos: m.index,
        key: gtaKey(m[2], m[3]),
        type: "create",
        kind: "view",
        invoker: !!m[4] && m[4].split(",").some((o) => GTA_INVOKER_ON.test(o.trim())),
      });
    }
  );

  each(
    new RegExp(
      String.raw`CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?` + GTA_QNAME,
      "gi"
    ),
    (m) => {
      events.push({
        pos: m.index,
        key: gtaKey(m[1], m[2]),
        type: "create",
        kind: "matview",
        invoker: false,
      });
    }
  );

  each(
    new RegExp(
      String.raw`ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` +
        GTA_QNAME +
        String.raw`\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY`,
      "gi"
    ),
    (m) => {
      events.push({
        pos: m.index,
        key: gtaKey(m[1], m[2]),
        type: "rls",
        on: /^ENABLE$/i.test(m[3]),
      });
    }
  );
  // The same RLS enables rls-missing-on-table credits: a later action of a
  // multi-action ALTER TABLE, and a DO-block FOREACH … ARRAY['a', 'b'] loop.
  for (const t of rlsMultiActionToggles(src))
    events.push({ pos: t.pos, key: t.key, type: "rls", on: t.on });
  for (const e of rlsDynLoopEnables(src))
    events.push({ pos: e.pos, key: e.key, type: "rls", on: true });

  each(
    new RegExp(
      String.raw`ALTER\s+(?:VIEW|TABLE)\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` +
        GTA_QNAME +
        String.raw`\s+(SET|RESET)\s*\(([^)]{0,300})\)`,
      "gi"
    ),
    (m) => {
      const opts = m[4].split(",").map((o) => o.trim());
      const key = gtaKey(m[1], m[2]);
      if (/^RESET$/i.test(m[3])) {
        // RESET (security_invoker) restores the default: owner's rights.
        if (opts.some((o) => /security_invoker/i.test(o)))
          events.push({ pos: m.index, key, type: "invoker", on: false });
      } else if (opts.some((o) => GTA_INVOKER_OFF.test(o))) {
        events.push({ pos: m.index, key, type: "invoker", on: false });
      } else if (opts.some((o) => GTA_INVOKER_ON.test(o))) {
        events.push({ pos: m.index, key, type: "invoker", on: true });
      }
    }
  );

  events.sort((a, b) => a.pos - b.pos);
  const state = new Map<string, GtaState>();
  for (const e of events) {
    let st = state.get(e.key);
    if (!st)
      state.set(
        e.key,
        (st = { rls: false, inv: false, firstCreate: Infinity, firstTable: Infinity })
      );
    if (e.type === "create") {
      st.kind = e.kind;
      st.firstCreate = Math.min(st.firstCreate, e.pos);
      if (e.kind === "table") st.firstTable = Math.min(st.firstTable, e.pos);
      // CREATE OR REPLACE VIEW replaces the whole reloptions list, so a
      // re-create without WITH resets security_invoker to false.
      if (e.kind === "view") st.inv = e.invoker;
    } else if (e.type === "rls") {
      st.rls = e.on;
    } else {
      st.inv = e.on;
    }
  }
  return state;
}

/** Data-API privileges of a GRANT / REVOKE privilege list as bits (SELECT 1,
 *  INSERT 2, UPDATE 4, DELETE 8; ALL is all four). Column lists removed first. */
function gtaPrivMask(privs: string): number {
  if (/\bALL\b/i.test(privs)) return 15;
  let mask = 0;
  if (/\bSELECT\b/i.test(privs)) mask |= 1;
  if (/\bINSERT\b/i.test(privs)) mask |= 2;
  if (/\bUPDATE\b/i.test(privs)) mask |= 4;
  if (/\bDELETE\b/i.test(privs)) mask |= 8;
  return mask;
}

/**
 * Every '…' literal and $tag$ body of a file, in source order (so properly
 * nested: a literal inside a DO block comes after it, with `parent` set), and
 * what runs it, worked out on demand by gtaRegionCls:
 *  - "exec": a DO block, or a literal / body handed to EXECUTE,
 *    cron.schedule or dblink_exec: SQL that runs.
 *  - "func": a CREATE FUNCTION / PROCEDURE body (… AS '…' / AS $$…$$), which
 *    runs only if someone calls the function.
 *  - "prose": anything else (COMMENT ON … IS '…', a RAISE message).
 * One left-to-right pass over the RAW file (linear): comments are skipped
 * (an apostrophe in one is not a quote), "…" identifiers are stepped over,
 * '' and E'\'' escapes stay inside their literal, and each dollar body is
 * lexed again for its own literals (to depth 4; Postgres ends a body at the
 * first matching tag, so nothing inside can run past it). Fails loud: an
 * unterminated literal or comment ends lexing of its region, so whatever
 * follows counts as live SQL.
 */
type GtaRegion = {
  open: number;
  close: number;
  lit: boolean;
  parent: number;
  cls?: "exec" | "func" | "prose";
};

function gtaRegions(content: string): GtaRegion[] {
  const out: GtaRegion[] = [];
  const ident = /[A-Za-z0-9_$]/;
  let dollarMisses = 0;
  const lex = (from: number, to: number, parent: number, depth: number) => {
    const re = /['"$]|--|\/\*/g;
    re.lastIndex = from;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null && m.index < to) {
      const i = m.index;
      if (m[0] === "--") {
        const j = content.indexOf("\n", i + 2);
        if (j === -1 || j >= to) return;
        re.lastIndex = j + 1;
      } else if (m[0] === "/*") {
        const j = content.indexOf("*/", i + 2);
        if (j === -1 || j + 2 > to) return;
        re.lastIndex = j + 2;
      } else if (m[0] === '"') {
        const j = content.indexOf('"', i + 1);
        if (j === -1 || j >= to) return;
        re.lastIndex = j + 1;
      } else if (m[0] === "'") {
        // E'…' takes backslash escapes; a standard literal only ''.
        const esc = /[eE]/.test(content[i - 1] ?? "") && !ident.test(content[i - 2] ?? "");
        let j = content.indexOf("'", i + 1);
        for (;;) {
          if (j === -1 || j >= to) return;
          let bs = 0;
          if (esc) for (let b = j - 1; b > i && content[b] === "\\"; b--) bs++;
          if (bs % 2 === 1) j = content.indexOf("'", j + 1);
          else if (content[j + 1] === "'") j = content.indexOf("'", j + 2);
          else break;
        }
        out.push({ open: i, close: j + 1, lit: true, parent });
        re.lastIndex = j + 1;
      } else {
        // `$1` positional params and foo$bar identifiers are not tags.
        if (ident.test(content[i - 1] ?? "") || dollarMisses >= 64) continue;
        const tag = /^\$(?:[A-Za-z_][A-Za-z0-9_]{0,62})?\$/.exec(content.slice(i, i + 66));
        if (!tag) continue;
        const close = content.indexOf(tag[0], i + tag[0].length);
        if (close === -1 || close + tag[0].length > to) {
          dollarMisses++;
          continue;
        }
        const self = out.length;
        out.push({ open: i, close: close + tag[0].length, lit: false, parent });
        if (depth < 4) lex(i + tag[0].length, close, self, depth + 1);
        re.lastIndex = close + tag[0].length;
      }
    }
  };
  lex(0, content.length, -1, 0);
  return out;
}

/** What runs region r (see gtaRegions), from what leads up to it in `src`
 *  (comments blanked). Memoized: only regions a GRANT / REVOKE sits in are
 *  ever classified. */
function gtaRegionCls(regions: GtaRegion[], r: number, src: string): GtaRegion["cls"] {
  const g = regions[r];
  if (g.cls) return g.cls;
  const lead = src.slice(Math.max(0, g.open - 200), g.open);
  if (/\bDO\s*(?:LANGUAGE\s+'?[a-z0-9_]+'?\s*)?$/i.test(lead)) g.cls = "exec";
  else if (/\bAS\s*$/i.test(lead)) g.cls = "func";
  else
    g.cls = /\b(?:EXECUTE|cron\s*\.\s*schedule|dblink_exec)\b/i.test(
      lead.slice(lead.lastIndexOf(";") + 1)
    )
      ? "exec"
      : "prose";
  return g.cls;
}

/** Innermost region containing idx, or -1: the last region opened before
 *  idx, or the nearest of its ancestors that has not closed by then. */
function gtaRegionAt(regions: GtaRegion[], idx: number): number {
  let lo = 0;
  let hi = regions.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (regions[mid].open < idx) lo = mid + 1;
    else hi = mid;
  }
  let r = lo - 1;
  while (r !== -1 && regions[r].close <= idx) r = regions[r].parent;
  return r;
}

/** True when the GRANT at `idx` is prose inside an ordinary '…' literal
 *  (COMMENT ON … IS 'never grant select on t to anon; it holds PII', a RAISE
 *  message), not SQL that runs. A literal handed to EXECUTE, cron.schedule or
 *  dblink_exec, or a single-quoted function body, still counts. */
function gtaInProse(regions: GtaRegion[], src: string, idx: number): boolean {
  const r = gtaRegionAt(regions, idx);
  return r !== -1 && regions[r].lit && gtaRegionCls(regions, r, src) === "prose";
}

/** True when the REVOKE at `idx` runs when the migration does: top-level SQL,
 *  or every body / literal around it is a DO block or EXECUTE'd. A REVOKE in a
 *  CREATE FUNCTION / PROCEDURE body only runs if someone calls it, and one in
 *  prose never does; neither takes a grant back. */
function gtaRuns(regions: GtaRegion[], src: string, idx: number): boolean {
  for (let r = gtaRegionAt(regions, idx); r !== -1; r = regions[r].parent)
    if (gtaRegionCls(regions, r, src) !== "exec") return false;
  return true;
}

// REVOKEs from anon / PUBLIC, per role ("all" = ON ALL TABLES IN SCHEMA
// public) or per role + object: positions ascending, and suffix[i] = every
// privilege revoked at pos[i] or later.
type GtaRevokeList = { pos: number[]; suffix: number[] };
type GtaRevokes = {
  all: Map<string, GtaRevokeList>;
  obj: Map<string, GtaRevokeList>;
  objKeys: Set<string>;
};

/**
 * Every REVOKE of Data-API privileges from anon or PUBLIC on a public object
 * or ON ALL TABLES IN SCHEMA public. REVOKE GRANT OPTION FOR (the privilege
 * stays) and column revokes (the table-level grant stays) take nothing away,
 * and a REVOKE … FROM PUBLIC does not touch a grant made to anon itself (nor
 * the reverse). Only a REVOKE that runs with the migration counts (gtaRuns):
 * not one in a function body or in prose. Statement by statement like the
 * GRANT loop; capped at 100 objects so the per-GRANT check stays cheap (past
 * the cap, a REVOKE is ignored and the grant still fires).
 */
function gtaRevokes(src: string, regions: GtaRegion[]): GtaRevokes {
  const all = new Map<string, GtaRevokeList>();
  const obj = new Map<string, GtaRevokeList>();
  const objKeys = new Set<string>();
  const add = (map: Map<string, GtaRevokeList>, k: string, pos: number, mask: number) => {
    let l = map.get(k);
    if (!l) map.set(k, (l = { pos: [], suffix: [] }));
    l.pos.push(pos);
    l.suffix.push(mask);
  };
  const re = /\bREVOKE\b/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(src)) !== null) {
    if (++guard > 20000 || objKeys.size >= 100) break;
    const idx = m.index;
    // Bounded exactly as in the GRANT loop of grant-to-anon.
    const end = sqlStatementEnd(src.slice(0, idx + 4000), idx, 4000);
    if (!/\$[A-Za-z0-9_]*\$/.test(src.slice(idx, end))) re.lastIndex = Math.max(re.lastIndex, end);
    if (!gtaRuns(regions, src, idx)) continue;
    const stmt = src.slice(idx + 6, end);
    if (/^\s*GRANT\s+OPTION\s+FOR\b/i.test(stmt)) continue;
    const on = /\sON\s/i.exec(stmt);
    if (!on) continue;
    const mask = gtaPrivMask(
      stmt.slice(0, on.index).replace(/\b[a-z]+(?:\s+PRIVILEGES)?\s*\([^()]*\)/gi, " ")
    );
    if (!mask) continue;
    const rest = " " + stmt.slice(on.index + on[0].length);
    const from = /\sFROM\s/i.exec(rest);
    if (!from) continue;
    const objects = rest.slice(0, from.index).trim().replace(/^TABLE\s+/i, "");
    let roles = rest.slice(from.index + from[0].length);
    const cut = /\b(?:GRANTED\s+BY|CASCADE|RESTRICT)\b/i.exec(roles);
    if (cut) roles = roles.slice(0, cut.index);
    const who = new Set(
      roles
        .split(",")
        .map((r) => unquote(r.trim().replace(/^GROUP\s+/i, "")))
        .filter((r) => r === "anon" || r === "public")
    );
    if (who.size === 0) continue;
    const allT = GTA_ALL_TABLES.exec(objects);
    if (allT) {
      if (allT[1].split(",").some((s) => unquote(s.trim()) === "public"))
        for (const r of who) add(all, r, idx, mask);
      continue;
    }
    if (GTA_NON_TABLE.test(objects) || /[%|$']/.test(objects)) continue;
    for (const o of objects.split(",")) {
      const om = GTA_OBJECT_RE.exec(o);
      if (!om) continue;
      const key = gtaKey(om[1], om[2]);
      objKeys.add(key);
      for (const r of who) add(obj, `${r}\u0000${key}`, idx, mask);
    }
  }
  for (const l of [...all.values(), ...obj.values()])
    for (let i = l.pos.length - 2; i >= 0; i--) l.suffix[i] |= l.suffix[i + 1];
  return { all, obj, objKeys };
}

/** Privileges the REVOKEs in `l` take away after `idx` (binary search). */
function gtaAfter(l: GtaRevokeList | undefined, idx: number): number {
  if (!l) return 0;
  let lo = 0;
  let hi = l.pos.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (l.pos[mid] <= idx) lo = mid + 1;
    else hi = mid;
  }
  return lo < l.pos.length ? l.suffix[lo] : 0;
}

/** True when everything the GRANT at `idx` gives each of `roles` (anon /
 *  public) through the Data API on `key` is revoked again later in the file,
 *  per object or ON ALL TABLES IN SCHEMA public. */
function gtaRevokedLater(
  rv: GtaRevokes,
  roles: string[],
  mask: number,
  key: string,
  idx: number
): boolean {
  return roles.every(
    (r) =>
      (mask & ~(gtaAfter(rv.all.get(r), idx) | gtaAfter(rv.obj.get(`${r}\u0000${key}`), idx))) ===
      0
  );
}

// ════════════════════════════════════════════════════════════════════════
// supabase/rls-missing-on-table — internals (used by that rule only)
//
// 157 findings on the .sql files of 55 real repos; two thirds were not a
// table without RLS: "-- Create table for …" comments, tables enabled by a
// DO-block FOREACH … ARRAY[…] loop with format('… %I …'), runtime names
// (pgboss.%I) reported as a table called "if" or "public", test fixtures and
// Supabase "context only" dashboard exports. What still fires: every static
// public table this file never enables, and every public table a function or
// DO block creates at runtime without enabling RLS in the same body — a
// partition created that way is readable through /rest/v1/<partition> even
// when its parent has RLS. Strictly per-file. Every identifier run is
// bounded, every unbounded \s+ follows a literal keyword, every loop is
// capped (50 / 50 / 1000) and every lookback is a fixed window: 200 KB of
// adversarial SQL runs in ~0.1 s.
// ════════════════════════════════════════════════════════════════════════

// One identifier, optionally quoted. 128, not 63: Postgres truncates a
// longer name, but still creates the table.
const RLS_ID = `["']?[a-z0-9_]{1,128}["']?`;
// A dollar-quote tag ($$ or $tag$). `$1` positional params never match.
const RLS_DOLLAR_TAG = /\$(?:[a-z_][a-z0-9_]{0,62})?\$/i;
// format('ALTER TABLE public.%I …') or 'ALTER TABLE public.' || x || '…':
// RLS enabled on a runtime-named table.
const RLS_DYN_ENABLE_RE =
  /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?:[a-z0-9_"]{1,130}\s{0,8}\.\s{0,8})?(?:"?%[Is]"?|'\s{0,8}\|\|[^;]{0,300}?\|\|\s{0,8}')\s*ENABLE\s+ROW\s+LEVEL\s+SECURITY/i;
const RLS_DYN_CREATE_MESSAGE =
  "A table in the public schema is created at runtime (EXECUTE ... CREATE TABLE public.%I or string concatenation), and this function or DO block never enables RLS on it. Tables created this way get Supabase's default anon/authenticated grants. A partition created this way can be read and written directly through /rest/v1/<partition> even when the parent has RLS. Add EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', <name>), plus policies, right after the CREATE.";

/** Last match of a global regex in `text` (null when none). */
function lastMatchOf(re: RegExp, text: string): RegExpExecArray | null {
  let last: RegExpExecArray | null = null;
  let m: RegExpExecArray | null;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) {
    last = m;
    if (m[0].length === 0) re.lastIndex++;
  }
  return last;
}

// The two helpers below are shared by rls-missing-on-table and grant-to-anon,
// so both rules credit the same RLS enables. Keys are schema.table, lowercase.

/**
 * RLS enabled (or disabled) as a later action of a multi-action ALTER TABLE:
 * ALTER TABLE t ADD COLUMN bio text, ENABLE ROW LEVEL SECURITY. The direct
 * form (ALTER TABLE t ENABLE …) is matched by each rule's own regex. Anchored
 * on the comma-preceded action (rare), then the last ALTER TABLE <name> in the
 * same statement is found in a fixed 2,000-character lookback, so the work is
 * capped (1,000 anchors × 2,000 characters).
 */
function rlsMultiActionToggles(src: string): { pos: number; key: string; on: boolean }[] {
  const out: { pos: number; key: string; on: boolean }[] = [];
  const re = /,\s*(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY\b/gi;
  const alterRe = new RegExp(
    String.raw`\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + GTA_QNAME + String.raw`\s`,
    "gi"
  );
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(src)) !== null) {
    if (++guard > 1000) break;
    const win = src.slice(Math.max(0, m.index - 2000), m.index);
    // Same statement only: nothing before the last ";".
    const stmt = win.slice(win.lastIndexOf(";") + 1);
    const a = lastMatchOf(alterRe, stmt);
    if (!a) continue;
    out.push({ pos: m.index, key: gtaKey(a[1], a[2]), on: /^ENABLE$/i.test(m[1]) });
  }
  return out;
}

/**
 * Dynamic-loop enables: an anonymous DO block that runs
 *   FOREACH t IN ARRAY ARRAY['a', 'b'] LOOP
 *     EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
 * credits every literal in the array. Each condition keeps a real gap firing:
 * the array must feed a LOOP that reaches the ALTER, sit in the SAME dollar
 * body (not a GRANT loop in an earlier DO block), and that body must be a DO
 * block — a loop inside CREATE FUNCTION only runs if someone calls the
 * function. `pos` is the ALTER inside the loop.
 */
function rlsDynLoopEnables(src: string): { pos: number; key: string }[] {
  const out: { pos: number; key: string }[] = [];
  const dynAlterRe =
    /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?:([a-z0-9_"]{1,130})\s{0,8}\.\s{0,8})?"?%[Is]"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = dynAlterRe.exec(src)) !== null) {
    if (++guard > 50) break;
    const schema = m[1] ? unquote(m[1]) : "public";
    const winStart = Math.max(0, m.index - 4000);
    const win = src.slice(winStart, m.index);
    const arr = lastMatchOf(/\bARRAY\s{0,8}\[/gi, win);
    if (!arr) continue;
    const listStart = arr.index + arr[0].length;
    const close = win.indexOf("]", listStart);
    if (close === -1) continue;
    if (!/\bLOOP\b/i.test(win.slice(close + 1))) continue;
    if (RLS_DOLLAR_TAG.test(win.slice(arr.index))) continue;
    const pre = src.slice(Math.max(0, winStart + arr.index - 3000), winStart + arr.index);
    const tag = lastMatchOf(new RegExp(RLS_DOLLAR_TAG.source, "gi"), pre);
    if (!tag) continue;
    const beforeTag = pre.slice(Math.max(0, tag.index - 40), tag.index);
    if (!/\bDO\s*(?:LANGUAGE\s+'?plpgsql'?\s*)?$/i.test(beforeTag)) continue;
    const list = win.slice(listStart, Math.min(close, listStart + 4000));
    const litRe = /'([a-z0-9_]{1,128})'/gi;
    let lm: RegExpExecArray | null;
    while ((lm = litRe.exec(list)) !== null)
      out.push({ pos: m.index, key: `${schema}.${lm[1].toLowerCase()}` });
  }
  return out;
}

/**
 * True when the file enables RLS on a table whose name is built at run time
 * and rlsDynLoopEnables cannot resolve it to literal names: a FOR r IN SELECT
 * … FROM pg_tables loop, a loop in a function, %I.%I, 'public.' || name.
 * grant-to-anon keeps its finding a warning then, since that loop may well
 * cover the granted table. The ALTER is the last ALTER TABLE in a fixed
 * 200-character lookback from each ENABLE (at most 1,000), so work is capped.
 */
function rlsDynUnresolved(src: string): boolean {
  const resolved = new Set(rlsDynLoopEnables(src).map((e) => e.pos));
  const re = /ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(src)) !== null) {
    if (++guard > 1000) break;
    const from = Math.max(0, m.index - 200);
    const a = lastMatchOf(/\bALTER\s+TABLE\b/gi, src.slice(from, m.index));
    if (!a) continue;
    if (!/%[Is]|\|\|/.test(src.slice(from + a.index + a[0].length, m.index))) continue;
    if (!resolved.has(from + a.index)) return true;
  }
  return false;
}

// ════════════════════════════════════════════════════════════════════════
// supabase/edge-function-no-auth — internals (used by that rule only)
//
// On the edge-function files of 55 real repos, 34 of 134 findings were not
// an open function: _shared helper modules (the Portuguese prose
// "não serve (" read as a std serve() call), template assets inside a
// function dir, Deno test modules, and functions that DO authenticate their
// caller without a user JWT: a cron / admin secret header compared to a
// server-side secret, a bearer compared to the service-role key,
// auth.getClaims(), a provider's webhook-signature API. Those are recognised
// below. Deliberately NOT trusted, so they keep firing: a comparison to a
// PUBLIC key (anon / publishable: every visitor has it), a secret enforced
// only when it is configured (fail-open), a comparison that only logs or sets
// a flag nobody checks, jose's decodeJwt (no signature check), the text
// "verify_jwt = true" (in a .ts file it is a comment or a string; the real
// setting lives in config.toml, and the gateway also admits the anon key),
// and custom helpers (verifySessionOwner, a LOCAL verifyWebhook*), whose
// body this rule cannot judge.
//
// Known gaps, documented and not fixed: a gate in a helper that is never
// called; a gate on one HTTP method or route branch only;
// `undefined === undefined` when the secret is unset and the header is read
// with `?.`; a handler started through a wrapper (servirComCors, a _shared
// serve helper) is not seen, as before; public-by-design endpoints (captcha
// proxy, aggregate stats) still fire.
//
// Strictly per-file. Every quantifier on file text is bounded, every loop is
// capped and every lookback is a fixed window: each of ~30 adversarial
// 200 KB inputs runs in well under 0.1 s, the slowest real file in ~4 ms.
// ════════════════════════════════════════════════════════════════════════

// Bounded horizontal whitespace, and an equality operator that is not the
// first half of a longer one.
const EFNA_W = "[ \\t]{0,8}";
const EFNA_OP = "(?:===|!==|==|!=)(?!=)";
/** Identifiers may contain `$`, a regex metacharacter. */
const efnaEsc = (s: string) => s.replace(/\$/g, "\\$");

/**
 * Split a path at the edge-function root:
 * "apps/web/supabase/functions/track/index.ts" → { prefix: "apps/web/",
 * rest: "track/index.ts" }. Anchored at the LAST supabase…/functions/
 * segment pair, the shape isEdgeFunction accepts, so a sibling project dir
 * (supabase-saas/functions/) gets the same treatment as supabase/functions/.
 * Segment-wise, so no regex ever runs over the whole path.
 */
function efnaSplit(path: string): { prefix: string; rest: string } | null {
  const segs = path.replace(/\\/g, "/").split("/");
  for (let i = segs.length - 3; i >= 0; i--) {
    if (/^supabase[\w.-]*$/i.test(segs[i]) && segs[i + 1].toLowerCase() === "functions") {
      return {
        prefix: i > 0 ? segs.slice(0, i).join("/") + "/" : "",
        rest: segs.slice(i + 2).join("/"),
      };
    }
  }
  return null;
}

/**
 * Could this file be (part of) a deployed function?
 *  - Not under a folder whose name starts with "_" (_shared, _lib, at any
 *    depth): function names must start with a letter, so those folders are
 *    never deployed. A _shared serve wrapper is reported nowhere: the
 *    function that calls it has no handler of its own (a known gap).
 *  - Not a test: a test dir above the functions root, a test dir or file
 *    INSIDE a function, or foo.test.ts / foo_test.ts / foo-test.ts.
 *    isTestPath never sees the function's own folder name, so a deployed
 *    function called "test" (supabase/functions/test/index.ts) stays in scope.
 */
function efnaInScope(path: string): boolean {
  const parts = efnaSplit(path);
  if (!parts) return false;
  const { prefix, rest } = parts;
  if (/^(?:[^\/]{1,100}\/){0,10}_[^\/]{0,100}\//.test(rest)) return false;
  const slash = rest.indexOf("/");
  const inner = slash === -1 ? "" : rest.slice(slash + 1);
  return !(
    isTestPath(prefix) ||
    (inner !== "" && isTestPath(inner)) ||
    /[._-]test\.[cm]?[jt]sx?$/i.test(rest)
  );
}

/** The entry file Supabase deploys: <function>/index.ts (or .js, …). */
function efnaIsEntry(path: string): boolean {
  const parts = efnaSplit(path);
  return parts !== null && /^[^\/_][^\/]{0,100}\/index\.(?:ts|js|mjs|tsx|jsx)$/.test(parts.rest);
}

/**
 * Is `name` (letters only) imported by name? The same test as
 *   /import[ \t]{0,8}\{[^}]{0,300}\bNAME\b[^}]{0,300}\}[ \t]{0,8}from[ \t]{0,8}['"]/
 * plus, with packageOnly, (?!\.) after the quote (a package, not a local
 * file). Written as a walk because that regex re-scans 300 chars after every
 * candidate name: 200 KB of "import {serve " took 0.9 s. Here each
 * `import {` finds its closing `}` through one forward pointer, so the work
 * stays linear, and a body is only examined when it is short enough to match.
 */
function efnaImportsName(text: string, name: string, packageOnly: boolean): boolean {
  const open = /import[ \t]{0,8}\{/g;
  const after = packageOnly
    ? /^\}[ \t]{0,8}from[ \t]{0,8}['"](?!\.)/
    : /^\}[ \t]{0,8}from[ \t]{0,8}['"]/;
  let close = -1;
  let m: RegExpExecArray | null;
  while ((m = open.exec(text)) !== null) {
    const bodyStart = m.index + m[0].length;
    if (close < bodyStart) {
      close = text.indexOf("}", bodyStart);
      if (close === -1) return false;
    }
    // [^}] cannot cross a `}`, so the body is exactly the text up to the next
    // one, and it holds at most 300 chars on either side of the name.
    if (close - bodyStart > 600 + name.length) continue;
    if (!after.test(text.slice(close, close + 24))) continue;
    const body = text.slice(bodyStart, close);
    const nameRe = new RegExp("\\b" + name + "\\b", "g");
    let n: RegExpExecArray | null;
    while ((n = nameRe.exec(body)) !== null) {
      if (n.index > 300) break;
      if (body.length - n.index - name.length <= 300) return true;
    }
  }
  return false;
}

/**
 * Index of the request handler's first character, or -1 when the file has
 * none. Deno.serve( / serve( must not be a property or the tail of a longer
 * name (io.unobserve(), app.serve()), and a bare serve( only counts when
 * `serve` is imported: "não serve (ex.: 10,50)" in a message is prose.
 * `export default async req =>` (no parentheses) is a handler too.
 */
function efnaFindHandler(text: string): number {
  let m = /(?:^|[^\w$.])Deno\.serve[ \t]{0,8}\(/m.exec(text);
  if (m) return m.index + (m[0].startsWith("Deno") ? 0 : 1);
  if (efnaImportsName(text, "serve", false)) {
    m = /(?:^|[^\w$.])serve[ \t]{0,8}\(/m.exec(text);
    if (m) return m.index + (m[0].startsWith("serve") ? 0 : 1);
  }
  m = /export[ \t]{1,8}default[ \t]{1,8}(?:async\b|function\b|\()/.exec(text);
  if (m) return m.index;
  m = /export[ \t]{1,8}default[ \t]{0,8}\{\s{0,20}(?:async[ \t]{1,8})?fetch\b/.exec(text);
  if (m) return m.index;
  return -1;
}

// A user JWT: the Authorization header is read AND its signature verified.
// Bare `jose` is not proof (its decodeJwt checks no signature), nor is the
// text "verify_jwt".
const EFNA_READS_AUTH =
  /headers\.get\([ \t]{0,8}['"`]authorization['"`][ \t]{0,8}\)|headers\[[ \t]{0,8}['"`]authorization['"`][ \t]{0,8}\]/i;
const EFNA_VERIFIES_JWT =
  /auth\.getUser[ \t]{0,8}\(|\bgetClaims[ \t]{0,8}\(|\bjwtVerify[ \t]{0,8}\(|\bcreateRemoteJWKSet[ \t]{0,8}\(|\bjwt\.verify[ \t]{0,8}\(/;
const EFNA_DJWT_IMPORT = /from[ \t]{0,8}['"][^'"]{0,120}djwt[^'"]{0,60}['"]/;

// Env names that hold a server-side secret. An allow-list: ADMIN_EMAIL,
// ADMIN_USER_ID and ENVIRONMENT are not secrets, and SUPABASE_KEY is as
// often the public anon key as not, so comparing a header to them proves
// nothing.
const EFNA_SECRET_NAME =
  /SECRET|TOKEN|PASSW|PASSPHRASE|SIGNING|HMAC|SERVICE_ROLE|(?:^|_)(?:API_?)?KEYS?(?:_|$)/i;
const EFNA_NOT_SECRET_NAME =
  /ANON|PUBLISHABLE|PUBLIC|SITE_?KEY|_URL$|^URL$|_IDS?$|^(?:VITE|NEXT_PUBLIC|EXPO_PUBLIC|REACT_APP)_|^(?:SUPABASE|SB)_(?:API_)?KEY$/i;
const efnaIsSecretEnvName = (n: string) =>
  EFNA_SECRET_NAME.test(n) && !EFNA_NOT_SECRET_NAME.test(n);

// const X = Deno.env.get("N") | const X: string = (await Deno.env.get("N") ?? "").trim()
const EFNA_ENV_ASSIGN_SRC =
  "\\b(?:const|let|var)[ \\t]{1,8}([A-Za-z_$][\\w$]{0,63})" +
  EFNA_W +
  "(?::[^=\\n]{1,40})?=" +
  EFNA_W +
  "(?:\\(" +
  EFNA_W +
  ")?(?:await[ \\t]{1,8})?Deno\\.env\\.get\\(" +
  EFNA_W +
  "['\"`]([A-Za-z0-9_]{1,80})['\"`]" +
  EFNA_W +
  "\\)";

// A request header that carries a credential. x-user-id and other plain
// identifiers are client-chosen, so they are not one.
const EFNA_CRED_CALL_SRC =
  "headers\\.get\\(" +
  EFNA_W +
  "['\"`](?:authorization|apikey|x-api-key|x-[a-z0-9-]{0,40}(?:secret|key|token|signature|auth)[a-z0-9-]{0,20})['\"`]" +
  EFNA_W +
  "\\)";

// A rejection: return/throw carrying 401/403 or "unauthorized"/"forbidden".
const EFNA_DENY =
  /(?:return|throw)\b[^;]{0,200}?(?:\b40[13]\b|unauthori[sz]ed|forbidden)/i;

/**
 * Does the function compare a request credential to a server-side secret,
 * and reject the request when they differ? (cron / internal / webhook gates,
 * a bearer checked against the service-role key.)
 */
function efnaSecretGate(src: string): boolean {
  // 1. Server-side secrets: identifiers bound to a secret env var, and the
  //    secret env names themselves (an inline Deno.env.get("CRON_SECRET")).
  //    Identifiers bound to a PUBLIC key are collected to void a gate below.
  const ids = new Set<string>();
  const pubIds = new Set<string>();
  const envAssign = new RegExp(EFNA_ENV_ASSIGN_SRC, "g");
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = envAssign.exec(src)) !== null) {
    if (++guard > 200) break;
    if (efnaIsSecretEnvName(m[2])) ids.add(m[1]);
    if (/ANON|PUBLISHABLE|PUBLIC/i.test(m[2])) pubIds.add(m[1]);
  }
  const names = new Set<string>();
  const envGet = /Deno\.env\.get\([ \t]{0,8}['"`]([A-Za-z0-9_]{1,80})['"`][ \t]{0,8}\)/g;
  guard = 0;
  while ((m = envGet.exec(src)) !== null) {
    if (++guard > 200) break;
    if (efnaIsSecretEnvName(m[1])) names.add(m[1]);
  }
  const idList = [...ids].slice(0, 50).map(efnaEsc);
  const nameList = [...names].slice(0, 50);
  if (idList.length === 0 && nameList.length === 0) return false;
  const refAlts: string[] = [];
  // SECRET.length is a length check, not a comparison of the value.
  if (idList.length) {
    refAlts.push("\\b(?:" + idList.join("|") + ")\\b(?![ \\t]{0,8}\\.[ \\t]{0,8}length\\b)");
  }
  if (nameList.length) {
    refAlts.push(
      "Deno\\.env\\.get\\(" + EFNA_W + "['\"`](?:" + nameList.join("|") + ")['\"`]" + EFNA_W + "\\)"
    );
  }
  const secretRef = "(?:" + refAlts.join("|") + ")";

  // 2. Request credentials: the header call itself, or a variable whose
  //    initializer reads it (hop 1) or uses such a variable (hop 2), e.g.
  //    const auth = req.headers.get("authorization"); const bearer = auth?.replace(…).
  //    The initializer runs on over continuation lines starting with ? : . | &.
  const decls: [string, string][] = [];
  const declRe =
    /\b(?:const|let|var)[ \t]{1,8}([A-Za-z_$][\w$]{0,63})[ \t]{0,8}(?::[^=\n]{1,40})?=((?:[^;\n]|\n[ \t]{0,40}[?:.|&]){0,300})/g;
  guard = 0;
  while ((m = declRe.exec(src)) !== null) {
    if (++guard > 3000) break;
    decls.push([m[1], m[2]]);
  }
  const credCall = new RegExp(EFNA_CRED_CALL_SRC, "i");
  const hop1 = new Set(decls.filter(([, rhs]) => credCall.test(rhs)).map(([v]) => v));
  const cred = new Set(hop1);
  if (hop1.size) {
    const hop1Re = new RegExp("\\b(?:" + [...hop1].slice(0, 50).map(efnaEsc).join("|") + ")\\b");
    for (const [v, rhs] of decls) if (!cred.has(v) && hop1Re.test(rhs)) cred.add(v);
  }
  const credIds = [...cred].slice(0, 50).map(efnaEsc);
  const credAtom =
    "(?:" + (credIds.length ? "\\b(?:" + credIds.join("|") + ")\\b|" : "") + "\\u0001\\u0002{0,120})";
  // Each header call (matched case-insensitively) becomes a same-length
  // placeholder, \u0001 then \u0002 padding: offsets stay aligned with src and
  // the comparison regexes stay case-sensitive.
  const s2 = src.replace(
    new RegExp(EFNA_CRED_CALL_SRC, "gi"),
    (x) => "\u0001" + "\u0002".repeat(x.length - 1)
  );

  // 3. Candidate comparisons: cred <op> secret, secret <op> cred (also
  //    `Bearer ${secret}`), or a constant-time compare taking both.
  const g1 = new RegExp(
    credAtom +
      "((?:(?!\\.length\\b)[^\\n;&|\\u0001\\u0002]){0,80}?)(" +
      EFNA_OP +
      ")\\s{0,8}(?:`[^`\\n]{0,20}\\$\\{" +
      EFNA_W +
      ")?" +
      secretRef,
    "g"
  );
  const g2 = new RegExp("(?:^|[^\\w$.])" + secretRef + EFNA_W + "(" + EFNA_OP + ")\\s{0,8}" + credAtom, "g");
  const g3 = new RegExp(
    "(!?)" +
      EFNA_W +
      "(?:timingSafeEqual|safeEqual|constantTimeEqual|secureCompare|timingSafeCompare|safeCompare)" +
      EFNA_W +
      "\\(([^;\\n]{0,240})",
    "g"
  );
  const credRe = new RegExp(credAtom);
  const secRe = new RegExp(secretRef);
  const cands: { idx: number; neg: boolean }[] = [];
  const finders: [RegExp, 1 | 2 | 3][] = [
    [g1, 1],
    [g2, 2],
    [g3, 3],
  ];
  for (const [re, kind] of finders) {
    guard = 0;
    while ((m = re.exec(s2)) !== null) {
      if (++guard > 100) break;
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      if (kind === 3) {
        if (!(credRe.test(m[2]) && secRe.test(m[2]))) continue;
        cands.push({ idx: m.index, neg: m[1] === "!" });
      } else {
        cands.push({ idx: m.index, neg: /^(?:!==|!=)$/.test(kind === 1 ? m[2] : m[1]) });
      }
    }
  }

  // The same condition / assignment also accepting a PUBLIC key
  // (token !== SERVICE_ROLE && token !== ANON) authenticates nobody.
  const pubAlts = [
    "Deno\\.env\\.get\\(" +
      EFNA_W +
      "['\"`][A-Za-z0-9_]{0,40}(?:ANON|PUBLISHABLE|PUBLIC)[A-Za-z0-9_]{0,40}['\"`]" +
      EFNA_W +
      "\\)",
  ];
  if (pubIds.size) pubAlts.push("\\b(?:" + [...pubIds].slice(0, 50).map(efnaEsc).join("|") + ")\\b");
  const pubAlt = "(?:" + pubAlts.join("|") + ")";
  const pubRef = new RegExp(
    EFNA_OP + "\\s{0,8}(?:`[^`\\n]{0,20}\\$\\{" + EFNA_W + ")?" + pubAlt + "|" + pubAlt + EFNA_W + EFNA_OP,
    "i"
  );
  // Fail-open shapes: the secret is only enforced when it is configured.
  const secretIdAlt = idList.length ? "(?:" + idList.join("|") + ")" : null;
  const failOpenAnd = secretIdAlt
    ? new RegExp("(?:^|[^\\w$.!])" + secretIdAlt + "[ \\t]{0,8}&&")
    : null;
  const failOpenTernary = secretIdAlt
    ? new RegExp("(?:^|[^\\w$.!])" + secretIdAlt + "[ \\t]{0,8}\\?")
    : null;
  const failOpenBlock = secretIdAlt
    ? new RegExp("if" + EFNA_W + "\\(" + EFNA_W + secretIdAlt + EFNA_W + "\\)" + EFNA_W + "\\{[^}]{0,250}$")
    : null;

  // 4. A candidate counts only when it decides a rejection.
  for (const c of cands.slice(0, 20)) {
    // The statement so far: up to 200 chars back, cut after the last ; { }.
    const b200 = s2.slice(Math.max(0, c.idx - 200), c.idx);
    const cut = Math.max(b200.lastIndexOf(";"), b200.lastIndexOf("{"), b200.lastIndexOf("}"));
    const stmt = b200.slice(cut + 1);
    // Its form: whichever of `if (` / `const V =` starts LAST. Neither means
    // the comparison sits in a log call, an object literal or a return value.
    let pIf = -1;
    let pAsg = -1;
    let asgVar: string | null = null;
    let mm: RegExpExecArray | null;
    const ifRe = /\bif[ \t]{0,8}\(/g;
    while ((mm = ifRe.exec(stmt)) !== null) pIf = mm.index;
    const asgRe = /\b(?:const|let|var)[ \t]{1,8}([A-Za-z_$][\w$]{0,63})[ \t]{0,8}(?::[^=;{}]{1,40})?=(?!=)/g;
    while ((mm = asgRe.exec(stmt)) !== null) {
      pAsg = mm.index;
      asgVar = mm[1];
    }
    if (pIf < 0 && pAsg < 0) continue;
    const isAsg = pAsg > pIf;
    const head = stmt.slice(Math.max(pIf, pAsg));
    const tail = s2.slice(c.idx, c.idx + 300);
    const tcut = tail.search(/;|\n[ \t]*\n|\bif\b|\breturn\b|\bthrow\b|\)[ \t]*\{/);
    if (pubRef.test(head + (tcut >= 0 ? tail.slice(0, tcut) : tail))) continue;
    if (failOpenAnd && failOpenTernary && failOpenBlock) {
      // if (SECRET && provided !== SECRET) return 401: unset secret = open.
      if (!isAsg && c.neg && failOpenAnd.test(head)) continue;
      // const ok = SECRET ? provided === SECRET : true
      if (
        isAsg &&
        failOpenTernary.test(head) &&
        /^[^;]{0,200}?:[ \t]{0,8}true\b/.test(src.slice(c.idx, c.idx + 200))
      ) {
        continue;
      }
      // if (SECRET) { …check… }: skipped entirely when unset.
      if (failOpenBlock.test(src.slice(Math.max(0, c.idx - 300), c.idx))) continue;
    }
    if (isAsg && asgVar !== null) {
      // const ok = cred === SECRET; … if (!ok) return 401 (within 1200 chars).
      const vRe = new RegExp("\\b" + efnaEsc(asgVar) + "\\b");
      const win = src.slice(c.idx, c.idx + 1200);
      const ifCond = /\bif[ \t]{0,8}\(([^)\n]{0,200})\)/g;
      let im: RegExpExecArray | null;
      let ig = 0;
      while ((im = ifCond.exec(win)) !== null) {
        if (++ig > 10) break;
        if (vRe.test(im[1]) && EFNA_DENY.test(win.slice(im.index, im.index + 300))) return true;
      }
    } else if (EFNA_DENY.test(src.slice(c.idx, c.idx + 400))) {
      return true;
    }
  }
  return false;
}

/**
 * Verified with a provider's signature API: Stripe constructEvent, svix /
 * standardwebhooks Webhook.verify, or a verifyWebhook* helper IMPORTED from a
 * package (a local one is unjudged code), with a rejection in the file. Bare
 * createHmac / crypto.subtle.sign never count: they also SIGN outbound data.
 */
function efnaWebhookVerified(src: string): boolean {
  const stripe = /\.webhooks\.constructEvent(?:Async)?[ \t]{0,8}\(/.test(src);
  const svix = /\bnew[ \t]{1,8}Webhook[ \t]{0,8}\(/.test(src) && /\.verify[ \t]{0,8}\(/.test(src);
  if (stripe || svix) {
    // Veto: the verified variable is also filled from the raw body
    // (event = JSON.parse(body) when the secret or signature is missing).
    let unsignedFallback = false;
    const asg =
      /\b([A-Za-z_$][\w$]{0,63})[ \t]{0,8}=[ \t]{0,8}(?:await[ \t]{1,8})?[\w$.]{0,80}?(?:\.webhooks\.constructEvent(?:Async)?|\.verify)[ \t]{0,8}\(/g;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = asg.exec(src)) !== null) {
      if (++guard > 20) break;
      const fallback = new RegExp(
        "\\b" +
          efnaEsc(m[1]) +
          "[ \\t]{0,8}=[ \\t]{0,8}(?:await[ \\t]{1,8})?(?:JSON\\.parse[ \\t]{0,8}\\(|(?:req|request)\\.json[ \\t]{0,8}\\()"
      );
      if (fallback.test(src)) {
        unsignedFallback = true;
        break;
      }
    }
    if (!unsignedFallback) return true;
  }
  const vw = /\b(verifyWebhook[A-Za-z]{0,20})[ \t]{0,8}\(/.exec(src);
  if (vw && /\b40[13]\b|unauthori[sz]ed|forbidden/i.test(src) && efnaImportsName(src, vw[1], true)) {
    return true;
  }
  return false;
}

// ── @supabase/server: withSupabase and its primitives ───────────────────
//
// Supabase's "Securing Edge Functions" guide (docs/guides/functions/auth)
// wraps the handler in withSupabase({ auth: <mode> }, handler) from
// @supabase/server. The wrapper reads the Authorization and apikey headers
// itself, so the file never calls headers.get("authorization"), and the
// checks above used to flag the guide's own example. Modes, as read from
// the package (v1.9.2: README, docs/auth-modes.md, src/core/
// verify-credentials.ts, src/core/utils/deprecation.ts):
//   'user'                                  a JWT verified against the
//                                           project JWKS (the default)
//   'secret' | 'secret:<name>' | 'secret:*' a secret API key on `apikey`
//   'publishable' | 'publishable:<name>' | 'publishable:*'
//                                           a PUBLIC key (shipped in every
//                                           client), so not authentication
//   'none'                                  every caller
// An array tries each mode in order and admits whoever matches ANY of them,
// so it authenticates only when EVERY entry does (['user', 'none'] is
// "optional user"). Without an `auth` key the mode is `allow` (deprecated
// alias), else 'user'. createSupabaseContext (package root) and verifyAuth
// (@supabase/server/core) take the same option but return { data, error }
// instead of rejecting, so they count only when the file returns or throws
// on that error.
//
// The gate holds only when one of these names is imported from
// @supabase/server, called at least once, and EVERY call (outside strings
// and comments) has a config this code can read whose mode authenticates.
// A config it cannot read (a spread, an imported object, a variable or
// conditional mode, a shorthand { auth }, a computed or accessor key, a
// `const` object that is touched again) keeps the rule firing, as does any
// non-call use of the imported name (an alias) and, when a gate sits on one
// router route or path prefix, any registered route it does not cover.
// Known gaps, as for the gates above: a gated call that does not wrap the
// served handler is still trusted, and so is .use(gate) inside a scoped
// group (Elysia's .group('/api', …)).

/** Where @supabase/server is imported from: the package (bare, npm:, or an
 *  esm.sh URL, optionally versioned), its /core primitives or an adapter. */
const EFNA_SBS_FROM =
  /\bfrom\s{0,8}['"]((?:npm:|https?:\/\/esm\.sh\/)?@supabase\/server(?:@[\w.^~*-]{1,40})?(?:\/(?:core|adapters\/[a-z0-9-]{1,20}))?(?:\?[^'"\n]{0,80})?)['"]/g;
const EFNA_SBS_WRAP = "withSupabase";
const EFNA_SBS_PRIMS = new Set(["createSupabaseContext", "verifyAuth"]);

const efnaSkipWs = (s: string, i: number, end: number) => {
  while (i < end && /\s/.test(s[i])) i++;
  return i;
};

/** A '…' / "…" / `…` literal starting at s[i]: [value, index after it], or
 *  null for an unterminated literal or a template with ${…} in it. */
function efnaStrLit(s: string, i: number, end: number): [string, number] | null {
  const q = s[i];
  let v = "";
  for (let j = i + 1; j < end; j++) {
    const ch = s[j];
    if (ch === "\\") {
      v += s[j + 1] ?? "";
      j++;
      continue;
    }
    if (ch === q) return [v, j + 1];
    if (q === "`" && ch === "$" && s[j + 1] === "{") return null;
    if (ch === "\n" && q !== "`") return null;
    v += ch;
  }
  return null;
}

/** Index just past the string literal starting at s[i], or -1. */
function efnaSkipStr(s: string, i: number, end: number): number {
  const q = s[i];
  for (let j = i + 1; j < end; j++) {
    if (s[j] === "\\") {
      j++;
      continue;
    }
    if (s[j] === q) return j + 1;
    if (s[j] === "\n" && q !== "`") return -1;
  }
  return -1;
}

/** The value of `auth:` / `allow:` at s[i]: one string literal or an array of
 *  them (optionally `as const`), followed by `,` or `}`. Anything else is an
 *  expression this code does not evaluate: null. */
function efnaModeValue(s: string, i: number, end: number): [string[], number] | null {
  const list: string[] = [];
  let j = i;
  const isQ = (c: string | undefined) => c === "'" || c === '"' || c === "`";
  if (s[j] === "[") {
    j = efnaSkipWs(s, j + 1, end);
    for (let n = 0; n < 12 && s[j] !== "]"; n++) {
      if (!isQ(s[j])) return null;
      const lit = efnaStrLit(s, j, end);
      if (!lit) return null;
      list.push(lit[0]);
      j = efnaSkipWs(s, lit[1], end);
      if (s[j] === ",") j = efnaSkipWs(s, j + 1, end);
      else if (s[j] !== "]") return null;
    }
    if (s[j] !== "]") return null;
    j++;
  } else if (isQ(s[j])) {
    const lit = efnaStrLit(s, j, end);
    if (!lit) return null;
    list.push(lit[0]);
    j = lit[1];
  } else {
    return null;
  }
  j = efnaSkipWs(s, j, end);
  const asConst = /^as[ \t]{1,8}const\b/.exec(s.slice(j, j + 20));
  if (asConst) j = efnaSkipWs(s, j + asConst[0].length, end);
  return s[j] === "," || s[j] === "}" ? [list, j] : null;
}

/**
 * The auth modes of the object literal opening at s[open]: its top-level
 * `auth`, else `allow`, else the package default ['user']. Nested objects
 * (cors headers, env) are skipped, strings are skipped whole. null when the
 * object cannot be read: a spread, a shorthand auth key, any computed,
 * numeric or accessor key (['auth'], get auth()), an unevaluated value, or
 * no closing brace within 4000 characters.
 */
function efnaObjectModes(s: string, open: number): string[] | null {
  const end = Math.min(s.length, open + 4000);
  let auth: string[] | undefined;
  let allow: string[] | undefined;
  let depth = 0;
  let expectKey = true;
  let i = open + 1;
  for (let steps = 0; i < end; steps++) {
    if (steps > 8000) return null;
    const ch = s[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (depth === 0 && expectKey) {
      expectKey = false;
      if (s.startsWith("...", i)) return null;
      let key: string | null = null;
      let after = i;
      if (ch === "'" || ch === '"') {
        const lit = efnaStrLit(s, i, end);
        if (!lit) return null;
        key = lit[0];
        after = lit[1];
      } else {
        const km = /^[A-Za-z_$][\w$]{0,63}/.exec(s.slice(i, i + 64));
        if (km) {
          key = km[0];
          after = i + km[0].length;
        } else if (ch !== "}") {
          // A computed ['auth'] key, a numeric key or a generator method:
          // which key it sets is not read here.
          return null;
        }
      }
      if (key !== null) {
        const k = efnaSkipWs(s, after, end);
        // get auth() { … } / set auth(v) / async auth(): an accessor or a
        // method whose name follows the keyword, not a key named get/set.
        if ((key === "get" || key === "set" || key === "async") && /[A-Za-z_$[\]'"*]/.test(s[k] ?? "")) {
          return null;
        }
        if (key === "auth" || key === "allow") {
          if (s[k] !== ":") return null;
          const v = efnaModeValue(s, efnaSkipWs(s, k + 1, end), end);
          if (!v) return null;
          if (key === "auth") auth = v[0];
          else allow = v[0];
          i = v[1];
          continue;
        }
        i = k;
        continue;
      }
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      const e = efnaSkipStr(s, i, end);
      if (e < 0) return null;
      i = e;
      continue;
    }
    if (ch === "{" || ch === "[" || ch === "(") {
      depth++;
    } else if (ch === "}" || ch === "]" || ch === ")") {
      if (depth === 0) {
        if (ch !== "}") return null;
        return auth !== undefined ? auth : allow !== undefined ? allow : ["user"];
      }
      depth--;
    } else if (ch === "," && depth === 0) {
      expectKey = true;
    }
    i++;
  }
  return null;
}

/**
 * `s` with the inside of every string literal and every `//` comment blanked
 * to spaces (quotes and newlines kept), so its indices line up with `s`. The
 * gate searches this view for code, so text inside a string is never a call,
 * and a `//` comment that stripJsComments keeps (one right after a quote or
 * `:`, as in `'x'// withSupabase(…)`) is gone too. A template literal is
 * blanked whole, ${…} included.
 */
function efnaCodeView(s: string): string {
  const out: string[] = [];
  let i = 0;
  const blankTo = (to: number) => {
    for (; i < to; i++) out.push(s[i] === "\n" ? "\n" : " ");
  };
  while (i < s.length) {
    const ch = s[i];
    if (ch === "/" && s[i + 1] === "/") {
      const nl = s.indexOf("\n", i);
      blankTo(nl < 0 ? s.length : nl);
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      out.push(ch);
      i++;
      let j = i;
      while (j < s.length && s[j] !== ch && (ch === "`" || s[j] !== "\n")) j += s[j] === "\\" ? 2 : 1;
      blankTo(Math.min(j, s.length));
      if (s[i] === ch) {
        out.push(ch);
        i++;
      }
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join("");
}

/** The modes of the config argument at c: an object literal, or an
 *  identifier bound exactly once by `const X = { … }` in the code (`let`, a
 *  second binding or a commented-out one does not count). For an identifier
 *  it also returns the name and where the declaration names it, so the gate
 *  can check that nothing else touches the object. */
function efnaConfigModes(
  src: string,
  code: string,
  c: number
): { modes: string[]; id?: string; declAt?: number } | null {
  if (src[c] === "{") {
    const modes = efnaObjectModes(src, c);
    return modes ? { modes } : null;
  }
  const id = /^([A-Za-z_$][\w$]{0,63})\s{0,8}[,)]/.exec(code.slice(c, c + 80));
  if (!id) return null;
  const decl = new RegExp(
    "\\b(const[ \\t]{1,8})" + efnaEsc(id[1]) + "[ \\t]{0,8}(?::[^=\\n]{1,80})?=[ \\t]{0,8}\\{",
    "g"
  );
  const found: RegExpExecArray[] = [];
  let m: RegExpExecArray | null;
  while ((m = decl.exec(code)) !== null && found.length < 2) found.push(m);
  if (found.length !== 1) return null;
  const modes = efnaObjectModes(src, found[0].index + found[0][0].length - 1);
  return modes ? { modes, id: id[1], declAt: found[0].index + found[0][1].length } : null;
}

/** A mode that admits only callers holding a credential the public lacks. */
const efnaModeAuthenticates = (mode: string) =>
  mode === "user" || /^secret(?::[^\s'"`]{0,64})?$/.test(mode);

/**
 * createSupabaseContext / verifyAuth at `at` (its `(` at `open`) return
 * { data, error }: the call gates only when its error is bound
 * (`const { error } = await …`, `{ error: e }`, or `const r = await …` read
 * as r.error) and the very next statement is `if (error …) return|throw`.
 * A check further down can test another `error` (a catch parameter, a
 * nested callback's) and does not prove this one is handled. `code` is the
 * efnaCodeView text, so a commented-out check is not seen.
 */
function efnaPrimitiveRejects(code: string, at: number, open: number): boolean {
  const s = code;
  const back = s.slice(Math.max(0, at - 260), at);
  let err: string;
  const d = /\b(?:const|let|var)\s{1,8}\{([^{}]{0,200})\}\s{0,8}=\s{0,8}(?:await\s{1,8})?$/.exec(back);
  if (d) {
    const e = /(?:^|,)\s{0,40}error\s{0,8}(?::\s{0,8}([A-Za-z_$][\w$]{0,63}))?\s{0,8}(?=,|$)/.exec(d[1]);
    if (!e) return false;
    err = efnaEsc(e[1] ?? "error") + "\\b";
  } else {
    const v = /\b(?:const|let|var)\s{1,8}([A-Za-z_$][\w$]{0,63})\s{0,8}(?::[^=\n]{1,80})?=\s{0,8}(?:await\s{1,8})?$/.exec(back);
    if (!v) return false;
    err = "\\b" + efnaEsc(v[1]) + "\\s{0,8}\\??\\.\\s{0,8}error\\b";
  }
  // The end of the call: its matching `)` (strings are blank in `code`).
  let end = -1;
  for (let i = open, depth = 0; i < Math.min(s.length, open + 4000); i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")" && --depth === 0) {
      end = i + 1;
      break;
    }
  }
  if (end < 0) return false;
  const reject = new RegExp(
    "^[\\s;]{0,400}if\\s{0,8}\\(\\s{0,8}" +
      err +
      "\\s{0,8}(?:(?:!==|!=)\\s{0,8}(?:null|undefined)\\s{0,8})?(?:\\|\\|[^()\\n]{0,80})?\\)\\s{0,40}\\{?\\s{0,40}(?:return|throw)\\b"
  );
  return reject.test(s.slice(end, end + 800));
}

/** A gate call that is an argument of a router method with a path first:
 *  app.get('/todos', withSupabase(…), handler) or app.use('/admin/*', …).
 *  Up to four simple middleware arguments may come before it. */
const EFNA_ROUTE_ARG =
  /\.\s{0,8}(get|post|put|patch|delete|all|options|head|use)\s{0,8}\(\s{0,40}(['"`])([^'"`\n]{0,200})\2\s{0,40},\s{0,40}(?:[\w$.]{1,60}(?:\(\s{0,8}\))?\s{0,40},\s{0,40}){0,4}$/;
/** A gate call that is the only argument of .use(…): middleware for every
 *  route. */
const EFNA_USE_ALL = /\.\s{0,8}use\s{0,8}\(\s{0,40}$/;
/** A route registration with a path first: app.post('/wipe', handler). */
const EFNA_ROUTE_REG =
  /\.\s{0,8}(get|post|put|patch|delete|all|options|head)\s{0,8}\(\s{0,40}(['"`])([^'"`\n]{0,200})\2\s{0,40},/g;

/** Is every @supabase/server gate in the file (and there is at least one)
 *  configured with authenticating modes? */
function efnaSupabaseServerGate(src: string): boolean {
  if (src.indexOf("@supabase/server") === -1) return false;
  // 1. Local names of withSupabase / the primitives imported from the package.
  const wrap = new Set<string>();
  const prim = new Set<string>();
  const importSpans: [number, number][] = []; // `{ … } from '…'` of those imports
  const from = new RegExp(EFNA_SBS_FROM.source, "g");
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = from.exec(src)) !== null) {
    if (++guard > 20) break;
    const win = src.slice(Math.max(0, m.index - 700), m.index);
    const close = win.lastIndexOf("}");
    if (close < 0 || !/^\s{0,8}$/.test(win.slice(close + 1))) continue;
    const open = win.lastIndexOf("{", close);
    if (open < 0) continue;
    // A commented-out `// import { … }` never reaches here: src is
    // stripJsComments output, which removes `//` comments at every column.
    const absOpen = Math.max(0, m.index - 700) + open;
    // `import {` or `import Default, {`. `import type { … }` brings in no
    // runtime value, so it does not match.
    if (!/\bimport\s{1,8}(?:[A-Za-z_$][\w$]{0,63}\s{0,8},\s{0,8})?$|\bimport\{$/.test(win.slice(Math.max(0, open - 90), open))) {
      continue;
    }
    for (const part of win.slice(open + 1, close).split(",").slice(0, 30)) {
      const spec = /^\s*([A-Za-z_$][\w$]{0,63})(?:\s+as\s+([A-Za-z_$][\w$]{0,63}))?\s*$/.exec(part);
      if (!spec || spec[1] === "type") continue;
      const local = spec[2] ?? spec[1];
      if (spec[1] === EFNA_SBS_WRAP) wrap.add(local);
      else if (EFNA_SBS_PRIMS.has(spec[1])) prim.add(local);
    }
    importSpans.push([absOpen, m.index + m[0].length]);
  }
  if (wrap.size === 0 && prim.size === 0) return false;
  // 2. Every reference to those names, outside strings and comments, must be
  //    a call with a readable, authenticating config. Any other use (an
  //    alias such as `const gate = withSupabase`, a pass-through, a
  //    re-export) can hide calls this scan never sees. `typeof X` in a type
  //    is fine.
  const code = efnaCodeView(src);
  const names = [...wrap, ...prim].slice(0, 10).map(efnaEsc);
  const ref = new RegExp("(?:^|[^\\w$.])(" + names.join("|") + ")(?![\\w$])", "g");
  const callOpen = /^[ \t]{0,8}(?:<[^<>()\n]{0,120}>)?[ \t]{0,8}\(/;
  const idUses = new Map<string, { declAt: number; at: Set<number> }>();
  let routeScoped = false; // a gate on one route (or one path prefix) only
  let useAll = false; // a gate as middleware for every route
  const scopedUse: string[] = []; // path prefixes gated by .use('/x/*', gate)
  const gatedRoutes = new Set<number>(); // registrations with a gate argument
  let calls = 0;
  let seen = 0;
  while ((m = ref.exec(code)) !== null) {
    if (++seen > 40) return false;
    const at = m.index + m[0].length - m[1].length;
    if (importSpans.some(([a, b]) => at >= a && at < b)) continue;
    const co = callOpen.exec(code.slice(at + m[1].length, at + m[1].length + 140));
    if (!co) {
      if (/\btypeof\s{1,8}$/.test(code.slice(Math.max(0, at - 20), at))) continue;
      return false;
    }
    if (++calls > 20) return false;
    const open = at + m[1].length + co[0].length - 1;
    let c = efnaSkipWs(code, open + 1, Math.min(code.length, open + 41));
    const isPrim = prim.has(m[1]);
    if (isPrim) {
      // (req, { auth: … }): step over the request argument.
      const a = /^[\w$.]{1,60}\s{0,20},\s{0,40}/.exec(code.slice(c, c + 140));
      if (!a) return false;
      c += a[0].length;
    }
    const cfg = efnaConfigModes(src, code, c);
    if (!cfg || cfg.modes.length === 0 || !cfg.modes.every(efnaModeAuthenticates)) return false;
    if (cfg.id !== undefined && cfg.declAt !== undefined) {
      const u = idUses.get(cfg.id) ?? { declAt: cfg.declAt, at: new Set<number>() };
      u.at.add(c);
      idUses.set(cfg.id, u);
    }
    if (isPrim && !efnaPrimitiveRejects(code, at, open)) return false;
    // Router placement: app.get('/x', gate, h) or app.use('/x/*', gate) gates
    // part of the app; app.use(gate) or app.use('*', gate) all of it.
    const base = Math.max(0, at - 300);
    const before = code.slice(base, at);
    const r = EFNA_ROUTE_ARG.exec(before);
    if (r) {
      const q = base + r.index + r[0].indexOf(r[2]) + 1;
      const path = src.slice(q, q + r[3].length);
      if (r[1] === "use" && (path === "*" || path === "/*")) useAll = true;
      else {
        routeScoped = true;
        if (r[1] === "use") scopedUse.push(path);
        else gatedRoutes.add(base + r.index);
      }
    } else if (EFNA_USE_ALL.test(before)) {
      useAll = true;
    }
  }
  if (calls === 0) return false;
  // 3. A config object bound by `const` must not be touched anywhere else:
  //    Object.assign(config, …) or config.auth = 'none' changes the mode.
  for (const [id, u] of idUses) {
    const occ = new RegExp("(?:^|[^\\w$.])(" + efnaEsc(id) + ")(?![\\w$])", "g");
    let n = 0;
    while ((m = occ.exec(code)) !== null) {
      if (++n > 40) return false;
      const p = m.index + m[0].length - id.length;
      if (p !== u.declAt && !u.at.has(p)) return false;
    }
  }
  // 4. With a per-route gate, every route the file registers must be gated:
  //    by its own gate argument, a .use() prefix that covers its path, or an
  //    app-wide .use(). Hono's adapter docs show per-route gates beside an
  //    open route, which is how an unguarded route slips past.
  if (routeScoped && !useAll) {
    const reg = new RegExp(EFNA_ROUTE_REG.source, "g");
    let n = 0;
    while ((m = reg.exec(code)) !== null) {
      if (++n > 60) return false;
      const q = m.index + m[0].indexOf(m[2]) + 1;
      const path = src.slice(q, q + m[3].length);
      if (!/^[/*]/.test(path) || gatedRoutes.has(m.index)) continue;
      const covered = scopedUse.some(
        (p) => p === path || (p.endsWith("*") && path.startsWith(p.slice(0, -1)))
      );
      if (!covered) return false;
    }
  }
  return true;
}

// ════════════════════════════════════════════════════════════════════════
// supabase/public-storage-bucket — internals (used by that rule only)
//
// On 55 real repos, 10 of 24 findings were buckets that are public on
// purpose: avatars, logos, cover art, product and profile images. A
// statement or call is now skipped only when EVERY bucket it makes public
// has an asset name AND that name is proven: a plain literal id in each
// VALUES row, `WHERE id|name = '…'` or `IN ('…', …)`, a literal createBucket()
// argument, or every literal assigned to the identifier anywhere in the file.
// Whatever cannot be proven fires as before: INSERT … SELECT, an aliased
// INSERT, a column list not led by id, an id expression ('a' || b, a call,
// $1), <> / NOT IN / LIKE / OR in the WHERE, a typed or defaulted parameter,
// a non-literal or compound assignment, a statement past the 8000-character
// cap. A sensitive word vetoes an asset word, so "patient-avatars",
// "logo-invoices" and "profile-verification-photos" still fire.
//
// The old SQL regex also ran 400 characters past the INSERT, so a `true` in
// the NEXT statement (another bucket, a USING (true) policy) or in a comment
// flagged a private bucket, on the wrong line. Each statement is now read on
// its own, comments blanked, up to its `;`.
//
// Known gaps, documented and not fixed: generic names stay flagged
// (company-assets, exercise-images); a bucket made public in one migration
// and private in a later one is still reported (strictly per-file); and
// supabase/config.toml `[storage.buckets.<name>] public = true` is not
// scanned by any rule. stripJsComments is not string-aware, so a string
// holding "/*" (an 'image/*' MIME type) blanks code up to the next "*/"; an
// assignment inside that span is not seen by identifier resolution.
//
// Every quantifier is bounded or its adjacent \s* runs are split by a
// mandatory literal; dynamic regexes are built from [\w$] identifiers only;
// every loop is capped (500 / 200 / 200) and hitting a cap means fire.
// ════════════════════════════════════════════════════════════════════════

// Words that never name a public-asset bucket, wherever they sit in the
// name. EXACT holds short tokens that would over-match as prefixes (id, rg,
// docs); PREFIX also covers plurals and pt/es/tr forms. Deliberately absent:
// bank, clinic, firma, legal, bare "doc" and bare "ident" — bank-logos,
// clinic-logos, firma-logos (German/Polish "company"), doctor-avatars and
// identicons are genuine asset buckets.
const PSB_VETO_EXACT =
  /^(ids?|kyc|ssn|cpf|rg|dni|nif|nie|cvs?|pii|phi|tax(es)?|nsfw|faces?|facial|docs?|firmas)$/;
const PSB_VETO_PREFIX =
  /^(privat|privad|secret|confiden|internal|interno|document|pdf|contract|contrat|invoice|factur|fatur|receipt|recibo|comprovant|signature|assinatura|passport|pasaport|passaport|licen|medic|health|saude|salud|patient|pacient|backup|export|attach|anexo|statement|payslip|payroll|fiscal|report|relator|letter|resume|curricul|verif|selfie|biometr|reconhec|recono|recogni|identit|identif|insur|seguro|nude|adult|explicit|evidenc)/;
// Enough on their own.
const PSB_ASSET =
  /^(avatars?|logos?|covers?|banners?|icons?|favicons?|emojis?|stickers?|branding)$/;
// An image word alone is NOT enough (job-photos, service-order-photos hold
// customer data), nor is "products" alone (paid downloads): only together.
const PSB_IMAGE_OWNER = /^(profile|profil|perfil|products?)$/;
const PSB_IMAGE =
  /^(images?|imgs?|pictures?|pics?|photos?|fotos?|resim|resimler|resimleri|imagem|imagens|imagen|imagenes|bild|bilder)$/;

/**
 * True when a bucket name says it only holds public assets. Never allowlisted
 * on their own: images, photos, media, assets, uploads, files, thumbnails,
 * public, static, products.
 */
function isPublicAssetBucketName(name: string): boolean {
  const tokens = String(name)
    .slice(0, 120)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  if (tokens.length === 0) return false;
  if (tokens.some((t) => PSB_VETO_EXACT.test(t) || PSB_VETO_PREFIX.test(t))) return false;
  if (tokens.some((t) => PSB_ASSET.test(t))) return true;
  return tokens.some((t) => PSB_IMAGE_OWNER.test(t)) && tokens.some((t) => PSB_IMAGE.test(t));
}

// storage.buckets, each part optionally "quoted" (pg_dump style).
const PSB_BUCKETS = String.raw`"?storage"?\s*\.\s*"?buckets"?(?![\w$])`;
const PSB_STMT_SRC = String.raw`\b(insert\s+into|update)\s+` + PSB_BUCKETS;
const PSB_INSERT_HEAD = new RegExp(
  String.raw`^insert\s+into\s+` + PSB_BUCKETS + String.raw`\s*(?:\(([^()]{0,300})\))?`,
  "i"
);
// The WHERE of an UPDATE, whole: only `id|name = 'x'` or `id|name IN ('x', …)`.
// <>, !=, NOT IN, LIKE, OR / AND and subqueries do not match, so they fire.
const PSB_UPDATE_WHERE =
  /^\(?\s*(?:"?storage"?\s*\.\s*)?(?:"?buckets"?\s*\.\s*)?"?(?:id|name)"?\s*(?:=\s*'([^'\n]{1,100})'|in\s*\(\s*('[^'\n]{1,100}'(?:\s*,\s*'[^'\n]{1,100}')*)\s*\))\s*\)?$/i;
// createBucket(name, …) / updateBucket(name, …): the first argument is a
// literal (group 2, which must be followed by ',' so 'avatars' + x fails) or
// a dotted identifier (group 3). Applied to the hit only, so it is bounded.
const PSB_ARG_RE =
  /^\w+\s*\(\s*(?:(['"`])([^'"`\n]{1,100})\1\s*,|([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*){0,4})\s*,)/;

/**
 * Bucket ids of `INSERT INTO storage.buckets … VALUES …`, or null when they
 * cannot be proven (the rule then fires). Every row must open with a plain
 * literal followed by ',' or ')': a variable, $1, a function call or
 * 'a' || b anywhere in the id column makes the whole statement unprovable.
 */
function psbInsertIds(stmt: string): string[] | null {
  const head = PSB_INSERT_HEAD.exec(stmt);
  if (!head) return null;
  // The first listed column must be id; with no list, id is the table's
  // first column.
  if (
    head[1] !== undefined &&
    head[1].split(",")[0].replace(/"/g, "").trim().toLowerCase() !== "id"
  ) {
    return null;
  }
  const rest = stmt.slice(head[0].length);
  // INSERT … SELECT, DEFAULT VALUES, an alias (`as b`), OVERRIDING, …
  if (!/^\s*values\b/i.test(rest)) return null;
  const tupleRe =
    /(?:\bvalues|\))\s*(?:,\s*)?\(\s*(?:'([^'\n]{1,100})'(?:\s*::\s*[a-z_]{1,20})?(?=\s*[,)]))?/gi;
  const ids: string[] = [];
  let t: RegExpExecArray | null;
  let guard = 0;
  while ((t = tupleRe.exec(rest)) !== null) {
    if (++guard > 200) return null;
    if (t[1] === undefined) return null;
    ids.push(t[1]);
  }
  return ids.length ? ids : null;
}

/** Bucket ids an `UPDATE storage.buckets … WHERE` targets, or null (fire). */
function psbUpdateIds(stmt: string): string[] | null {
  const w = /\bwhere\b/i.exec(stmt);
  if (!w) return null;
  const rest = stmt.slice(w.index + 5).trim();
  if (rest.length === 0 || rest.length > 400) return null;
  const s = PSB_UPDATE_WHERE.exec(rest);
  if (!s) return null;
  if (s[1] !== undefined) return [s[1]];
  const ids: string[] = [];
  const lit = /'([^'\n]{1,100})'/g;
  let l: RegExpExecArray | null;
  while ((l = lit.exec(s[2])) !== null) ids.push(l[1]);
  return ids.length ? ids : null;
}

/**
 * Every literal assigned to `ident` in this (comment-blanked) file, or
 * unknown. Unknown when the name is a parameter or object property (typed,
 * defaulted, destructured), is compound-assigned, or ANY assignment has a
 * non-literal right-hand side (env var, ternary, call, `this.x = param`):
 * suppressing on the first literal found would hide a later reassignment.
 * Empty lits means no in-file definition (an imported constant).
 */
function psbResolveIdentifier(
  ident: string,
  clean: string
): { unknown: true } | { unknown: false; lits: string[] } {
  const id = ident.replace(/\$/g, "\\$");
  if (new RegExp("[(,{]\\s*" + id + "\\s*(?:\\?\\s*)?(?::|=(?![=>]))").test(clean)) {
    return { unknown: true };
  }
  if (new RegExp("(?:^|[^\\w$])" + id + "\\s*(?:\\+|-|\\|\\||\\?\\?|&&)=").test(clean)) {
    return { unknown: true };
  }
  // [^\w$] includes ".", so `this.bucket = name` counts as an assignment.
  const asg = new RegExp(
    "(?:^|[^\\w$])" +
      id +
      "\\s{0,5}(?::[^=\\n;(){}]{1,60})?=(?![=>])\\s{0,5}(?:(['\"`])([^'\"`\\n]{0,100})\\1)?",
    "g"
  );
  const lits: string[] = [];
  let a: RegExpExecArray | null;
  let guard = 0;
  while ((a = asg.exec(clean)) !== null) {
    if (++guard > 200) return { unknown: true };
    if (a[2] === undefined) return { unknown: true };
    lits.push(a[2]);
  }
  return { unknown: false, lits };
}

// Reported where a scan loop hits its cap: the rest of the file is not
// checked, and an unchecked bucket must not pass silently.
const PSB_GUARD_MESSAGE =
  "This file creates or updates more than 500 storage buckets, so GuardLayer stopped checking them one by one here. Any bucket from this point on may be public: every object in a public bucket is readable by anyone with the URL, with no authentication.";

/** Per-match message naming the non-asset buckets that are made public. */
function psbMessage(names: string[]): string {
  const uniq = [...new Set(names)];
  const shown = uniq.slice(0, 5).map((n) => `'${n}'`).join(", ");
  const more = uniq.length > 5 ? ` and ${uniq.length - 5} more` : "";
  return uniq.length === 1
    ? `Storage bucket ${shown} is created or updated as public. Every object in it is readable by anyone with the URL, with no authentication.`
    : `Storage buckets ${shown}${more} are created or updated as public. Every object in them is readable by anyone with the URL, with no authentication.`;
}

// ════════════════════════════════════════════════════════════════════════
// supabase/service-role-key-in-client — internals (used by that rule only)
//
// On 55 real repos both findings were a setup page that only NAMES the key:
// a 'SUPABASE_SERVICE_ROLE_KEY' checklist label and a `serviceRoleKey:
// boolean` "is it configured" field. Neither handles the key value.
//
// A line now fires when (A) a SINK matches the comment-blanked line (an env
// read, a Supabase client factory call, an apikey/Bearer header, a hardcoded
// key literal), OR (B) any mention on it is NOT one of the proven-benign
// shapes B1–B6 in srkBenign(). Everything else fires exactly as before:
// imported constants, props, destructuring, aliases, localStorage reads,
// a rendered value. Benign is opt-in; unknown means fire.
//
// Accepted residual FPs (the conservative direction): multi-line JSX prose
// naming the env var with no tag on that line, "bring your own Supabase"
// forms holding the key in state, i18n keys passed as a call's first
// argument, and type names like ServiceRoleKeyStatus outside `import type`.
//
// ReDoS: every quantifier is bounded and every look-around reads a fixed
// window (SRK_WIN chars, 120 for the per-file pass). The lexer is a single
// linear pass over one line.
// ════════════════════════════════════════════════════════════════════════

// Cheap line gate. Wider than the token: S1 also catches SUPABASE_SERVICE_KEY
// and SUPABASE_SECRET_KEY (new-style sb_secret_) env reads, S2/S3 `serviceRole`.
const SRK_PREFILTER = /service[_-]?role|SUPABASE_?(?:SERVICE|SECRET)_?KEY/i;
// The rule's original token, global for matchAll.
const SRK_TOKEN_G = /SUPABASE_SERVICE_ROLE_KEY|service[_-]?role[_-]?key/gi;
// A sink means the key VALUE is being read or used here: always fire.
const SRK_SINKS: RegExp[] = [
  // S1 env read: process.env.X, process.env['X'], import.meta.env.X, env.X,
  // serverEnv.X, env.server.X, getEnv('X'), requireEnv("X"), Deno.env.get('X')
  /env\s{0,5}(?:\.\s{0,5}(?:get\s{0,5}\(\s{0,5})?|\[\s{0,5}|\(\s{0,5})['"`]?[A-Z0-9_.]{0,64}(?:SERVICE_?ROLE|SUPABASE_?(?:SERVICE|SECRET)_?KEY)/i,
  // S2 Supabase client factory: createClient / createBrowserClient /
  // createServerClient / createXxxClient / new SupabaseClient; optional
  // generics; nested parens allowed in the argument list.
  /\b(?:create\w{0,40}Client|SupabaseClient)\s{0,5}(?:<[^()\n]{0,200}>)?\s{0,5}\([^;\n]{0,300}?service[_-]?role/i,
  // S3 header: `apikey: x`, `'apikey', x` (headers.set / setRequestHeader), `Bearer x`
  /(?:\bapikey['"`]?\s{0,5}[:,]|\bBearer\s)[^,}\n]{0,200}?service[_-]?role/i,
  // S4 hardcoded literal (>=20 key chars) assigned to a service-role-named var/prop
  /service[_-]?role[_-]?key['"`]?\s{0,5}[:=]\s{0,5}['"`][A-Za-z0-9._-]{20}/i,
];
// `serviceRoleKey: boolean`, `= true`, `: !!x` — a configured/missing flag, not
// the key. A union that also names `string` is NOT a flag.
const SRK_BOOL_VALUE =
  /^\??\s{0,5}[:=]\s{0,5}(?:(?:boolean|number|true|false)\b(?![^;,}\n]{0,80}\bstring\b)|!!)/i;
const SRK_WIN = 300;
// Lexer char states; 0 = code (the Uint8Array default).
const SRK_STR = 1;
const SRK_COMMENT = 2;
type SrkLine = {
  state: Uint8Array;
  lit: Int32Array;
  litOpen: number[];
  litClose: number[];
  code: string;
};

/** Widen [s, e) to the whole identifier around it (60-char cap each side), lowercased. */
function srkIdent(text: string, s: number, e: number) {
  let is = s;
  let ie = e;
  while (is > 0 && s - is < 60 && /[\w$]/.test(text[is - 1])) is--;
  while (ie < text.length && ie - e < 60 && /[\w$]/.test(text[ie])) ie++;
  return { ident: text.slice(is, ie).toLowerCase(), is, ie };
}

/**
 * Linear single-line lexer. Marks each char CODE / STR / COMMENT and records
 * each string literal's opening and closing quote index (-1 = unterminated on
 * this line). Handles \ escapes and template ${ } nesting. `code` is the line
 * with comment chars replaced by spaces (same length), so sinks never match a
 * mention inside `//`, `/* *\/` or JSX `{/* *\/}`, while a URL inside a string
 * ('https://…', protocol-relative '//host') is never mistaken for a comment.
 */
function srkLex(line: string): SrkLine {
  const n = line.length;
  const state = new Uint8Array(n);
  const lit = new Int32Array(n).fill(-1);
  const litOpen: number[] = [];
  const litClose: number[] = [];
  const tpl: { id: number; depth: number }[] = [];
  let inStr = false;
  let q = "";
  let cur = -1;
  let i = 0;
  const open = (at: number) => {
    cur = litOpen.length;
    litOpen.push(at);
    litClose.push(-1);
    state[at] = SRK_STR;
    lit[at] = cur;
  };
  while (i < n) {
    const ch = line[i];
    if (!inStr) {
      // ':' guard: https:// in JSX text is not a comment.
      if (ch === "/" && line[i + 1] === "/" && line[i - 1] !== ":") {
        state.fill(SRK_COMMENT, i);
        break;
      }
      if (ch === "/" && line[i + 1] === "*") {
        const end = line.indexOf("*/", i + 2);
        const stop = end === -1 ? n : end + 2;
        state.fill(SRK_COMMENT, i, stop);
        i = stop;
        continue;
      }
      if (ch === "'" || ch === '"') {
        inStr = true;
        q = ch;
        open(i);
        i++;
        continue;
      }
      if (ch === "`") {
        inStr = true;
        q = "`";
        open(i);
        tpl.push({ id: cur, depth: -1 });
        i++;
        continue;
      }
      // Inside a template's ${ }: track brace depth; the matching } resumes the template text.
      const top = tpl[tpl.length - 1];
      if (top && top.depth >= 0) {
        if (ch === "{") top.depth++;
        else if (ch === "}") {
          if (top.depth === 0) {
            top.depth = -1;
            inStr = true;
            q = "`";
            cur = top.id;
            state[i] = SRK_STR;
            lit[i] = cur;
            i++;
            continue;
          }
          top.depth--;
        }
      }
      i++;
      continue;
    }
    state[i] = SRK_STR;
    lit[i] = cur;
    if (ch === "\\") {
      if (i + 1 < n) {
        state[i + 1] = SRK_STR;
        lit[i + 1] = cur;
      }
      i += 2;
      continue;
    }
    if (q === "`" && ch === "$" && line[i + 1] === "{") {
      state[i + 1] = SRK_STR;
      lit[i + 1] = cur;
      tpl[tpl.length - 1].depth = 0;
      inStr = false;
      i += 2;
      continue;
    }
    if (ch === q) {
      litClose[cur] = i;
      if (q === "`") tpl.pop();
      inStr = false;
      cur = -1;
      i++;
      continue;
    }
    i++;
  }
  let code = "";
  for (let k = 0; k < n; k++) code += state[k] === SRK_COMMENT ? " " : line[k];
  return { state, lit, litOpen, litClose, code };
}

/**
 * True only for proven-benign mention shapes. Anything else is treated as the
 * key value being handled in client code.
 */
function srkBenign(
  line: string,
  a: SrkLine,
  s: number,
  e: number,
  boolF: Set<string>,
  strF: Set<string>,
  dynEnvIndex: boolean
): boolean {
  const code = a.code;
  // B1 closed string literal (label, help text, error message), with three
  // exceptions that stay firing: the file does dynamic env lookups
  // `env[name]` (the label IS the lookup key); the literal is a bare key
  // passed as a call's first argument or used as an index
  // (getItem('serviceRoleKey'), searchParams.get('service_role_key'),
  // obj['serviceRoleKey']); or the literal is an object KEY whose value is
  // not boolean/number ({ 'x-service-role-key': key }).
  if (a.state[s] === SRK_STR && a.litClose[a.lit[s]] !== -1) {
    if (dynEnvIndex) return false;
    const open = a.litOpen[a.lit[s]];
    const close = a.litClose[a.lit[s]];
    const body = close - open - 1 <= 80 ? line.slice(open + 1, close) : "";
    const before = code.slice(Math.max(0, open - SRK_WIN), open);
    if (/^[\w.\-]{1,80}$/.test(body) && /[\w$)\]]\s{0,5}[(\[]\s{0,5}$/.test(before)) return false;
    const afterLit = code.slice(close + 1, close + 1 + SRK_WIN);
    if (/^\s{0,5}:/.test(afterLit)) return SRK_BOOL_VALUE.test(afterLit);
    return true;
  }
  // An unterminated string (an apostrophe in JSX prose, a regex literal with a
  // quote) falls through to the code checks below.
  const { ident, is, ie } = srkIdent(code, s, e);
  const before = code.slice(Math.max(0, is - SRK_WIN), is);
  const after = code.slice(ie, ie + SRK_WIN);
  // B2 JSX text: between a tag-closing '>' (preceded by letter/digit/quote/}/'/',
  // i.e. not '=>' or ' > ') and a tag-opening '<' (followed by a letter or '/'),
  // with no {}=;` in between — so {cfg.serviceRoleKey} still fires.
  const L = before.lastIndexOf(">");
  const R = after.indexOf("<");
  if (
    L !== -1 &&
    R !== -1 &&
    /[A-Za-z0-9"'}\/]/.test(before[L - 1] ?? "") &&
    /[A-Za-z\/]/.test(after[R + 1] ?? "") &&
    !/[{}=;`<]/.test(before.slice(L + 1)) &&
    !/[{}=;`>]/.test(after.slice(0, R))
  ) {
    return true;
  }
  // B3 annotated or assigned as boolean/number on this line (serviceRoleKey:
  // boolean / = true / : !!x), and no `string` in that union.
  if (SRK_BOOL_VALUE.test(after)) return true;
  // B4 this file types this exact identifier as boolean/number and never as
  // string (covers s.infrastructure.serviceRoleKey on a later line).
  if (boolF.has(ident) && !strF.has(ident)) return true;
  // B5 type-only import/export line: erased at compile time, ships nothing.
  if (/^\s*(?:import|export)\s+type\s*\{/.test(line)) return true;
  // B6 used only as a condition: ternary test (not ?. or ??), && guard, or
  // negated (!x.serviceRoleKey). Passing it to a call still fires.
  if (/^\s{0,5}(?:\?(?![.?])|&&)/.test(after)) return true;
  if (/!\s{0,3}(?:[\w$]{1,40}\??\.){0,8}$/.test(before)) return true;
  return false;
}


/** A live service_role key, decoded from a base64url JWT payload. Skips the
 *  Supabase CLI's public demo key (iss "supabase-demo") and hand-made local
 *  keys whose project ref is not a real 20-character ref (e.g. ref "local"
 *  in a localhost fallback) — those grant nothing on a hosted project.
 *  Self-hosted keys without a ref still fire. */
function isLiveServiceRoleJwt(seg: string): boolean {
  const claims = jwtPayloadClaims(seg);
  if (!claims || claims.role !== "service_role") return false;
  if (claims.iss === "supabase-demo") return false;
  if (typeof claims.ref === "string" && !/^[a-z0-9]{20}$/.test(claims.ref)) return false;
  return true;
}

/** The claims of a base64url JWT payload, or null. Pure JS so the engine
 *  still runs in the browser checker (no Buffer, no atob reliance). */
function jwtPayloadClaims(seg: string): Record<string, unknown> | null {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let bits = 0;
  let acc = 0;
  let str = "";
  for (const ch of seg) {
    const v = A.indexOf(ch);
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      str += String.fromCharCode((acc >> bits) & 0xff);
    }
  }
  try {
    const parsed: unknown = JSON.parse(str);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

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
  // (fires on a sink or any mention not proven benign — see the
  // service-role-key-in-client internals above)
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
      // Per-file facts (no cross-file state). Each pass is anchored on token
      // matches, so its cost is bounded per match.
      const boolF = new Set<string>();
      const strF = new Set<string>();
      for (const m of f.content.matchAll(SRK_TOKEN_G)) {
        const { ident, ie } = srkIdent(f.content, m.index!, m.index! + m[0].length);
        const tail = f.content.slice(ie, ie + 120);
        if (/^\??\s{0,5}:\s{0,5}(?:boolean|number)\b(?![^;,}\n]{0,80}\bstring\b)/i.test(tail)) {
          boolF.add(ident);
        }
        if (/^\??\s{0,5}:[^;,}\n]{0,80}\bstring\b/i.test(tail)) strF.add(ident);
      }
      // `env[name]` anywhere: a quoted env-var name may be the lookup key, so
      // B1 (closed string literal) is not trusted in this file.
      const dynEnvIndex = /env\s{0,5}\[\s{0,5}(?!['"`])[A-Za-z_$]/.test(f.content);
      return matchLines(f, (line) => {
        if (!SRK_PREFILTER.test(line)) return null;
        const trimmed = line.trim();
        // Skip comment lines / JSDoc that merely mention the term.
        if (
          trimmed.startsWith("//") ||
          trimmed.startsWith("*") ||
          trimmed.startsWith("/*")
        ) {
          return null;
        }
        const a = srkLex(line);
        // (A) earliest sink on the comment-blanked line.
        let col = -1;
        for (const re of SRK_SINKS) {
          const m = a.code.search(re);
          if (m !== -1 && (col === -1 || m < col)) col = m;
        }
        // (B) an earlier mention that is not proven benign moves the column left.
        for (const m of a.code.matchAll(SRK_TOKEN_G)) {
          const s = m.index!;
          const e = s + m[0].length;
          if (col !== -1 && s >= col) break;
          if (srkBenign(line, a, s, e, boolF, strF, dynEnvIndex)) continue;
          col = s;
          break;
        }
        return col === -1 ? null : { column: col + 1 };
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
    // Decode the payload instead of grepping its base64: "service_role" encodes
    // to a different base64 string depending on its byte offset in the JSON,
    // so a fixed substring missed roughly two of every three real keys.
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /eyJ[A-Za-z0-9_-]{6,400}\.(eyJ[A-Za-z0-9_-]{6,2000})\.[A-Za-z0-9_-]{6,1000}/g;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(f.content)) !== null && ++guard <= 500) {
        if (!isLiveServiceRoleJwt(m[1])) continue;
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
        });
      }
      return out;
    },
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
      const out: RuleMatch[] = [];
      if (isSql(f.path)) {
        // Comments blanked, same length and lines: a "-- never set this to
        // true" note is not a public bucket, and indexes still map to f.content.
        const src = stripSqlComments(f.content);
        const re = new RegExp(PSB_STMT_SRC, "gi");
        let m: RegExpExecArray | null;
        let guard = 0;
        while ((m = re.exec(src)) !== null) {
          if (++guard > 500) {
            out.push({
              line: lineAt(f.content, m.index),
              column: columnAt(f.content, m.index),
              snippet: snippetAt(f.content, m.index),
              message: PSB_GUARD_MESSAGE,
            });
            break;
          }
          // One statement only, so a `true` in the next one never counts.
          const end = sqlStatementEnd(src, m.index);
          // 8000-character cap hit, or an unterminated $$ body: ids unprovable.
          const truncated = end < src.length && src[end] !== ";";
          const stmt = src.slice(m.index, end);
          re.lastIndex = Math.max(end, m.index + 1);
          const isInsert = /^insert/i.test(m[1]);
          const isPublic = isInsert
            ? /\btrue\b/i.test(stmt)
            : /\bset\b[\s\S]{0,160}?"?\bpublic"?\s*=\s*true\b/i.test(stmt);
          if (!isPublic) continue;
          const ids = truncated ? null : isInsert ? psbInsertIds(stmt) : psbUpdateIds(stmt);
          if (ids && ids.every(isPublicAssetBucketName)) continue;
          out.push({
            line: lineAt(f.content, m.index),
            column: columnAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            ...(ids ? { message: psbMessage(ids.filter((id) => !isPublicAssetBucketName(id))) } : {}),
          });
        }
        return out;
      }
      // [^)]{0,1000} also covers the whitespace after "(": a separate \s*
      // there backtracks against it (600 ms on 200 KB of spaces). 1000, not
      // 300, so a long allowedMimeTypes list before public: true still matches.
      const hit = /\b(?:createBucket|updateBucket)\s*\([^)]{0,1000}?["']?\bpublic["']?\s*:\s*true\b/g;
      // Calls are matched with `//`-only lines blanked (same length, so every
      // index is an index into f.content): a commented-out createBucket, or a
      // commented-out `public: true` line inside a live call, is not a public
      // bucket. Not stripJsComments: an 'image/*' MIME type in one call would
      // blank the next call up to a later `*/`.
      const live = blankJsCommentLines(f.content);
      // Comment-blanked text, for identifier resolution ONLY: it does not
      // keep offsets, so every line/column comes from f.content.
      let clean: string | null = null;
      // Same identifier, same file, same answer: resolve each name once.
      const resolved = new Map<string, ReturnType<typeof psbResolveIdentifier>>();
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = hit.exec(live)) !== null) {
        if (++guard > 500) {
          out.push({
            line: lineAt(f.content, m.index),
            column: columnAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            message: PSB_GUARD_MESSAGE,
          });
          break;
        }
        const arg = PSB_ARG_RE.exec(m[0]);
        let names: string[] | undefined;
        let literal = false;
        if (arg && arg[2] !== undefined) {
          names = [arg[2]];
          literal = true;
        } else if (arg && arg[3] !== undefined) {
          const ident = arg[3].split(".").pop() as string;
          clean ??= stripJsComments(f.content);
          let r = resolved.get(ident);
          if (!r) {
            r = psbResolveIdentifier(ident, clean);
            resolved.set(ident, r);
          }
          if (!r.unknown) {
            literal = r.lits.length > 0;
            // No in-file definition (an imported AVATARS_BUCKET): judge the
            // identifier's own name.
            names = literal ? r.lits : [ident];
          }
        }
        if (names && names.every(isPublicAssetBucketName)) continue;
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          // Name the bucket only when it is a known literal, never an identifier.
          ...(names && literal
            ? { message: psbMessage(names.filter((n) => !isPublicAssetBucketName(n))) }
            : {}),
        });
      }
      return out;
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
      // Test fixtures build throwaway databases, not the app's schema.
      if (isTestPath(f.path)) return [];
      // A Supabase dashboard export says it is "for context only" and is not
      // run — unless it sits in a migrations folder, where `supabase db push`
      // executes it like any other migration.
      const p = f.path.replace(/\\/g, "/").toLowerCase();
      if (
        !/(^|\/)migrations\//.test(p) &&
        /schema is for context only and is not meant to be run/i.test(f.content.slice(0, 600))
      ) {
        return [];
      }

      const matches: RuleMatch[] = [];
      // Comments blanked, string- and dollar-body-aware, same length: every
      // regex runs on `src`, and its indexes are valid in f.content. A "--"
      // inside a literal can't hide a live CREATE TABLE, and a commented-out
      // "ALTER TABLE … ENABLE ROW LEVEL SECURITY" earns no credit.
      const src = stripSqlCommentsQuoteAware(f.content);
      const ID = RLS_ID;
      // Tables that DO get RLS enabled, keyed schema.table (quote-tolerant).
      const enabled = new Set<string>();
      let m: RegExpExecArray | null;

      // 1. Static enables.
      const alterRe = new RegExp(
        `ALTER\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?(?:ONLY\\s+)?(?:(${ID})\\s{0,8}\\.\\s{0,8})?(${ID})\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
        "gi"
      );
      while ((m = alterRe.exec(src)) !== null) {
        enabled.add(`${m[1] ? unquote(m[1]) : "public"}.${unquote(m[2])}`);
      }
      // ... and as a later action of a multi-action ALTER TABLE
      //     (ALTER TABLE t ADD COLUMN x int, ENABLE ROW LEVEL SECURITY).
      for (const t of rlsMultiActionToggles(src)) if (t.on) enabled.add(t.key);

      // 2. Dynamic-loop enables (DO-block FOREACH … ARRAY['a', 'b'] LOOP …
      //    EXECUTE format('ALTER TABLE public.%I ENABLE …')): see
      //    rlsDynLoopEnables, shared with grant-to-anon.
      for (const e of rlsDynLoopEnables(src)) enabled.add(e.key);
      let guard = 0;

      // 3. Static CREATEs. The IF NOT EXISTS lookahead stops the backtrack
      //    that reported a table named "if" for CREATE TABLE IF NOT EXISTS
      //    pgboss.%I; the two trailing lookaheads reject a runtime-named
      //    target (pgboss.%I, 'public.' || t), which pass 4 handles. UNLOGGED
      //    tables are exposed through PostgREST like any other; TEMP tables
      //    are not and still don't match.
      const createRe = new RegExp(
        `CREATE\\s+(?:UNLOGGED\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?!IF\\s+NOT\\s+EXISTS\\b)(?:(${ID})\\s{0,8}\\.\\s{0,8})?(${ID})(?![a-z0-9_"'])(?!\\s{0,8}\\.)`,
        "gi"
      );
      guard = 0;
      while ((m = createRe.exec(src)) !== null) {
        if (++guard > 1000) break;
        const schema = m[1] ? unquote(m[1]) : "public";
        const table = unquote(m[2]);
        if (schema !== "public") continue; // non-public schemas aren't exposed
        if (INTERNAL_SCHEMAS.has(schema)) continue;
        if (table.startsWith("_")) continue;
        if (!enabled.has(`${schema}.${table}`)) {
          let message = `Table "${table}" is created but RLS is never enabled for it in this file.`;
          if (/^[^;]{0,400}?\bPARTITION\s+OF\b/i.test(src.slice(m.index))) {
            message += ` It is a partition: RLS on the parent is not applied when this partition is queried directly through /rest/v1/${table}.`;
          }
          matches.push({
            line: lineAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            message,
          });
        }
      }

      // 4. Runtime-named public tables (EXECUTE format('CREATE TABLE
      //    public.%I …') or 'CREATE TABLE public.' || name). These used to be
      //    reported as a table called "public"; now they fire only when the
      //    enclosing function / DO body never enables RLS on a runtime name.
      //    A private schema (pgboss.%I) is skipped; a %I.%I target (dynamic
      //    schema) doesn't match at all.
      const dynCreateRe =
        /CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:([a-z0-9_"]{1,130})\s{0,8}\.\s{0,8})?(?:"?%[Is]"?(?!\s{0,8}\.)|'\s{0,8}\|\|)/gi;
      guard = 0;
      while ((m = dynCreateRe.exec(src)) !== null) {
        if (++guard > 50) break;
        const schema = m[1] ? unquote(m[1]) : "public";
        if (schema !== "public") continue;
        // The enclosing dollar body: from the nearest tag before the CREATE
        // to the same tag after it, each side capped at 8,000 characters.
        const preFrom = Math.max(0, m.index - 8000);
        const tag = lastMatchOf(
          new RegExp(RLS_DOLLAR_TAG.source, "gi"),
          src.slice(preFrom, m.index)
        );
        let body: string;
        if (tag) {
          const end = src.indexOf(tag[0], m.index);
          body = src.slice(
            preFrom + tag.index,
            end === -1 ? m.index + 8000 : Math.min(end, m.index + 8000)
          );
        } else {
          body = src.slice(Math.max(0, m.index - 4000), m.index + 4000);
        }
        if (RLS_DYN_ENABLE_RE.test(body)) continue;
        matches.push({
          line: lineAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: RLS_DYN_CREATE_MESSAGE,
        });
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
    scan: (f) => {
      const out: RuleMatch[] = [];
      // String-aware strip (length-preserving, so offsets map onto
      // f.content): a commented-out policy is not a policy, but a "--" or "/*"
      // inside a literal must never blank a live one.
      const src = stripSqlCommentsQuoted(f.content);
      const starts: number[] = [];
      const re = /\bCREATE\s+POLICY\b/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(src)) !== null) {
        starts.push(m.index);
        if (starts.length >= 5000) break; // same guard as matchAll
      }
      let facts: PutFacts | null = null; // built lazily, once per file
      // Incremental line counter: starts are ascending, so the file is
      // walked once instead of once per policy.
      let lineIdx = 0;
      let lineNo = 1;
      for (let k = 0; k < starts.length; k++) {
        const start = starts[k];
        // Cut at the next CREATE POLICY too: a missing ";" must not let one
        // policy borrow the next one's (true), TO or FOR.
        const end = Math.min(sqlStatementEnd(src, start), starts[k + 1] ?? Infinity);
        const stmt = src.slice(start, end);
        if (!/\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/i.test(stmt)) continue;

        for (; lineIdx < start; lineIdx++) if (f.content.charCodeAt(lineIdx) === 10) lineNo++;
        const at = {
          line: lineNo,
          column: columnAt(f.content, start),
          snippet: snippetAt(f.content, start),
        };

        const hdr = PUT_HDR_RE.exec(stmt);
        if (!hdr) {
          out.push(at); // can't read the header: fire at the default (loud)
          continue;
        }
        let rest = stmt.slice(hdr[0].length);
        // RESTRICTIVE policies are AND-ed: (true) only fails to narrow, it
        // can never grant a row.
        if (/^\s*AS\s+RESTRICTIVE\b/i.test(rest)) continue;
        rest = rest.replace(/^\s*AS\s+PERMISSIVE\b/i, "");
        const cmd = (
          /^\s*FOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i.exec(rest)?.[1] ?? "ALL"
        ).toUpperCase();
        // The TO list sits between FOR and the first predicate.
        const p = rest.search(/\bUSING\b|\bWITH\s+CHECK\b/i);
        const head = p < 0 ? rest : rest.slice(0, p);
        const toM = /\bTO\s+([^()]{1,300})$/i.exec(head.trimEnd());
        // No TO clause = PUBLIC, which includes anon.
        const roles = toM
          ? toM[1]
              .split(",")
              .map((r) => r.replace(/"/g, "").trim().toLowerCase())
              .filter(Boolean)
          : ["public"];
        if (roles.length > 0 && roles.every((r) => RLS_BYPASS_ROLES.has(r))) continue;

        const q = hdr[1];
        const schema = q.includes(".")
          ? q.split(".")[0].replace(/"/g, "").trim().toLowerCase()
          : "";
        const table = bareName(q);
        const target = schema ? `${schema}.${table}` : table;
        // PUBLIC reaches the API through both of Supabase's request roles.
        const apiRoles = roles.flatMap((r) => (r === "public" ? ["anon", "authenticated"] : [r]));
        const anonReadable = roles.includes("public") || roles.includes("anon");
        const who = toM ? roles.join(", ") : "PUBLIC (anon and authenticated)";

        if (cmd !== "SELECT") {
          out.push({
            ...at,
            severity: "warning",
            message:
              `This FOR ${cmd} policy has a constant (true) predicate, so ${who} can ` +
              `${PUT_WRITE_ACTION[cmd]} ${target}, regardless of who is asking.` +
              (toM
                ? ""
                : " No TO clause, so this applies to PUBLIC, including anonymous callers. If it is meant for server code, delete it: the service_role key bypasses RLS and needs no policy."),
          });
          continue;
        }

        // SELECT (true): graded by what the table holds and who can read it.
        const reader = anonReadable
          ? "anonymous visitor"
          : roles.includes("authenticated")
            ? "signed-in user"
            : `caller with the ${roles.join(", ")} role`;
        const publicRead =
          `Public-read policy: every ${reader} can read all rows and columns of ${target}. ` +
          "Fine for genuinely public reference data. If it holds emails, phone numbers, tokens, finances or per-user rows, scope it.";
        let severity: Severity = "info";
        let message = publicRead;
        if (schema === "storage" && table === "objects") {
          severity = "warning";
          message = `SELECT USING (true) on storage.objects lets ${who} list and download every file in every bucket, including private buckets. Add a bucket_id (and owner/folder) condition.`;
        } else if (table.includes("%")) {
          // EXECUTE format(… %I …): the target table is only known at run time.
          severity = "warning";
          message = `SELECT USING (true) on a table chosen at run time (EXECUTE format %I/%s) lets ${who} read every row; the target table can't be checked statically. Scope each generated policy, or confirm every table in the loop is public reference data.`;
        } else {
          facts ??= putFileFacts(src);
          const colList = [...(facts.cols.get(table) ?? [])];
          const rv = facts.revoked.get(table);
          const gt = facts.granted.get(table);
          // Mitigated only if EVERY API role lost table-level SELECT and none
          // got it back. REVOKE … FROM public alone doesn't count: Supabase
          // grants anon and authenticated directly.
          if (
            apiRoles.length > 0 &&
            rv &&
            apiRoles.every((r) => rv.has(r)) &&
            !apiRoles.some((r) => gt?.has(r))
          ) {
            message = `${publicRead} Table-level SELECT is revoked in this file; make sure the column grants exclude private columns.`;
          } else {
            const pii = colList.find((c) => PII_COLUMN.test(c));
            const cred = colList.find((c) => CREDENTIAL_COLUMN.test(c));
            if (anonReadable && (PRIVATE_TABLE.test(table) || pii)) {
              severity = "warning";
              message = `Anyone holding the public anon key can read every row and every column of ${target}${pii ? ` (including ${pii})` : ""}. RLS cannot hide columns: scope rows with auth.uid() or expose a view/RPC with only public columns.`;
            } else if (!anonReadable && (OWNER_PRIVATE_TABLE.test(table) || cred)) {
              severity = "warning";
              message = roles.includes("authenticated")
                ? `Every signed-in account can read all rows of ${target}. Supabase sign-ups are open by default, so 'authenticated' usually means anyone. Scope rows to the owner or tenant.`
                : `Every caller with the ${roles.join(", ")} role can read all rows of ${target}. Scope rows to the owner or tenant.`;
            }
          }
        }
        out.push({ ...at, severity, message });
      }
      return out;
    },
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
      // Comment-stripped (length-preserving, so offsets map onto f.content):
      // a commented-out policy is not a policy.
      const src = stripSqlComments(f.content);
      const ctx: ScopeCtx = {
        src,
        fns: null, // same-file helper definitions, parsed lazily, once
        memo: new Map(),
        defInfo: new Map(),
        budget: 0,
        isWrite: false,
      };
      // policy-using-true's view of the file, built on first use (both
      // strips are length-preserving, so the offsets line up).
      let putSrc: string | null = null;
      const re = /CREATE\s+POLICY\b[\s\S]{0,600}?;/gi;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(src)) !== null) {
        if (++guard > 500) break;
        let stmt = m[0];
        // A missing ";" must not let one policy borrow the next one's auth
        // call, helper, RESTRICTIVE or (false): cut at the next CREATE POLICY
        // and resume the scan there so it is judged on its own.
        const k = stmt.slice(13).search(/\bCREATE\s+POLICY\b/i);
        if (k !== -1) {
          stmt = stmt.slice(0, 13 + k);
          re.lastIndex = m.index + stmt.length;
        }
        // Every test below runs on `rest` — the policy NAME is excluded.
        const head = HEAD_RE.exec(stmt);
        const rest = head ? stmt.slice(head[0].length) : stmt;

        if (!/\bUSING\b|\bWITH\s+CHECK\b/i.test(rest)) continue; // no predicate
        // (true) policies are reported by policy-using-true — mirror its
        // matcher so nothing falls between the two rules.
        if (HANDOFF_RE.test(f.content.slice(m.index, m.index + stmt.length))) {
          putSrc ??= stripSqlCommentsQuoted(f.content);
          if (HANDOFF_RE.test(putSrc.slice(m.index, m.index + stmt.length))) continue;
        }
        if (IDENTITY_RE.test(rest)) continue; // properly scoped
        // A RESTRICTIVE policy can only narrow what permissive ones grant.
        if (/\bAS\s+RESTRICTIVE\b/i.test(rest)) continue;
        // Deny-all: every predicate is (false) — no row is reachable.
        const kws = (rest.match(/\b(?:USING|WITH\s+CHECK)\b/gi) ?? []).length;
        const falses = (
          rest.match(/\b(?:USING|WITH\s+CHECK)\s*\(\s*false\s*\)/gi) ?? []
        ).length;
        if (kws > 0 && falses === kws) continue;
        // Dynamic SQL (format('… using %s', pred) / 'using ' || pred): the
        // predicate lives in a variable built just above. Suppress only when
        // that window identifies the caller — never blindly.
        if (
          /\b(?:USING|WITH\s+CHECK)\s{0,4}\(?\s{0,4}(?:%(?:\d\$)?[sL]\b|'\s{0,4}\|\|)/i.test(
            rest
          )
        ) {
          const win = src.slice(Math.max(0, m.index - 2000), m.index);
          if (IDENTITY_RE.test(win) || hasTrustedHelper(ctx, win)) continue;
        }
        // Helper delegation: every top-level predicate must scope the caller
        // (via auth.*, a trusted helper, or (false)), per scoped()'s AND/OR walk.
        ctx.isWrite = !/\bFOR\s+SELECT\b/i.test(rest);
        ctx.budget = 0;
        const bodies = predicateBodies(rest);
        if (bodies.length > 0 && bodies.every((b) => scoped(ctx, b, 0))) continue;
        // Intentionally public content: a SELECT (not on storage.objects)
        // filtered only by an explicit publication flag.
        if (
          /\bFOR\s+SELECT\b/i.test(rest) &&
          !/\bON\s+"?storage"?\s*\.\s*"?objects"?/i.test(rest)
        ) {
          const n = rest
            .slice(rest.search(/\bUSING\b/i))
            .replace(/\s+/g, " ")
            .replace(/"/g, "")
            .toLowerCase();
          if (PUB_RE.test(n)) continue;
        }
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
      "Verify the caller inside the function. For user calls, wrap the handler in withSupabase({ auth: 'user' }, handler) from @supabase/server, or read the Authorization header, call supabase.auth.getUser(token) or auth.getClaims(token), and reject when there is no user. For cron or internal calls, use withSupabase({ auth: 'secret' }) (or 'secret:<name>') or compare a dedicated secret header to a server-side secret, and fail closed when that secret is unset. For provider webhooks, verify the provider's signature. The 'none' and 'publishable' modes do not authenticate the caller: a publishable key ships in every client. verify_jwt = true alone is not enough, because the public anon key is a valid JWT.",
    // Deployable code only: no _shared/_lib modules, no tests (efnaInScope).
    appliesTo: (f) => isEdgeFunction(f.path) && isJsLike(f) && efnaInScope(f.path),
    scan: (f) => {
      // Comments blanked with line structure kept: a commented-out auth
      // check (or a "verify_jwt = true" note) is not an auth check.
      const src = stripJsComments(f.content);
      // A Deno test module is never deployed as a handler.
      if (/\bDeno\.test[ \t]{0,8}\(/.test(src)) return [];
      let idx = efnaFindHandler(src);
      let base = src;
      // stripJsComments is not string-aware: a "*/*" string followed by any
      // later `*/` blanks the code between them, the handler included. In a
      // function's entry file, look the handler up in the raw text instead,
      // with `//`-only lines blanked: a commented-out Deno.serve( is no handler.
      if (idx < 0 && efnaIsEntry(f.path)) {
        base = blankJsCommentLines(f.content);
        idx = efnaFindHandler(base);
      }
      if (idx < 0) return [];
      // A user JWT: the Authorization header read AND its signature verified.
      // A bare mention of "authorization" or an unrelated db.getUser() is not
      // proof of authentication.
      const verifiesJwt =
        EFNA_VERIFIES_JWT.test(src) ||
        (EFNA_DJWT_IMPORT.test(src) && /\bverify[ \t]{0,8}\(/.test(src));
      if (EFNA_READS_AUTH.test(src) && verifiesJwt) return [];
      // Supabase's own wrapper: withSupabase({ auth: 'user' | 'secret…' })
      // from @supabase/server (or its createSupabaseContext / verifyAuth
      // primitives with the error handled). 'none' and 'publishable' modes
      // authenticate nobody and fall through to the checks below.
      if (efnaSupabaseServerGate(src)) return [];
      // A non-user caller authenticated by a secret or a webhook signature.
      if (efnaSecretGate(src)) return [];
      if (efnaWebhookVerified(src)) return [];
      // Report on the handler line, not line 1. stripJsComments drops `//`
      // text, so only NEWLINES line up between src and f.content: count lines
      // in the text the index came from, then take that line from f.content.
      const line = lineAt(base, idx);
      let lineStart = 0;
      for (let n = 1; n < line; n++) {
        const nl = f.content.indexOf("\n", lineStart);
        if (nl === -1) break;
        lineStart = nl + 1;
      }
      return [
        {
          line,
          snippet: snippetAt(f.content, lineStart),
          message:
            "Edge function handles requests but does not read and verify the Authorization header.",
        },
      ];
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
      "supabase.auth.getSession() is called in server middleware (middleware.ts, or proxy.ts since Next.js 16). On the server it reads the session straight from the request cookies WITHOUT verifying the JWT, so a forged cookie can spoof it. Supabase's guidance is to use getUser() (or getClaims()) — which revalidates the token with the Auth server — for any authorization decision.",
    recommendation:
      "In server code (middleware or proxy, route handlers, server actions) authorize with supabase.auth.getUser() — it revalidates the JWT — not getSession(). getSession() is fine on the client, where the session is already trusted.",
    // middleware.ts (any path, as before) or its Next.js 16 name proxy.ts (see
    // middlewareFileKind). "proxy" is also an everyday name for a route helper
    // that forwards a request to a backend (app/api/proxy.ts,
    // src/services/proxy.ts), so a proxy.ts counts only where Next.js loads it
    // (isProxyEntryPath) or as a Supabase session helper in a supabase/ folder
    // (lib/supabase/proxy.ts, the counterpart of lib/supabase/middleware.ts),
    // which runs inside the gate.
    appliesTo: (f) => {
      if (!isJsLike(f)) return false;
      const kind = middlewareFileKind(f.path);
      if (kind === "proxy") {
        return isProxyEntryPath(f.path) || /(?:^|[\/\\])supabase[\/\\]proxy\.(?:ts|js)$/.test(f.path);
      }
      return kind === "middleware";
    },
    scan: (f) => {
      // Server-only footgun; a client component using getSession is fine.
      if (isClientComponent(f.content)) return [];
      // A proxy.ts can also be a browser fetch wrapper that reads getSession()
      // to attach the access token as a Bearer header, which is the documented
      // client-side use (and a Vite/SPA file has no 'use client' to tell). A
      // proxy file counts only when it is Next.js server code: the same
      // isNextProxyCode gate as nextjs/middleware-no-matcher.
      if (middlewareFileKind(f.path) === "proxy" && !isNextProxyCode(f.content)) return [];
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
  // CRITICAL (table) / WARNING (view, matview, foreign table) — public
  // object explicitly GRANTed to the anon role with nothing in front of it
  // (no RLS, no security_invoker). A plain table the same file creates
  // without RLS and grants to anon is the CVE-2025-48757 shape.
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "supabase/grant-to-anon",
    title: "Table or view granted to the anon role without RLS",
    severity: "warning",
    category: "supabase",
    cwe: "CWE-732",
    message:
      "An object in the public schema is GRANTed to the anon (unauthenticated) role, or to PUBLIC, with nothing in front of it in this migration: a table without RLS (or with RLS disabled again), a view that is not security_invoker (it runs with its owner's rights and bypasses RLS on the tables it reads), or a materialized view or foreign table, which can never have RLS. A GRANT … ON ALL TABLES IN SCHEMA public does the same to every such table this file has already created. Since the 2026 Supabase change, tables reach the Data API only via explicit grants — so this GRANT hands every anonymous visitor direct access with no policy in front of it.",
    recommendation:
      "For a table, enable RLS (ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;) and add scoped policies. For a view, create it WITH (security_invoker = true) and repeat that clause on every CREATE OR REPLACE VIEW. Materialized views and foreign tables cannot be protected: revoke the anon grant or move them to a schema the Data API does not expose. Prefer per-table grants over ON ALL TABLES IN SCHEMA public. Only keep an anon grant for genuinely public data that is still RLS-protected.",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      // Test fixtures build throwaway databases, not the app's schema (the
      // same skip as rls-missing-on-table, which flags the CREATE behind it).
      if (isTestPath(f.path)) return [];
      const out: RuleMatch[] = [];
      // Comments blanked with line structure kept, so an index into src is
      // the same index into f.content for line and snippet.
      const src = stripSqlComments(f.content);
      const state = gtaObjectState(src);

      // Line and snippet of a GRANT. lineAt/snippetAt rescan from the start
      // of the file / line on every call, which made a hostile 1 MB file of
      // tiny GRANTs take 12 s. GRANT hits only move forward, so the line is
      // counted incrementally and the snippet is reused within a line. Same
      // values as lineAt(f.content, idx) / snippetAt(f.content, idx).
      let lnPos = 0;
      let lnNum = 1;
      let snipLine = 0;
      let snip = "";
      const at = (idx: number) => {
        for (; lnPos < idx; lnPos++) if (f.content.charCodeAt(lnPos) === 10) lnNum++;
        if (snipLine !== lnNum) {
          snipLine = lnNum;
          snip = snippetAt(f.content, idx);
        }
        return { line: lnNum, snippet: snip };
      };

      // ON ALL TABLES candidates, in state order. RLS / security_invoker is
      // the FINAL state, so only "created before this GRANT" depends on the
      // GRANT: a sorted list of creation points answers that by binary
      // search, and the first five names are recomputed only when the count
      // changes (GRANT hits only move forward, so equal count = equal set).
      // `table` is when the object first became a plain table without RLS
      // (Infinity for views, matviews, foreign tables): an ON ALL TABLES
      // grant after that exposes at least one table (critical); one that
      // only reaches views / matviews / foreign tables stays a warning.
      const allCands: { name: string; key: string; firstCreate: number; table: number }[] = [];
      for (const [k, st] of state) {
        if (!k.startsWith("public.")) continue;
        const name = k.slice("public.".length);
        if (st.kind === undefined || name.startsWith("_") || gtaProtected(st)) continue;
        const table = st.kind === "table" ? st.firstTable : Infinity;
        allCands.push({ name, key: k, firstCreate: st.firstCreate, table });
      }
      const createdAt = allCands.map((c) => c.firstCreate).sort((a, b) => a - b);
      const tableAt = allCands
        .filter((c) => c.table !== Infinity)
        .map((c) => c.table)
        .sort((a, b) => a - b);
      /** How many of the sorted positions come before idx. */
      const countBefore = (sorted: number[], idx: number) => {
        let lo = 0;
        let hi = sorted.length;
        while (lo < hi) {
          const mid = (lo + hi) >> 1;
          if (sorted[mid] < idx) lo = mid + 1;
          else hi = mid;
        }
        return lo;
      };
      let allCount = 0;
      let allFirst: string[] = [];

      // Literals and dollar bodies: is a GRANT prose, does a REVOKE run?
      const regions = gtaRegions(f.content);
      // A grant whose Data-API privileges are all revoked from the same
      // role(s) later in the file leaves anon nothing to use.
      const rv = gtaRevokes(src, regions);
      // RLS enabled on run-time-built names the scanner cannot resolve: a
      // table finding stays a warning, as that loop may cover it.
      const dynRls = rlsDynUnresolved(src);
      // Candidates a REVOKE names directly: the only ones an ON ALL TABLES
      // grant can lose one by one (at most 100, the gtaRevokes cap). Their
      // REVOKE lists are looked up once here, not once per GRANT.
      const revokedCands = rv.objKeys.size
        ? allCands
            .filter((c) => rv.objKeys.has(c.key))
            .map((c) => ({
              c,
              anon: rv.obj.get(`anon\u0000${c.key}`),
              pub: rv.obj.get(`public\u0000${c.key}`),
            }))
        : [];

      // One GRANT statement at a time: the old regex ran on past the `;` of
      // a GRANT … TO authenticated into an unrelated "anon" further down.
      const gRe = /\bGRANT\b/gi;
      let gm: RegExpExecArray | null;
      let guard = 0;
      while ((gm = gRe.exec(src)) !== null) {
        if (++guard > 20000) break;
        // Pathological input guard, as in matchAll.
        if (out.length >= 5000) break;
        const idx = gm.index;
        // sqlStatementEnd caps its walk at 4000 chars but not the search for
        // a closing $tag$, which runs to the end of the file: a hostile file
        // of GRANT $t1$ GRANT $t2$ … took 6.5 s. Handing it the text up to
        // its own cap returns the same end (a tag closing at or past the cap
        // already yields the cap) and keeps every call bounded.
        const end = sqlStatementEnd(src.slice(0, idx + 4000), idx, 4000);
        // Resume after the statement, so total work stays linear and a huge
        // pg_dump grant section (function grants first) is scanned to the
        // end. Not across a $tag$: sqlStatementEnd can overshoot there. A
        // GRANT after a quote is NOT skipped: EXECUTE 'grant … on public.t
        // to anon' has a literal, resolvable target; dynamic ones drop below.
        if (!/\$[A-Za-z0-9_]*\$/.test(src.slice(idx, end)))
          gRe.lastIndex = Math.max(gRe.lastIndex, end);
        // ... but not prose in an ordinary literal (COMMENT ON … IS '…').
        if (gtaInProse(regions, src, idx)) continue;

        const stmt = src.slice(idx + 5, end);
        const on = /\sON\s/i.exec(stmt);
        if (!on) continue;
        // TRUNCATE / REFERENCES / TRIGGER alone are not reachable through the
        // Data API, and they are the post-2026 Supabase default ACL pg_dump
        // writes for every new table. Column lists are dropped first. They
        // never nest, so [^()] (linear) rather than [^)], which rescans to the
        // next ")" from every "(" — 3.6 s on a 1 MB run of unclosed "(".
        const privs = stmt.slice(0, on.index).replace(/\([^()]*\)/g, " ");
        if (!/\b(?:SELECT|INSERT|UPDATE|DELETE|ALL)\b/i.test(privs)) continue;

        const rest = " " + stmt.slice(on.index + on[0].length);
        const to = /\sTO\s/i.exec(rest);
        if (!to) continue;
        const objects = rest.slice(0, to.index).trim().replace(/^TABLE\s+/i, "");

        let roles = rest.slice(to.index + to[0].length);
        for (const cut of [/\bWITH\s+GRANT\s+OPTION\b/i, /\bGRANTED\s+BY\b/i]) {
          const c = cut.exec(roles);
          if (c) roles = roles.slice(0, c.index);
        }
        const roleList = roles
          .split(",")
          .map((r) => unquote(r.trim().replace(/^GROUP\s+/i, "")));
        const who = roleList.includes("anon")
          ? "anon"
          : roleList.includes("public")
            ? "PUBLIC (every role, including anon)"
            : null;
        if (!who) continue;
        const privMask = gtaPrivMask(privs);
        const grantees = roleList.filter((r) => r === "anon" || r === "public");

        const all = GTA_ALL_TABLES.exec(objects);
        if (all) {
          const schemas = all[1].split(",").map((s) => unquote(s.trim()));
          if (!schemas.includes("public")) continue;
          // ON ALL TABLES only reaches relations that already exist, so a
          // table created after the GRANT is not exposed by it.
          let exposed = countBefore(createdAt, idx);
          // What each grantee keeps after a later REVOKE … ON ALL TABLES;
          // nothing kept takes the whole grant back.
          const needAnon = grantees.includes("anon")
            ? privMask & ~gtaAfter(rv.all.get("anon"), idx)
            : 0;
          const needPub = grantees.includes("public")
            ? privMask & ~gtaAfter(rv.all.get("public"), idx)
            : 0;
          if (needAnon === 0 && needPub === 0) exposed = 0;
          let tables = exposed > 0 ? countBefore(tableAt, idx) : 0;
          // A later per-object REVOKE takes back that object only.
          let dropped: Set<string> | null = null;
          if (exposed > 0) {
            for (const { c, anon, pub } of revokedCands) {
              if (c.firstCreate >= idx) continue;
              if ((needAnon & ~gtaAfter(anon, idx)) !== 0) continue;
              if ((needPub & ~gtaAfter(pub, idx)) !== 0) continue;
              (dropped ??= new Set()).add(c.name);
              exposed--;
              if (c.table < idx) tables--;
            }
          }
          if (exposed > 0) {
            // Equal count = equal set only when nothing was dropped.
            if (dropped || exposed !== allCount) {
              allCount = dropped ? -1 : exposed;
              allFirst = [];
              for (const c of allCands) {
                if (c.firstCreate >= idx || dropped?.has(c.name)) continue;
                allFirst.push(c.name);
                if (allFirst.length === 5) break;
              }
            }
            const more = exposed - 5;
            out.push({
              ...at(idx),
              message: `GRANT ... ON ALL TABLES IN SCHEMA public gives ${who} access to ${allFirst.join(", ")}${more > 0 ? ` and ${more} more` : ""}, which this file creates without RLS (or as views without security_invoker). Anyone with the public anon key can use these privileges on every row.`,
              ...(tables > 0 && !dynRls ? { severity: "critical" as Severity } : {}),
            });
          }
          // ALTER DEFAULT PRIVILEGES … ON TABLES is NOT handled here; the
          // NON_TABLE check below skips it.
          continue;
        }

        if (GTA_NON_TABLE.test(objects)) continue;
        // format() placeholders or concatenation: the target is unknowable.
        if (/[%|$']/.test(objects)) continue;

        // A name listed twice in one GRANT would only repeat the same match.
        const reported = new Set<string>();
        for (const obj of objects.split(",")) {
          const om = GTA_OBJECT_RE.exec(obj);
          if (!om) continue;
          const schema = om[1] ? unquote(om[1]) : "public";
          const name = unquote(om[2]);
          if (schema !== "public") continue; // only the Data-API-exposed schema
          if (INTERNAL_SCHEMAS.has(schema)) continue;
          if (name.startsWith("_")) continue;
          // Defined in another file: its RLS state is unknowable per-file.
          // rls-missing-on-table flags the CREATE site, rls-explicitly-
          // disabled a DISABLE, and policy-using-true permissive policies.
          const st = state.get(`${schema}.${name}`);
          if (!st || st.kind === undefined) continue;
          if (gtaProtected(st)) continue;
          if (gtaRevokedLater(rv, grantees, privMask, `${schema}.${name}`, idx)) continue;
          if (reported.has(name)) continue;
          reported.add(name);
          const message =
            st.kind === "table"
              ? `Table "${name}" is created in this file without RLS (or has RLS disabled again) and is granted to ${who}. Anyone with the public anon key can use these privileges on every row. The scanner reads one file at a time: if a later migration enables RLS on it, this is the state between the two migrations.`
              : st.kind === "view"
                ? `View "${name}" is granted to ${who} but is not security_invoker at its last definition in this file, so it runs with its owner's privileges and bypasses RLS on the tables it reads. Recreate it WITH (security_invoker = true), and repeat the WITH clause on every CREATE OR REPLACE VIEW, unless every row and column it returns is meant to be public.`
                : st.kind === "matview"
                  ? `Materialized view "${name}" is granted to ${who}. Materialized views cannot have RLS or security_invoker, so every row they store is readable by anyone with the anon key. Revoke the grant or move the view out of the exposed schema unless all of its data is meant to be public.`
                  : `Foreign table "${name}" is granted to ${who}. Foreign tables do not support RLS, so the remote data is readable by anyone with the anon key. Move it to a schema that is not exposed through the Data API, or revoke the grant.`;
          // A plain table without RLS that this file itself grants to anon is
          // the CVE-2025-48757 shape: critical. Views, materialized views and
          // foreign tables keep the rule's default (warning), and so does an
          // object that only became a table after the GRANT (a view dropped
          // and recreated as one), as the ON ALL TABLES branch does.
          out.push({
            ...at(idx),
            message,
            ...(st.kind === "table" && st.firstTable < idx && !dynRls
              ? { severity: "critical" as Severity }
              : {}),
          });
        }
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
      "A SECURITY DEFINER function runs with the privileges of the user who created it, but its search_path is inherited from the caller. Anyone who can create objects in a schema on that search_path can make the function resolve to a table or function they control, and it will run with elevated privileges. If a later migration pins it (CREATE OR REPLACE … SET search_path or ALTER FUNCTION … SET search_path) or drops it, this finding is stale.",
    recommendation:
      "Pin the search_path on the function: add `set search_path = ''` to the definition (or `ALTER FUNCTION <name> SET search_path = '';`) and fully qualify every object reference inside it, e.g. public.profiles instead of profiles.",
    reference:
      "https://supabase.github.io/splinter/0011_function_search_path_mutable/",
    appliesTo: (f) => isSql(f.path),
    scan: (f) => {
      // pgTAP suites and disposable fixture schemas create unpinned definer
      // functions on purpose, and never reach a real database. Real migrations
      // and declarative schemas always count: a folder upload puts the picked
      // folder's name first, so a project folder named "test" must not hide
      // its migrations.
      const p = f.path.replace(/\\/g, "/");
      if (isTestPath(p) && !/(^|\/)(migrations|schemas)\//i.test(p)) return [];

      const src = stripSqlComments(f.content);
      const out: RuleMatch[] = [];

      // Functions pinned via a separate ALTER FUNCTION statement are fine,
      // but only for the same schema + overload, and only when the ALTER is a
      // real pin. `[^;]` keeps the match inside one statement: with
      // `[\s\S]`, pg_dump's `ALTER FUNCTION "public"."x"() OWNER TO
      // "postgres";` reached the NEXT function's `SET "search_path"`. The
      // {1,63} bound (Postgres NAMEDATALEN) keeps each ALTER start at
      // O(63·300) instead of O(n·300).
      const pins: { schema: string; name: string; arity: number | null; idx: number }[] = [];
      const altRe =
        /ALTER\s+FUNCTION\s+(?:(["']?[a-z0-9_]{1,63}["']?)\s*\.\s*)?(["']?[a-z0-9_]{1,63}["']?)[^;]{0,300}?\bSET\s+"?search_path"?\s*(?:(?:TO|=)(?!\s*DEFAULT\b)|FROM\s+CURRENT\b)/gi;
      const ALT_HEAD =
        /^ALTER\s+FUNCTION\s+(?:["']?[a-z0-9_]{1,63}["']?\s*\.\s*)?["']?[a-z0-9_]{1,63}["']?/i;
      let am: RegExpExecArray | null;
      let aGuard = 0;
      while ((am = altRe.exec(src)) !== null) {
        if (++aGuard > 300) break;
        const head = ALT_HEAD.exec(am[0]);
        pins.push({
          schema: am[1] ? unquote(am[1]) : "public",
          name: unquote(am[2]),
          // null = ALTER without an arg list (only legal when the name is unique).
          arity: paramArity(src, am.index + (head ? head[0].length : am[0].length)),
          idx: am.index,
        });
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
        // `SET search_path TO DEFAULT` is not a pin; pg_dump quotes the name.
        if (SEARCH_PATH_PIN_RE.test(stmt)) continue;
        const schema = m[1] ? unquote(m[1]) : "public";
        if (INTERNAL_SCHEMAS.has(schema)) continue;
        // Session-local helpers die with the session. Postgres reserves pg_*
        // schema names, so this only matches pg_temp and pg_temp_N.
        if (schema.startsWith("pg_temp")) continue;
        const name = unquote(m[2]);
        const createIdx = m.index;
        const arity = paramArity(src, createIdx + m[0].length);
        // Only an ALTER AFTER this CREATE counts: CREATE OR REPLACE resets proconfig.
        // It must also be the same schema and the same overload (arity), or have no arg list.
        if (
          pins.some(
            (a) =>
              a.idx > createIdx &&
              a.name === name &&
              a.schema === schema &&
              (a.arity === null || arity === null || a.arity === arity)
          )
        )
          continue;
        // A body that resolves no names (an append-only trigger that only
        // RAISEs) has nothing a planted object could shadow.
        if (bodyHasNoLookups(stmt)) continue;

        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: `SECURITY DEFINER function "${name}" does not pin its search_path. If a later migration pins it (CREATE OR REPLACE … SET search_path or ALTER FUNCTION … SET search_path) or drops it, this finding is stale.`,
        });
      }
      return out;
    },
  },
];
