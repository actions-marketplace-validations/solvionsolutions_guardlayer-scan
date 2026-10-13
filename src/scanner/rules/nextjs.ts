import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  hasUseServerDirective,
  isApiRoute,
  isEdgeFunction,
  isTestPath,
  matchAll,
  snippetAt,
  lineAt,
  columnAt,
} from "../helpers";

const isJsLike = (f: ScanFile) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path);
const isNextConfig = (f: ScanFile) =>
  /(^|[\/\\])next\.config\.(js|cjs|mjs|ts|mts)$/.test(f.path);

// The image optimizer is OFF — nothing is fetched server-side, so remote-image
// settings cannot be abused. Only a literal `true` / `"custom"` counts; an
// env-driven toggle is not proof it is off in production.
const IMAGE_OPTIMIZER_OFF =
  /\bunoptimized\s*:\s*true\b|\bloader\s*:\s*(['"`])custom\1/g;

// Is the match at `idx` commented out? Deliberately NOT stripJsComments: image
// globs ('//**/**', '/**', '**/x') look like /* ... */ to a regex stripper, which
// would erase the very pattern we match. Instead: a `//` (not part of `://`)
// earlier on the same line, or a line that opens/continues a block comment.
function isCommentedOut(content: string, idx: number): boolean {
  const lineStart = content.lastIndexOf("\n", idx - 1) + 1;
  const before = content.slice(lineStart, idx);
  if (/(^|[^:])\/\//.test(before)) return true;
  return /^\s*(\/\*|\*)/.test(before);
}

const imageOptimizerOff = (content: string) => {
  for (const m of content.matchAll(IMAGE_OPTIMIZER_OFF)) {
    if (!isCommentedOut(content, m.index ?? 0)) return true;
  }
  return false;
};

// Recognised authentication / authorization shapes. Deliberately broad to
// avoid the worst-case outcome: a CRITICAL "no auth" finding on code that IS
// guarded. Note bare `userId` / `session.` were removed — merely reading a
// user id from client input is NOT an auth check (it's the IDOR bug itself).
const AUTH_SIGNALS =
  /\bauth\s*\(|\bauth\.|getUser|getClaims|getSession|getServerSession|getAuth(?:ed)?(?:User|\b)|currentUser|require(?:User|Auth|Session|SignedIn)|assert(?:SignedIn|Authed|User|Auth)|verify(?:Session|Auth|User|Jwt|Token)|isAuthenticated|\bclerk|withAuth|auth(?:ed)?Action|protect(?:ed)?Action|ctx\.user|session\.user|\bsignedIn\b/i;

// ── nextjs/server-action-no-auth helpers (55-repo corpus) ──────────────────
// Database writes. The old trailing `|drizzle` alternative is gone: it matched
// the drizzle-orm IMPORT, so read-only actions counted as writes. Drizzle writes
// still match `.insert(` / `.update(` / `.delete(`.
const MUTATION_SIGNALS =
  /\.(insert|update|delete|upsert)\s*\(|prisma\.[a-zA-Z]+\.(create|update|delete|upsert|deleteMany|updateMany)|db\.(insert|update|delete)/i;
// Raw-SQL writes (drizzle sql``, postgres.js, neon, pg), which the `drizzle`
// alternative used to catch by accident. Bounded runs => ReDoS-safe.
const RAW_SQL_WRITE =
  /\b(?:INSERT\s{1,20}INTO|DELETE\s{1,20}FROM|UPDATE\s{1,20}[A-Za-z_."]{1,64}\s{1,20}SET)\b/; // no /i: UI prose such as "Delete from cart" must not count

/** Index of the first database write in `s`, or -1. */
function firstMutationIndex(s: string): number {
  const a = MUTATION_SIGNALS.exec(s),
    b = RAW_SQL_WRITE.exec(s);
  if (!a) return b ? b.index : -1;
  if (!b) return a.index;
  return Math.min(a.index, b.index);
}

// A custom guard call, awaited, e.g. `await requireViewer()`,
// `await requireTeamRole(id, "admin")`, `await adminViewer()`. CASE-SENSITIVE.
// - `ensure` counts only in its unambiguous auth forms: in the corpus,
//   ensure*Account/User/Admin/Session are get-or-create helpers.
// - Bare resource suffixes (Account/Org/Team/Workspace/Tenant) are NOT accepted:
//   they match load-or-404 helpers such as requireWorkspace(slug).
//   requireOrgAdmin / requireTeamRole still match through their authz suffix.
// ReDoS-safe: the infix {0,30} is followed by a fixed suffix set, every other
// run is bounded.
const GUARD_CALL =
  /\bawait\s{1,5}(?:(?:require|assert)([A-Za-z0-9_]{0,30})(?:User|Viewer|Admin|Auth|Session|Member|Owner|Role|Access|Permission|Permissions|Context|SignedIn|LoggedIn)|(?:get|load|current|admin|require)Viewer|ensure(?:Auth|Authed|Authenticated|Authorized|SignedIn|LoggedIn))\s{0,5}\(/g;
// A For/By/From infix means the subject is PASSED IN, so the helper resolves a
// resource for a caller-chosen user instead of authenticating the caller.
const SUBJECT_INFIX = /(?:For|By|From)(?=[A-Z]|$)/;
// Start of a top-level exported function/const (each one is a callable action).
const EXPORT_START =
  /^export[ \t]+(?:default[ \t]+)?(?:async[ \t]+)?(?:function\b|const[ \t]+[A-Za-z0-9_$]{1,80}[ \t]*=)/gm;

/** Positions of real (uncommented, subject-free) custom guard calls. */
function guardCallIndexes(content: string): number[] {
  const out: number[] = [];
  GUARD_CALL.lastIndex = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = GUARD_CALL.exec(content)) !== null && ++k <= 200) {
    if (m[1] && SUBJECT_INFIX.test(m[1])) continue; // e.g. requireClientIdForUser(admin, userId)
    if (isCommentedOut(content, m.index)) continue; // e.g. // TODO: await requireAdmin()
    out.push(m.index);
  }
  return out;
}

// GUARD_CALL is weaker, name-based evidence, so it must cover EVERY exported
// block that writes. Each block runs from one top-level `export` function/const
// to the next. Returns the index of the first write in an unguarded block, or
// -1 when every writing block is guarded, or when no export blocks are found.
function firstUnguardedExportMutation(content: string, guards: number[]): number {
  const starts: number[] = [];
  EXPORT_START.lastIndex = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = EXPORT_START.exec(content)) !== null && ++k <= 500) starts.push(m.index);
  for (let s = 0; s < starts.length; s++) {
    const a = starts[s],
      b = s + 1 < starts.length ? starts[s + 1] : content.length;
    const mi = firstMutationIndex(content.slice(a, b));
    if (mi < 0) continue;
    if (!guards.some((g) => g >= a && g < b)) return a + mi;
  }
  return -1;
}

// A NEXT_PUBLIC_ value is only a CRITICAL leak when the NAME signals a genuine
// secret. A bare "*_KEY" / "*_TOKEN" is NOT enough on its own — publishable
// keys (PostHog phc_, Stripe pk_, Mapbox, analytics, Supabase anon) are
// overwhelmingly named that way, so flagging on "KEY" alone is a false-positive
// machine. Require either a high-confidence fragment OR a known-secret provider.
// (1) Fragments that are essentially never publishable:
const STRONG_SECRET =
  /(SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|CREDENTIAL|BEARER|CONNECTION_STRING|CLIENT_SECRET)/;
// (2) Providers whose *_KEY / *_TOKEN really is secret:
const SECRET_PROVIDER =
  /(OPENAI|ANTHROPIC|\bCLAUDE\b|SENDGRID|TWILIO|RESEND|MAILGUN|POSTMARK|\bAWS\b|AZURE|SUPABASE_SERVICE|STRIPE_SECRET|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_(?:BOT|USER|APP)?_?TOKEN|NPM_TOKEN|VERCEL_TOKEN|OPENROUTER|\bGROQ\b|GEMINI_API|GOOGLE_API)/;
// Known-PUBLIC names — publishable / anon / analytics / maps / captcha keys are
// designed to live in the browser.
const PUBLIC_ENV_OK =
  /(ANON|PUBLISHABLE|\bPUBLIC\b|SITE_KEY|RECAPTCHA|TURNSTILE|HCAPTCHA|MAPBOX|MAPS|POSTHOG|MIXPANEL|AMPLITUDE|SEGMENT|HOTJAR|GTAG|ANALYTICS|ALGOLIA|SENTRY|CLERK|STRIPE_PUBLISHABLE|INTERCOM|CRISP|ABLY|PUSHER)/;

// ── nextjs/cors-wildcard ─────────────────────────────────────────────────
// A bare Access-Control-Allow-Origin '*' is NOT a vulnerability on its own:
// browsers never share a '*' response with a credentialed (cookie) request,
// so on a public or token-authenticated API it exposes nothing an attacker
// couldn't fetch server-side. On 55 real repos the old "any '*'" rule produced
// 150 findings, almost all Supabase edge-function boilerplate and public API
// routes. The rule now reports '*' only where it IS abusable:
//  1. paired with Allow-Credentials true (the pairing browsers reject, and
//     whose usual "fix" is echoing the request Origin);
//  2. in a dev-server configuration (the Vite / webpack-dev-server CVE class);
//  3. in a file that runs its own HTTP server, i.e. a local tool or intranet
//     service any website can reach through http://localhost:<port>.
//
// Accepted residual risks (each is a per-file limit, documented on purpose):
//  (1) A handler module that sets '*' while listen() runs in another file
//      (Express app.js plus server.js, or bin/www) is silenced. Treating
//      express() as a server signal would mostly add FPs on production APIs.
//  (2) '*' on routes protected only by an IP allowlist or VPN cannot be
//      detected per file.
//  (3) A credentials header set in a different module from the '*' is
//      missed. The browser rejects that pairing anyway.
//  (4) FOLLOW-UP RULE NEEDED: the exploitable variant was never detected by
//      this rule. Allow-Origin set from the request Origin (req.headers.origin,
//      headers.get('origin')) together with credentials true and no allowlist
//      comparison (includes, has, ===), and cors({ origin: true,
//      credentials: true }). Allowlist-based reflection (seen in the corpus in
//      Next.js proxies, a Vercel api/_cors.js, a Cloudflare worker and an
//      Express server.js) must stay silent under that rule.
//
// Every quantifier below is a single \s*, the bounded lazy [^}]{0,200}?, or a
// path [\w.-]* followed by the disjoint [\/\\]: no nested or adjacent
// overlapping repetition (600-720 KB adversarial inputs run in a few ms).

// '*' origin in every literal form: 'ACAO': '*' | ('ACAO', '*') |
// headers.set("ACAO","*") | { key: 'ACAO', value: '*' } (next.config
// headers()) | { "key": "ACAO", "value": "*" } (vercel.json). Case-insensitive
// because header names are: res.writeHead(200, {'access-control-allow-origin': '*'}).
const ACAO_STAR =
  /["']Access-Control-Allow-Origin["']\s*(?:[:,]|,\s*["']?value["']?\s*:)\s*["'`]\*["'`]/gi;
// Credentials enabled: the header literal in object, call or key/value form
// (string "true" or boolean true), or a cors-library `credentials: true`.
const CORS_CREDENTIALS_TRUE =
  /["']Access-Control-Allow-Credentials["']\s*(?:[:,]|,\s*["']?value["']?\s*:)\s*["'`]?true\b|\bcredentials\s*:\s*true\b/i;
// Reflected origin: Access-Control-Allow-Origin set to an expression (not a
// string literal) in a file that reads the request's Origin header. Paired
// with credentials this lets ANY site read a signed-in user's responses —
// the classic "fix" for the '*'-plus-credentials error. An allowlist check
// in the same file (includes/has/===, allowedOrigins...) clears it. The
// lookbehind stops the header name itself ("...-Allow-Origin") counting as one.
const ACAO_DYNAMIC =
  /["'`]Access-Control-Allow-Origin["'`]\s{0,4}[:,]\s{0,4}(?!["'])(?:`[^`\n]{0,80}\$\{|[A-Za-z_$(])/gi;
const ORIGIN_FROM_REQUEST =
  /headers\s{0,4}\.\s{0,4}get\s{0,4}\(\s{0,4}["'`]origin["'`]|headers\s{0,4}(?:\.\s{0,4}origin\b|\[\s{0,4}["'`]origin["'`])/i;
const ORIGIN_ALLOWLIST =
  /(?<![-\w])(?:allowed|trusted|whitelisted|allowlisted)[_-]?origins?\b|\b(?:allowlist|whitelist|ALLOWED_ORIGINS?)\b|\.(?:includes|has|indexOf|test|some|find|endsWith)\s{0,4}\(\s{0,4}[\w$.]{0,40}origin|\borigin\w{0,20}\s{0,4}[!=]==?|[!=]==?\s{0,4}[\w$.]{0,40}origin\b/i;
const MSG_CORS_REFLECT =
  "The request's Origin header is echoed back as Access-Control-Allow-Origin together with Access-Control-Allow-Credentials. Any website can then make credentialed requests and read the responses, i.e. read a signed-in user's data. This is what the '*'-plus-credentials error tempts you into; '*' would at least have been refused by the browser.";
// Dev-server configuration (Vite / webpack / Vue CLI / Rspack / CRA proxy /
// Metro): only ever reachable on a developer machine, which is exactly where a
// '*' lets any visited website read source files and dev endpoints. None of
// these calls listen() in the same file, so the own-server gate can't see them.
const DEV_SERVER_CONFIG_PATH =
  /(^|[\/\\])(?:(?:vite|webpack|vue|rspack)\.config\.[cm]?[jt]s|setupProxy\.[cm]?[jt]s)$/i;
const DEV_SERVER_CONFIG =
  /\bdevServer\s*:|\bconfigure(?:Preview)?Server\s*\(|\bsetupMiddlewares\s*[:(]|\benhanceMiddleware\s*[:(]/;
// The file runs its own HTTP server: Node http/https/http2/net, Express/Koa/
// Fastify .listen, Bun.serve, Deno std listenAndServe, Deno.serve /
// @hono/node-server serve with an options object that sets port or hostname,
// or an explicit Private Network Access opt-in. Deno.serve({ port }) without a
// hostname binds 0.0.0.0, which includes loopback, so no bind address is
// required. Supabase edge functions are excluded by PATH in the rule (their
// Express-in-a-function app.listen(8000) is a Supabase docs pattern and is
// internet-facing), not by bind address. Deno.serve(handler) with no options
// object is the Deno Deploy shape and does not count.
const STARTS_OWN_SERVER =
  /\bcreate(?:Secure)?Server\s*\(|\bBun\.serve\s*\(|\.listen\s*\(|\blistenAndServe(?:Tls)?\s*\(|\bserve\s*\(\s*\{[^}]{0,200}?\b(?:port|hostname)\s*:|access-control-allow-private-network/i;
// Test harnesses answer every origin on purpose. isTestPath misses Deno's
// *_test.ts naming, so cover it here.
const isTestLike = (p: string) => isTestPath(p) || /_test\.[cm]?[jt]sx?$/i.test(p);

const MSG_CORS_CREDS =
  "Access-Control-Allow-Origin '*' is combined with Access-Control-Allow-Credentials: true. Browsers reject this pair, and the common 'fix' of echoing the request Origin lets any website make authenticated requests as your users. Use an explicit origin allowlist.";
const MSG_CORS_DEV_SERVER =
  "This dev-server configuration answers every origin with Access-Control-Allow-Origin '*'. While the dev server runs, any website the developer visits can read your source files and dev endpoints from http://localhost:<port> (the class of Vite CVE-2025-24010 and webpack-dev-server CVE-2025-30359). Remove the header or allow only your app's exact origin.";
const MSG_CORS_LOCAL_SERVER =
  "This file runs its own HTTP server and answers every origin with Access-Control-Allow-Origin '*'. If that server is reachable only from a developer machine or an internal network, any website a person on that machine visits can read its responses from http://localhost:<port> (the class of Vite CVE-2025-24010). Allow only your app's exact origin, or check the Origin header.";

// ── nextjs/webhook-no-signature-verification ────────────────────────────
// On 55 real Next.js+Supabase repos the old rule produced 16 findings, almost
// all receivers that DO authenticate the caller with something other than an
// HMAC: a shared secret compared to an env var with a 401, a named auth /
// constant-time helper, Twilio's validateRequest, a per-tenant API key looked
// up in the DB, or a getUser() on an outbound trigger. It also fired on test
// files and on scripts that only read a fetch() Response body. The rule now
// suppresses those gates, but only when they are real: the compared value must
// not be public or hardcoded, a compare must be paired with a 401/403 (a
// mismatch that is only logged is no gate), and a different HTTP handler in the
// same file cannot vouch for the one that reads the body. Three shapes always
// fire: a same-file verify/auth helper that is a `return true` stub, a guard
// that only rejects when the caller sends a credential (fail-open), and a Meta
// hub.verify_token handshake with no X-Hub-Signature-256 HMAC on POST.
//
// Accepted residual risks (documented on purpose):
//  (1) Verification delegated to a helper in another file is trusted only by
//      name (verify*Signature, authorize*Webhook, ...); an HMAC done in another
//      module under an unrecognised name is still reported.
//  (2) Block-form optional verification `if (secret) { constructEvent(...) }`
//      is not detected (the constructEvent call suppresses).
//  (3) A hardcoded secret in another module (CONFIG.webhookSecret) is not seen.
//  (4) FOLLOW-UP: the path gate (/webhook/ or a provider signature header)
//      misses receivers named mpesa / ipn / payment-callback.
//
// Every quantifier is bounded ({0,N}); no nested or adjacent unbounded
// repetition. blankComments and scopeToHandler are single linear passes.
// Worst case on 200 KB adversarial inputs is ~28 ms (ANON_CMP, which only runs
// behind the cheap ANON_PRE prefilter); a full scan() stays under ~30 ms.

// Test files never ship. isTestPath alone would also skip any test/, mocks/ or
// fixtures/ directory, which includes a deployed app/api/webhooks/test/route.ts,
// so deployed entrypoints (API routes, edge-function index files) are only
// skipped by the unambiguous test-file names and test-only directories.
function isWebhookTestFile(path: string): boolean {
  const p = path.toLowerCase().replace(/\\/g, "/");
  // foo.test.ts, foo.spec.js and Deno's index_test.ts.
  if (/[._](?:test|spec)\.[cm]?[jt]sx?$/.test(p)) return true;
  if (/(^|\/)(?:__tests__|__mocks__|__fixtures__|e2e|cypress|testdata)\//.test(p)) return true;
  const deployable =
    isApiRoute(p) || /(^|\/)supabase\/functions\/[^/]+\/index\.[cm]?[jt]sx?$/.test(p);
  return !deployable && isTestPath(p);
}

// Blank `//` and `/* */` comments to spaces (newlines kept, same length) so a
// verifier named only in a TODO comment does not suppress, and indexes still
// line up with the raw content. Deliberately NOT helpers.stripJsComments: its
// /\/\*[\s\S]*?\*\// is quadratic on an unterminated `/*` and, without the m
// flag, never strips a `//` comment at column 0. This is one linear pass that
// skips string literals ('…' and "…" end at a newline) and leaves `://` URLs.
function blankWebhookComments(c: string): string {
  const out = c.split("");
  const n = c.length;
  let i = 0;
  while (i < n) {
    const ch = c[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      i++;
      while (i < n && c[i] !== ch) {
        if (c[i] === "\\") i++;
        else if (c[i] === "\n" && ch !== "`") break;
        i++;
      }
      i++;
      continue;
    }
    if (ch === "/" && c[i + 1] === "/" && c[i - 1] !== ":") {
      while (i < n && c[i] !== "\n") out[i++] = " ";
      continue;
    }
    if (ch === "/" && c[i + 1] === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      // An unterminated /* blanks to EOF.
      while (i < n && !(c[i] === "*" && c[i + 1] === "/")) {
        if (c[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) {
        out[i] = " ";
        out[i + 1] = " ";
        i += 2;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

// App Router files often export GET and POST side by side. A GET handler's
// hub.verify_token compare, getUser() or 401 must not vouch for the POST that
// reads the body, so every OTHER exported HTTP handler is blanked up to the
// next top-level declaration. Imports and top-level helpers are kept.
const WEBHOOK_HANDLER =
  /^export[ \t]{1,3}(?:async[ \t]{1,3})?function[ \t]{1,3}(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|^export[ \t]{1,3}const[ \t]{1,3}(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/gm;
const WEBHOOK_TOPLEVEL = /^(?:export|async|function|const|let|var|class|type|interface|import)\b/gm;
function scopeToWebhookHandler(b: string, bodyIdx: number): string {
  const starts: number[] = [];
  WEBHOOK_HANDLER.lastIndex = 0;
  let hm: RegExpExecArray | null;
  while ((hm = WEBHOOK_HANDLER.exec(b)) !== null) starts.push(hm.index);
  if (starts.length < 2) return b;
  let own: number | undefined;
  for (const s of starts) if (s <= bodyIdx) own = s;
  if (own === undefined) return b;
  // One char array; the blanked ranges never overlap, so the total is O(n).
  const out = b.split("");
  for (const h of starts) {
    if (h === own) continue;
    WEBHOOK_TOPLEVEL.lastIndex = h + 1;
    const t = WEBHOOK_TOPLEVEL.exec(b);
    const end = t ? t.index : b.length;
    for (let i = h; i < end; i++) if (out[i] !== "\n") out[i] = " ";
  }
  return out.join("");
}

// Reading the INBOUND request body. The old catch-all `await X.text(` also
// matched fetch() Response bodies in scripts that SEND webhooks.
const WEBHOOK_BODY_READ =
  /\b(?:req|request)\.(?:text|json|arrayBuffer|formData|blob|parseBody)\s{0,3}\(|\b(?:req|request)\.(?:body|rawBody)\b|\b(?:buffer|getRawBody|readRawBody)\s{0,3}\(\s{0,3}(?:req|request)\b/;
// A same-file auth/verify helper whose body is just `return true` / `=> true`.
const WEBHOOK_STUB =
  /\b(?:is|check|has)?(?:verif|authori[sz]|authentic|validate)\w{0,60}\s{0,3}(?:=\s{0,3}(?:async\s{1,3})?)?(?:function\s{0,3})?\([^()]{0,300}\)\s{0,3}(?::[^{}=;\n]{0,80})?(?:=>|\{)\s{0,200}(?:\{\s{0,200})?(?:return\s{1,3})?true\b/i;
// A guard that rejects only when the credential is PRESENT:
// `if (sig && !verify(...)) return 401` / `if (secret && secret !== env) return 401`.
// A branch that does not return 401/403 (a fail-closed flag set later) is no match.
const WEBHOOK_FAIL_OPEN =
  /\bif\s{0,3}\(\s{0,3}[\w.$?]{0,80}(?:secret|token|api_?key|hottok|signature|sig)\w{0,20}\s{0,3}&&\s{0,3}(?:!\s{0,3}[\w.$]{1,80}\s{0,3}\([^()\n]{0,200}\)|[\w.$]{1,80}\s{0,3}!==?\s{0,3}[^()\n]{1,200})\s{0,3}\)\s{0,3}\{?\s{0,200}return\b[^;]{0,300}\b40[13]\b/i;
// The same fail-open, nested: the comparison sits inside `if (expectedSecret) {`,
// so when the secret env var / column is unset every request is accepted.
// Only counts when the file can actually leave it empty (an env var, or a
// `|| ''` / `?? ''` fallback); `if (!secret) return 500` first is fail-closed
// and never produces this shape.
const WEBHOOK_FAIL_OPEN_NESTED =
  /\bif\s{0,3}\(\s{0,3}[\w.$]{0,80}(?:secret|token|api_?key|signature)\w{0,20}\s{0,3}\)\s{0,3}\{\s{0,300}?if\s{0,3}\([^)\n]{0,250}!==?[^)\n]{0,250}\)\s{0,3}\{?[\s\S]{0,300}?\b40[13]\b/i;
const SECRET_MAY_BE_UNSET =
  /process\.env\.[A-Z0-9_]{0,60}(?:SECRET|TOKEN|KEY)[A-Z0-9_]{0,30}|\|\|\s{0,3}["'`]{2}|\?\?\s{0,3}["'`]{2}/;

// Meta (WhatsApp / Messenger / Instagram) webhook: hub.verify_token guards only
// the GET handshake, so POST events need a real HMAC (VERIFIES_STRONG).
const WEBHOOK_META = /hub[._](?:mode|verify_token|challenge)/i;
const WEBHOOK_VERIFIES_STRONG =
  /constructEvent(?:Async)?|createHmac|timingSafeEqual|["'`]HMAC["'`]|verif\w{0,40}Signature/i;
const WEBHOOK_VERIFIES =
  /constructEvent(?:Async)?|\bnew\s{1,3}Webhook\s{0,3}\(|verif\w{0,40}(?:Signature|Webhook|Header)|timingSafeEqual|createHmac|["'`]HMAC["'`]/i;
// Twilio's validateRequest counts only when the file mentions twilio: the bare
// name is also a common zod / input-validation helper.
const WEBHOOK_TWILIO_CALL = /\bvalidateRequest(?:WithBody)?\s{0,3}\(/;
// Named caller-auth or constant-time helper. Payment-authorization helpers
// (authorizePayment, authorizeCharge) are not caller auth, and
// isAuthorized/isAuthenticated count only when called with the request or
// headers, so a status helper like isAuthorized(payment.status) does not.
const WEBHOOK_AUTH_HELPER =
  /\b(?:(?:authenticate|authori[sz]e)(?!\w{0,30}(?:Payment|Charge|Card|Transaction|Order|Capture))\w{0,30}(?:Webhook|Request|Caller|Secret|Token|Key)\w{0,20}|secretsMatch|bearerMatches|safeCompare|safeEqual|constantTime\w{0,20})\s{0,3}\(|\bis(?:Authenticated|Authori[sz]ed)\w{0,20}\s{0,3}\(\s{0,3}(?:req|request|headers|ctx|c)\b/i;
// Shared-secret gate. A credential compared to a non-literal value
// (`secret !== expected`, `!== `Bearer ${secret}``,
// `!== `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}``).
const WEBHOOK_SECRET_CMP =
  /(?:secret|token|api_?key|hottok|signature)\w{0,40}\s{0,3}[!=]==?\s{0,3}(?!["'`]|null\b|undefined\b)[\w.$(`]|[!=]==?\s{0,3}(?:`[^`\n]{0,60}\$\{\s{0,3})?[\w.$]{0,60}(?:secret|token|api_?key|hottok)\w{0,20}\b|[!=]==?\s{0,3}(?:`[^`\n]{0,60}\$\{\s{0,3})?(?:process\.env\.|Deno\.env\.get\(\s{0,3}["'`])\w{0,60}(?:SECRET|TOKEN|KEY|HOTTOK)\b/i;
// A credential-named DB lookup (per-tenant API key / hottok). A payload
// payment_token / order_token lookup is not caller authentication.
const WEBHOOK_KEY_LOOKUP =
  /\.eq\(\s{0,3}["'`]\w{0,30}(?:api_?key|secret|hottok|(?:webhook|callback|api|auth|access|integration)_?token)\w{0,20}["'`]\s{0,3},|\.eq\(\s{0,3}["'`]\w{1,30}["'`]\s{0,3},\s{0,3}[\w.]{0,40}(?:secret|api_?key|hottok|(?:webhook|callback|api|auth|access|integration|header)_?token)\w{0,20}\s{0,3}\)/i;
const WEBHOOK_GET_USER = /\.auth\.getUser\s{0,3}\(/;
const WEBHOOK_REJECTS =
  /\bstatus\s{0,3}:\s{0,3}40[13]\b|\.status\(\s{0,3}40[13]\s{0,3}\)|,\s{0,3}40[13]\s{0,3}\)/;
const WEBHOOK_AUTH_HEADER_READ =
  /headers(?:\(\s{0,2}\))?(?:\.get\(\s{0,3}|\[\s{0,3})["'`][\w-]{0,40}(?:token|secret|hottok|auth|api-?key)[\w-]{0,20}["'`]/i;
// Gate disqualifiers: the "secret" is public (client-bundled env, Supabase
// anon/publishable key), has a literal fallback, is hardcoded, or the
// "signature" is an unkeyed hash of the body anyone can recompute.
const WEBHOOK_PUBLIC_SECRET_REF =
  /\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC)_\w{0,60}(?:SECRET|TOKEN|API_?KEY|AUTH_?KEY|PASSWORD|PASSWD)/;
const WEBHOOK_ANON_PRE = /(?:anon|publishable)_?key/i;
const WEBHOOK_ANON_CMP =
  /[!=]==?[^\n;&|)]{0,80}(?:anon|publishable)_?key|(?:anon|publishable)_?key[^\n;&|(]{0,40}[!=]==?/i;
// An empty fallback ("") is fail-closed and does not count.
const WEBHOOK_FALLBACK_LITERAL =
  /(?:process\.env\.|import\.meta\.env\.|Deno\.env\.get\(\s{0,3}["'`])\w{0,60}(?:SECRET|TOKEN|API_?KEY|HOTTOK|PASSWORD)\w{0,30}["'`]?\s{0,3}\)?\s{0,3}(?:\|\||\?\?)\s{0,3}["'`][^"'`\n]{1,200}["'`]/i;
// Case-sensitive on purpose; header names (x-…) and env-var names are excluded.
const WEBHOOK_LITERAL_SECRET =
  /\b(?:const|let|var)\s{1,3}\w{0,40}(?:secret|Secret|SECRET)\w{0,20}\s{0,3}(?::\s{0,3}string\s{0,3})?=\s{0,3}["'`](?![xX]-)(?![A-Z][A-Z0-9_]{3,}["'`])[^"'`\n]{4,200}["'`]/;
// A keyed hash (Midtrans / PayU: server key or salt inside update()) is fine.
const WEBHOOK_UNKEYED_HASH =
  /createHash\(\s{0,3}["'`][\w-]{1,12}["'`]\s{0,3}\)\s{0,3}\.update\((?![^)\n]{0,200}(?:secret|key|salt|token|hottok))|subtle\.digest\(\s{0,3}["'`][\w-]{1,12}["'`]\s{0,3},(?![^\n]{0,200}(?:secret|key|salt|token|hottok))/i;

const MSG_WEBHOOK_DEFAULT =
  "Webhook route reads the request body but no signature verification (constructEvent / HMAC) was detected.";
const MSG_WEBHOOK_STUB =
  "This webhook's auth/verification helper is a stub that always returns true, so forged events are accepted.";
const MSG_WEBHOOK_FAIL_OPEN =
  "Verification only runs when the caller sends a signature/secret (`if (x && …) return 401`), so omitting it skips the check. Reject when it is missing.";
const MSG_WEBHOOK_FAIL_OPEN_UNSET =
  "The secret check only runs when a secret is configured (`if (expectedSecret) { … return 401 }`), and the secret can be unset here, so a deployment without it accepts every forged request. Reject when the expected secret is missing (return 500) instead of skipping the check.";
const MSG_WEBHOOK_META =
  "hub.verify_token only protects the GET subscription handshake; POST events must be verified against X-Hub-Signature-256 (HMAC-SHA256 with the app secret).";
const MSG_WEBHOOK_WEAK_SECRET =
  "The webhook compares the caller's credential to a value that is public or hardcoded (NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ env, Supabase anon/publishable key, a string literal or literal fallback) or to an unkeyed hash, so it does not authenticate the sender.";

// ── nextjs/api-route-no-input-validation ────────────────────────────────
// The old rule fired on any body read in a file with no schema library, and a
// typeof / .test / .includes / .has / status 400 ANYWHERE in the file silenced
// it. On 55 real Next.js+Supabase repos (1,021 API routes, 469 body readers)
// that gave 9 findings, all false positives, while a hand-rolled type or 400
// check neither strips extra keys nor stops SSRF, command or path attacks.
// The rule now reports only where request input reaches a dangerous sink, at
// most one finding per kind and 3 per file:
//   mass      the body written whole: insert/update/create payload, spread,
//             Prisma data:, Mongoose 2nd argument, Object.assign + save(),
//             auth.admin user calls, app_metadata                CWE-915
//   filter    the body as a whole-object filter or RPC params, or a body
//             value as the table name                            CWE-639/943
//   owner     a body user/owner id written as the row owner, or scoping
//             the rows of an update/delete                       CWE-639
//   ssrf      a body URL fetched server-side (a fixed host with a body
//             PATH is not reported)                              CWE-918
//   command   a body value in exec() or vm                       CWE-78/94
//   path      a body value in an fs path or service-role storage key CWE-22
//   sql       a body SQL string executed                         CWE-89
//   redirect  a body redirect target                             CWE-601
//   amount    a body Stripe amount that is clearly a price       CWE-602
// Each kind has its own suppressor (AIV_STRICT_SCHEMA, AIV_*_GUARD). A non-strict
// zod/yup parse of the RAW object does not suppress a mass write: the raw
// object still carries extra keys. Writing the parse RESULT never fires, since
// a parse result is never a body-derived name.
//
// Taint is tracked by NAME, file-wide, with one hop of propagation (aliases,
// destructuring, spreads, Object.assign, structuredClone, key-copy loops).
// Accepted residual risks (documented on purpose):
//  (1) Input handed to a helper in another module is not followed.
//  (2) Explicit-field writes are not reported unless the field is an owner id.
//  (3) Names are per file: sinks are searched only from the line of the first
//      body read, so a helper defined ABOVE the handler with a same-named
//      parameter does not collide; one defined below it can.
//  (4) FOLLOW-UP RULES, outside this one: an unauthenticated auth.admin call
//      for a body-chosen email (password update, generateLink), an
//      unauthenticated email send with a client-chosen recipient/template
//      (open relay), searchParams-driven SSRF in GET image proxies, and
//      cross-file stored SSRF.
//
// Every quantifier is bounded ({0,N}) or a \s* between fixed tokens.
// Identifier infixes are \w{0,40}, never \w*: a 40-char infix is unrealistic,
// and an unbounded one is quadratic on a long word. Dynamic names are capped
// (WHOLE 20, FIELD 40) and `$`-escaped. Measured linear: 200-600 KB hostile
// inputs run in 25-130 ms; the largest real route file in 19 ms.
const AIV_ID = String.raw`[A-Za-z_$][\w$]{0,39}`;
// The value itself, not a property of it (body.x / body?.x / body[k]).
const AIV_NOT_PROP = String.raw`(?![\w$]|\s*(?:\?\.|[.\[]))`;
// A name reached after a free-form lazy run must start a token: not the tail
// of a longer identifier (`filename` for a field `name`) and not a property
// (`res.body`). `...body` stays allowed (two dots before the single one).
const AIV_LB = String.raw`(?<![\w$])(?<![^.]\.)`;
// One char, or one balanced (...) group.
const AIV_PAREN_ARG = String.raw`(?:[^()]|\([^()]{0,80}\))`;
// The TOP level of an object literal only: a nested {...} value is consumed
// whole, so `payload: { ...body }` (a JSONB column) is not a row-level spread.
const AIV_OBJ_ITEM = String.raw`(?:[^(){}]|\([^()]{0,80}\)|\{(?:[^{}()]|\([^()]{0,80}\)){0,120}\})`;
// `...X` or `...(X as T)` as a whole element; never `...(X ? a : b)` or
// `...X && y` (a conditional spread of server-built values).
const aivSpread = (x: string) =>
  String.raw`\.\.\.\s*(?:` + x + String.raw`(?![\w$])|\(\s*` + x +
  String.raw`(?![\w$])\s*(?:as\s+[^()]{1,60})?\))\s*(?=[,}\]])`;
const AIV_REQ = String.raw`[\w$]{0,20}?(?:req|Req|request|Request)`;
// A type annotation is only legal right after `const|let|var NAME`; the
// lookbehind stops `a:b,` soup from scanning 80 chars per identifier.
const AIV_TYPE_ANN = String.raw`(?:(?<=\b(?:const|let|var)\s+[\w$]{1,40}\s*):[^=;\n]{1,80})?`;
const AIV_TYPE_ANN_DESTR = String.raw`(?::[^=;\n]{1,80})?`;
// The statement really ends (no `.filter(...)` chained on the next line), so
// `const rows = body.rows\n  .filter(...).map(...)` is server-built, not a copy.
const AIV_STMT_END = String.raw`[ \t]*(?:;|$|\r?\n(?![ \t]*(?:\?\.|\.|\[|\?|:|\|\||&&|\+|-|\*|\/)))`;
// `NAME [: T] <tail>`; group 1 is the declared name.
const aivDecl = (tail: string) =>
  String.raw`(?<![\w$.])(` + AIV_ID + String.raw`)\s*` + AIV_TYPE_ANN + tail;
const AIV_DESTR = String.raw`\b(?:const|let|var)\s*\{([^{}]{1,400})\}\s*` + AIV_TYPE_ANN_DESTR;
// `= await req.json()`, `= (await request.json()) as T`, `= req.body`.
const AIV_SRC_TAIL =
  String.raw`=\s*\(?\s*(?:await\s+)?` + AIV_REQ +
  String.raw`\s*\.\s*(?:json\s*\(\s*\)|body\b(?!\s*(?:\?\.|\.)))`;
const AIV_TEXT_CALL = String.raw`(?:await\s+)?` + AIV_REQ + String.raw`\s*\.\s*text\s*\(\s*\)`;
const AIV_FD_CALL = String.raw`(?:await\s+)?` + AIV_REQ + String.raw`\s*\.\s*formData\s*\(\s*\)`;
const AIV_WHOLE_SRC = new RegExp(aivDecl(AIV_SRC_TAIL), "g");
const AIV_RAW_SRC = new RegExp(aivDecl(String.raw`=\s*\(?\s*` + AIV_TEXT_CALL), "g");
const AIV_FD_SRC = new RegExp(aivDecl(String.raw`=\s*\(?\s*` + AIV_FD_CALL), "g");
const AIV_DESTR_SRC = new RegExp(AIV_DESTR + AIV_SRC_TAIL, "g");

// Gate: the route reads the request body (any *req / *Request receiver).
const AIV_USES_INPUT =
  /[\w$]{0,20}(?:req|Req|request|Request)\s*\.\s*(?:json|formData|text)\s*\(|\breq\.body\b/;
// Signature-verified webhooks read the raw body to check an HMAC first; that
// verification is the input gate. createHmac alone is NOT verification: it
// also SIGNS outgoing requests (a "send test webhook" route), so it counts
// only next to an incoming-signature read or a signature/digest compare.
const AIV_SIG_STRONG =
  /x-hub-signature|stripe-signature|constructEvent|timingSafeEqual|webhook[_-]?secret|verif\w{0,40}(?:Signature|Webhook)|\bnew\s+Webhook\s*\(/i;
const AIV_SIG_READ =
  /\.get\s*\(\s*['"`][^'"`\n]{0,60}(?:signature|hmac)|\[\s*['"`][^'"`\n]{0,60}(?:signature|hmac)['"`]\s*\]|\b\w{0,40}(?:signature|digest)\w{0,40}\s*[!=]==?|[!=]==?\s*\w{0,40}(?:signature|digest)\b|(?:safeCompare|secureCompare|constantTimeEqual)\s*\(/i;
// Fields that name a row, not an object that could be written whole.
const AIV_ID_LIKE =
  /^(?:id|_id|uuid|slug|key|path|filePath|filename|fileName|name|email|token|code|[\w$]*(?:Id|_id|ID|Ids|_ids))$/;
const AIV_OWNER_NAMES =
  "user_id|userId|owner_id|ownerId|author_id|authorId|created_by|createdBy|creator_id|creatorId|uid";
const AIV_OWNER = "(?:" + AIV_OWNER_NAMES + ")";
const AIV_OWNER_FULL = new RegExp("^" + AIV_OWNER + "$");
// Inside a Prisma `data: {…}` object, `author` is also an owner: it is the
// conventional owner RELATION (Post.author -> User), so a client value there
// sets the owner or nests a `connect` to another user. Elsewhere `author` is
// often a plain text column (a quote's or a book's author), so it stays out
// of AIV_OWNER.
const AIV_PRISMA_OWNER = "(?:" + AIV_OWNER_NAMES + "|author)";
const AIV_PRISMA_OWNER_FULL = new RegExp("^" + AIV_PRISMA_OWNER + "$");
// A body value hashed / signed (createHash().update(password)) is not a write.
const AIV_CRYPTO_BEFORE =
  /(?:createHash|createHmac|createCipheriv|createDecipheriv|createSign|createVerify)\s*\([^()]{0,100}\)\s*$|(?:^|[^\w$])(?:hash|hmac|hasher|cipher|decipher|signer|verifier|md5|sha\d{0,3}|digest)\s*$/i;
const AIV_DIGEST_AFTER = /^[^;\n]{0,200}?\.digest\s*\(/;
const AIV_STORAGE_ADMIN =
  /SERVICE_ROLE|service_role|createAdminClient|createServiceClient|supabaseAdmin|getSupabaseAdmin|serviceRole|adminClient|\badmin\s*\.\s*storage/;
const AIV_PRODUCTISH = /^(?:product|plan|item|cart|sku|tier|package|course|ticket|line_?items?)/i;
const AIV_PRICE_NAMED =
  /(?:unit_amount|amount)\s*:\s*(?:[\w$.]{0,60}\(\s*){0,4}(?:[\w$]{1,40}\s*\??\.\s*)?(?:price|unitPrice|unit_price|unitAmount|totalPrice|total_price|total|cost|subtotal)\b/i;

// Per-kind suppressors. Each is evidence that THIS kind of sink is guarded.
// Mass: a strict schema (rejects unknown keys) anywhere in the file.
const AIV_STRICT_SCHEMA =
  /\.strict\s*\(|strictObject|additionalProperties\s*:\s*false|\.noUnknown\s*\(|\.exact\s*\(|forbidNonWhitelisted|forbidUnknownValues/;
const AIV_SSRF_GUARD =
  /\.(?:hostname|host|origin|protocol)\b|allow-?list|allowed_?(?:hosts|domains|origins|urls)|whitelist|isPrivate|isLoopback|is_?private_?ip|ipaddr|private-?ip|ssrf|dns\s*\.\s*(?:promises\s*\.\s*)?lookup|request-filtering-agent|[\w$]{0,40}(?:url|Url|URL|href|Href|host|Host|domain|Domain|endpoint|Endpoint)\s*\.\s*(?:startsWith|endsWith|match)\s*\(|\.test\s*\(\s*[\w$]{0,40}(?:url|Url|URL|href|host|Host|domain|endpoint)/;
const AIV_CMD_GUARD = /shell-quote|shellescape|escapeShellArg|shlex|shell-escape/;
const AIV_PATH_GUARD =
  /basename\s*\(|\.includes\s*\(\s*['"]\.\.['"]|path\s*\.\s*relative\s*\(|sanitize-?filename|[\w$]{0,40}(?:path|Path|dir|Dir|key|Key|name|Name)\s*\)?\s*\.\s*startsWith\s*\(/;
const AIV_REDIRECT_GUARD =
  /startsWith\s*\(\s*['"]\/['"]|isSafe\w{0,40}(?:Redirect|Url|Path)|safeRedirect|isRelative\w{0,40}|allowed\w{0,40}(?:Redirect|Url|Path)s?\b/i;
// Owner: an admin-only route, or the body id compared to the session user.
const AIV_OWNER_ADMIN_PATH = /(?:^|[\/\\])(?:admin|superadmin|internal|cron)(?:[\/\\]|$)/i;
const AIV_OWNER_GUARD =
  /(?:require|assert|ensure|check|verify|is)_?(?:Super)?Admin\b|\brole\s*[!=]==?\s*['"](?:admin|owner|superadmin)['"]|(?:userId|user_id|ownerId|owner_id|authorId|uid)\s*!==?\s*(?:user|session\.user|auth\.user|currentUser)\s*(?:\?\.|\.)\s*id\b|(?:user|session\.user|auth\.user|currentUser)\s*(?:\?\.|\.)\s*id\s*!==?\s*(?:userId|user_id|ownerId|owner_id|authorId|uid)\b/;

type AivKind =
  | "mass"
  | "filter"
  | "owner"
  | "ssrf"
  | "command"
  | "path"
  | "sql"
  | "redirect"
  | "amount";
// Reporting order (most specific / most damaging first).
const AIV_ORDER: AivKind[] = [
  "mass",
  "filter",
  "owner",
  "ssrf",
  "command",
  "path",
  "sql",
  "redirect",
  "amount",
];
const AIV_TEXT: Record<AivKind, { message: string; recommendation: string }> = {
  mass: {
    message:
      "The request body is written as a whole object. A caller can set any column the table accepts (role, user_id, owner_id, is_admin, price…). (CWE-915)",
    recommendation:
      "Copy an explicit allow-list of fields, or parse with a strict schema (zod .strict()) and write the parsed result.",
  },
  filter: {
    message:
      "The request decides which table, which rows (a whole-object filter) or which function parameters a database call uses. (CWE-639/943)",
    recommendation:
      "Fix the table name in code; build filters and RPC arguments from named, validated fields.",
  },
  owner: {
    message:
      "A user/owner id taken from the request decides whose row is written. Any caller can write as, or into, another user's data. (CWE-639)",
    recommendation:
      "Use the id from the verified session (user.id), or check that it equals the session user before writing.",
  },
  ssrf: {
    message: "A URL taken from the request is fetched server-side (SSRF, CWE-918).",
    recommendation:
      "Allow-list hosts and schemes, and reject private, loopback and link-local addresses.",
  },
  command: {
    message: "Request input reaches a shell command or code evaluation (CWE-78/94).",
    recommendation:
      "Use execFile/spawn with an argument array and no shell; never evaluate request input.",
  },
  path: {
    message: "Request input chooses a filesystem path or storage object key (CWE-22).",
    recommendation:
      "Use path.basename or a server-built key, and check the resolved path or key prefix against the caller's folder.",
  },
  sql: {
    message: "A SQL statement taken from the request is executed (CWE-89).",
    recommendation:
      "Never run client-supplied SQL; expose specific parameterised queries or RPCs.",
  },
  redirect: {
    message: "The redirect target comes from the request body (open redirect, CWE-601).",
    recommendation:
      'Only accept relative paths that start with a single "/", or allow-list hosts.',
  },
  amount: {
    message:
      "A payment amount comes from the request. If this is a product price, the buyer can set it (CWE-602).",
    recommendation:
      "Look the price up on the server (Stripe Price id or a DB row) from the product id.",
  },
};

const aivEsc = (s: string) => s.replace(/\$/g, "\\$");
const aivAlt = (names: Iterable<string>) => "(?:" + [...names].map(aivEsc).join("|") + ")";

type AivNames = { whole: Set<string>; field: Set<string> };

/** Destructuring list `a, b: c, d = 1, ...rest` -> rest is WHOLE, the rest FIELD. */
function aivAddDestructured(list: string, n: AivNames): void {
  for (const part of list.split(",").slice(0, 40)) {
    const p = part.trim();
    if (!p) continue;
    const rest = /^\.\.\.\s*([A-Za-z_$][\w$]{0,39})$/.exec(p);
    if (rest) {
      if (n.whole.size < 20) n.whole.add(rest[1]);
      continue;
    }
    const target = p.slice(p.lastIndexOf(":") + 1).trim(); // `a: b` renames to b
    const id = /^([A-Za-z_$][\w$]{0,39})\s*(?:=[^,]*)?$/.exec(target);
    if (id && n.field.size < 40) n.field.add(id[1]);
  }
}

/** Names that hold the whole body (WHOLE) or one value read from it (FIELD). */
function aivBodyNames(c: string): AivNames {
  const n: AivNames = { whole: new Set(), field: new Set() };
  const raw = new Set<string>();
  const fd = new Set<string>();
  const add = (s: Set<string>, cap: number, v: string) => {
    if (s.size < cap) s.add(v);
  };
  for (const m of c.matchAll(AIV_WHOLE_SRC)) add(n.whole, 20, m[1]);
  for (const m of c.matchAll(AIV_RAW_SRC)) add(raw, 10, m[1]);
  for (const m of c.matchAll(AIV_FD_SRC)) add(fd, 10, m[1]);
  // JSON.parse(raw) / JSON.parse(await req.text()) / JSON.parse(req.body)
  const rawAlt = [...[...raw].map(aivEsc), AIV_TEXT_CALL, String.raw`req\.body`].join("|");
  const jsonParse = new RegExp(
    aivDecl(String.raw`=\s*\(?\s*JSON\.parse\s*\(\s*(?:` + rawAlt + String.raw`)\s*\)`),
    "g"
  );
  for (const m of c.matchAll(jsonParse)) add(n.whole, 20, m[1]);
  // Object.fromEntries(formData) => WHOLE; formData.get('x') => FIELD
  const fdAlt = [...[...fd].map(aivEsc), AIV_FD_CALL].join("|");
  const fromEntries = new RegExp(
    aivDecl(
      String.raw`=\s*Object\.fromEntries\s*\(\s*(?:` + fdAlt +
        String.raw`)\s*(?:\.\s*entries\s*\(\s*\)\s*)?\)`
    ),
    "g"
  );
  for (const m of c.matchAll(fromEntries)) add(n.whole, 20, m[1]);
  if (fd.size) {
    const fdGet = new RegExp(aivDecl(String.raw`=\s*\(?\s*` + aivAlt(fd) + String.raw`\s*\.\s*get\s*\(`), "g");
    for (const m of c.matchAll(fdGet)) add(n.field, 40, m[1]);
  }
  // Destructuring straight from the request.
  for (const m of c.matchAll(AIV_DESTR_SRC)) aivAddDestructured(m[1], n);
  // One hop of propagation from WHOLE names, two passes.
  for (let pass = 0; pass < 2 && n.whole.size; pass++) {
    const W = aivAlt(n.whole);
    // const { a, ...rest } = body
    const destr = new RegExp(
      AIV_DESTR + String.raw`=\s*` + W + String.raw`\s*(?:as\s+[^;\n]{1,80})?` + AIV_STMT_END,
      "g"
    );
    for (const m of c.matchAll(destr)) aivAddDestructured(m[1], n);
    // Alias, spread copy, Object.assign({}, …) or structuredClone of a WHOLE.
    const alias = new RegExp(
      aivDecl(
        String.raw`=\s*(?:` +
          W + String.raw`\s*(?:as\s+[^;\n]{1,80})?(?=` + AIV_STMT_END + ")|" +
          String.raw`\{` + AIV_OBJ_ITEM + "{0,300}?" + aivSpread(W) + "|" +
          String.raw`Object\.assign\s*\(\s*\{\s*\}\s*,` + AIV_PAREN_ARG + "{0,200}?" + AIV_LB + W + AIV_NOT_PROP + "|" +
          String.raw`structuredClone\s*\(\s*` + W + String.raw`\s*\))`
      ),
      "g"
    );
    for (const m of c.matchAll(alias)) add(n.whole, 20, m[1]);
    // Object.assign(target, body) taints the target.
    const assign = new RegExp(
      String.raw`Object\.assign\s*\(\s*(` + AIV_ID + String.raw`)\s*,` + AIV_PAREN_ARG + "{0,200}?" + AIV_LB + W + AIV_NOT_PROP,
      "g"
    );
    for (const m of c.matchAll(assign)) if (m[1] !== "Object") add(n.whole, 20, m[1]);
    // Key-copy loop: for (const k in body) / of Object.entries(body) { x[k] = … }
    // An allow-list check inside the loop body is a filter, not a copy.
    const loop = new RegExp(
      String.raw`\bfor\s*\(\s*(?:const|let|var)\s+(?:\[\s*(` + AIV_ID + String.raw`)\s*,\s*` + AIV_ID +
        String.raw`\s*\]|(` + AIV_ID + String.raw`))\s+(?:in\s+` + W +
        String.raw`|of\s+Object\s*\.\s*(?:entries|keys)\s*\(\s*` + W + String.raw`\s*\))\s*\)([^]{0,240})`,
      "g"
    );
    for (const m of c.matchAll(loop)) {
      const k = m[1] || m[2];
      const loopText = m[3]; // the next 240 chars: the loop body
      if (/\.(?:includes|has)\s*\(|\bin\s+[A-Z_]{3,}|allow|editable|whitelist/i.test(loopText)) continue;
      const t = new RegExp(String.raw`(?<![\w$.])(` + AIV_ID + String.raw`)\s*\[\s*` + aivEsc(k) + String.raw`\s*\]\s*=(?!=)`).exec(loopText);
      if (t) add(n.whole, 20, t[1]);
    }
    // const x = body.url / body?.url [as T] [?? / ||]
    const prop = new RegExp(
      aivDecl(
        String.raw`=\s*\(?\s*` + W + String.raw`\s*(?:\?\.|\.)\s*` + AIV_ID +
          String.raw`\s*\)?\s*(?:as\s+[\w$<>\[\]| ]{1,60})?(?:\s*(?:\?\?|\|\|)|` + AIV_STMT_END + ")"
      ),
      "g"
    );
    for (const m of c.matchAll(prop)) add(n.field, 40, m[1]);
  }
  return n;
}

/** First match at or after `from` that `ok` accepts; gives up after 200 rejects. */
function aivFirstMatch(
  re: RegExp,
  c: string,
  from: number,
  ok?: (m: RegExpExecArray) => boolean
): RegExpExecArray | null {
  re.lastIndex = from;
  let m: RegExpExecArray | null;
  let rejected = 0;
  while ((m = re.exec(c)) !== null) {
    if (!ok || ok(m)) return m;
    if (++rejected >= 200) break;
    if (m[0].length === 0) re.lastIndex++;
  }
  return null;
}

type AivSink = { kind: AivKind; index: number; text: string };

/** Candidate sinks, in per-kind priority order. */
function aivFindSinks(c: string, n: AivNames, from: number): AivSink[] {
  const out: AivSink[] = [];
  const first = (kind: AivKind, res: RegExp[], ok?: (m: RegExpExecArray) => boolean) => {
    for (const re of res) {
      const m = aivFirstMatch(re, c, from, ok);
      if (m) {
        out.push({ kind, index: m.index, text: m[0] });
        return;
      }
    }
  };
  const whole = [...n.whole];
  const field = [...n.field];
  const INLINE = [
    String.raw`req\.body`,
    String.raw`\(?\s*(?:await\s+)?` + AIV_REQ + String.raw`\s*\.\s*json\s*\(\s*\)\s*\)?`,
  ];
  // W: the whole body. P: objects that may be written whole (WHOLE, a
  // non-id-like FIELD such as `updates`, or the inline body read).
  const W = "(?:" + [...whole.map(aivEsc), ...INLINE].join("|") + ")";
  const P =
    "(?:" +
    [...whole.map(aivEsc), ...field.filter((f) => !AIV_ID_LIKE.test(f)).map(aivEsc), ...INLINE].join("|") +
    ")";
  // ARG: a body-derived scalar (body.x, req.body.x, (await req.json()).x, a FIELD).
  const argParts: string[] = [];
  if (whole.length) argParts.push(aivAlt(whole) + String.raw`\s*(?:\??\.\s*` + AIV_ID + String.raw`|\[)`);
  argParts.push(String.raw`req\.body\s*(?:\??\.\s*` + AIV_ID + String.raw`|\[)`);
  argParts.push(String.raw`\(\s*await\s+` + AIV_REQ + String.raw`\s*\.\s*json\s*\(\s*\)\s*\)\s*\??\.\s*` + AIV_ID);
  if (field.length) argParts.push(aivAlt(field) + String.raw`(?![\w$])`);
  const ARG = "(?:" + argParts.join("|") + ")";
  const NP = AIV_NOT_PROP;
  const OI = AIV_OBJ_ITEM;
  const PA = AIV_PAREN_ARG;

  // ---- mass assignment ----
  const notCrypto = (m: RegExpExecArray) =>
    !AIV_CRYPTO_BEFORE.test(c.slice(Math.max(0, m.index - 120), m.index)) &&
    !AIV_DIGEST_AFTER.test(c.slice(m.index, m.index + 200));
  const WRITE = String.raw`(?:\.(?:insert|update|upsert|create|createMany|insertOne|insertMany|replaceOne|save|bulkCreate)|(?<!Object)\.values)`;
  const mass: RegExp[] = [
    // M1 the payload IS the body (sole argument, or followed by an options object)
    new RegExp(WRITE + String.raw`\s*\(\s*\[?\s*` + P + NP + String.raw`\s*\]?\s*(?:\)|,\s*\{)`, "g"),
    // M1b Drizzle .set(body), WHOLE only
    new RegExp(String.raw`\.set\s*\(\s*` + W + NP + String.raw`\s*\)`, "g"),
    // M2 the body spread at the top level of the payload object
    new RegExp("(?:" + WRITE + String.raw`|\.set)\s*\(\s*\[?\s*\{` + OI + "{0,300}?" + aivSpread(P), "g"),
    // M3 Prisma data: X / data: { ...X } / upsert create: X / update: X
    new RegExp(
      String.raw`\.(?:create|update|upsert|createMany|updateMany)\s*\(\s*\{` + PA +
        String.raw`{0,300}?\b(?:data|create|update)\s*:\s*(?:\{` + OI + "{0,200}?" + aivSpread(P) +
        "|" + P + NP + String.raw`\s*(?=[,}]))`,
      "g"
    ),
    // M5 second-argument update payload (Mongoose / TypeORM / Sequelize), optionally { $set: X }
    new RegExp(
      String.raw`\.(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|update|replaceOne|findOneAndReplace|merge)\s*\(\s*` +
        PA + String.raw`{1,200}?,\s*(?:\{\s*\$set\s*:\s*)?` + P + NP + String.raw`\s*[,)}]`,
      "g"
    ),
  ];
  // M4 Prisma shorthand `{ data }` when `data` is body-derived
  if (n.whole.has("data") || n.field.has("data"))
    mass.push(
      new RegExp(String.raw`\.(?:create|update|upsert|createMany|updateMany)\s*\(\s*\{(?:` + PA + String.raw`{0,300}?,)?\s*data\s*[,}]`, "g")
    );
  // M6 new Model(body) ... .save()
  if (/\.save\s*\(/.test(c))
    mass.push(
      new RegExp(
        String.raw`\bnew\s+(?!(?:Response|NextResponse|URL|URLSearchParams|Error|[A-Z]\w{0,40}Error|Map|Set|Date|Blob|Headers|Request|FormData|TextEncoder|TextDecoder|Promise|Proxy|WeakMap|WeakSet|Uint8Array|ArrayBuffer|ReadableStream|AbortController)\b)[A-Z][\w$]{0,39}\s*\(\s*(?:\{` +
          OI + "{0,300}?" + aivSpread(W) + "|" + W + NP + ")",
        "g"
      )
    );
  // Object.assign(doc, body) / doc.set(body), then doc.save(): checked first.
  {
    const assign = new RegExp(
      String.raw`(?:Object\.assign\s*\(\s*(` + AIV_ID + String.raw`)\s*,|(?<![\w$.])(` + AIV_ID + String.raw`)\s*\.\s*set\s*\()` +
        PA + "{0,200}?" + AIV_LB + P + NP,
      "g"
    );
    assign.lastIndex = from;
    let m: RegExpExecArray | null;
    let k = 0;
    while ((m = assign.exec(c)) !== null && ++k <= 200) {
      const tgt = m[1] || m[2];
      if (!tgt || tgt === "Object") continue;
      const save = new RegExp(String.raw`(?<![\w$.])` + aivEsc(tgt) + String.raw`\s*\.\s*save\s*\(`, "g");
      save.lastIndex = m.index;
      if (save.exec(c)) {
        mass.unshift(
          new RegExp(
            String.raw`(?:Object\.assign\s*\(\s*|(?<![\w$.]))` + aivEsc(tgt) + String.raw`\s*(?:,|\.\s*set\s*\()` +
              PA + "{0,200}?" + AIV_LB + P + NP,
            "g"
          )
        );
        break;
      }
    }
  }
  // M7 auth.admin user calls fed the whole body
  mass.push(
    new RegExp(
      String.raw`auth\s*\.\s*admin\s*\.\s*(?:createUser|updateUserById|inviteUserByEmail|generateLink)\s*\(\s*(?:[^(),]{1,80},\s*)?(?:\{` +
        OI + "{0,300}?" + aivSpread(W) + "|" + W + NP + ")",
      "g"
    )
  );
  first("mass", mass, notCrypto);
  // M8 body input written into Supabase app_metadata (role / plan claims)
  {
    const short = field.length ? String.raw`|(?<=[{,]\s*)` + aivAlt(field) + String.raw`(?=\s*[,}])` : "";
    first("mass", [
      new RegExp(
        String.raw`\bapp_metadata\s*:\s*(?:` + ARG + "|" + W + NP + String.raw`|\{[^{}]{0,200}?(?:\.\.\.\s*(?:` +
          ARG + "|" + W + NP + String.raw`)|:\s*(?:` + ARG + ")" + short + "))",
        "g"
      ),
    ]);
  }

  // ---- whole-body filter, RPC params, or the caller picks the table ----
  first("filter", [
    new RegExp(
      String.raw`\.(?:match|find|findOne|findMany|deleteOne|deleteMany|countDocuments|findOneAndDelete|findOneAndUpdate|updateOne|updateMany)\s*\(\s*` +
        W + NP + String.raw`\s*[,)]`,
      "g"
    ),
    new RegExp(
      String.raw`\.rpc\s*\(\s*(?:'[^'\n]{1,80}'|"[^"\n]{1,80}"|` + "`[^`\\n]{1,80}`|" + AIV_ID +
        String.raw`)\s*,\s*` + W + NP + String.raw`\s*[,)]`,
      "g"
    ),
    new RegExp(
      String.raw`(?<![\w$.])(?:supabase\w{0,40}|admin\w{0,40}|serviceClient|sb|db|client)\s*\.\s*from\s*\(\s*(?:` + ARG + ")",
      "g"
    ),
  ]);

  // ---- owner id chosen by the caller (IDOR / spoofing) ----
  {
    const shortFor = (full: RegExp) => {
      const names = field.filter((f) => full.test(f));
      return names.length ? String.raw`|(?<=[{,]\s*)` + aivAlt(names) + String.raw`(?=\s*[,}])` : "";
    };
    const SHORT = shortFor(AIV_OWNER_FULL);
    first("owner", [
      new RegExp(
        String.raw`(?:\.(?:insert|upsert|update|create|createMany|insertOne|replaceOne)|(?<!Object)\.values|\.set)\s*\(\s*\[?\s*\{` +
          OI + String.raw`{0,300}?(?:\b` + AIV_OWNER + String.raw`\s*:\s*(?:` + ARG + ")" + SHORT + ")",
        "g"
      ),
      new RegExp(
        String.raw`\.(?:update|delete|upsert)\s*\(` + PA + String.raw`{0,300}?\)(?:\s*\.\s*(?:eq|neq|in|is|match|filter|select)\s*\(` +
          PA + String.raw`{0,200}?\)){0,6}?\s*\.\s*(?:eq|match)\s*\(\s*['"]` + AIV_OWNER + String.raw`['"]\s*,\s*(?:` + ARG + ")",
        "g"
      ),
      new RegExp(
        String.raw`\.(?:update|updateMany|delete|deleteMany|upsert)\s*\(\s*\{` + PA + String.raw`{0,300}?\bwhere\s*:\s*\{[^{}]{0,200}?(?:\b` +
          AIV_OWNER + String.raw`\s*:\s*(?:` + ARG + ")" + SHORT + ")",
        "g"
      ),
      // Prisma nests the row in `data: { … }`, which the top-level-only object
      // walk above cannot enter: `create({ data: { authorId: body.authorId } })`.
      new RegExp(
        String.raw`\.(?:create|update|upsert|createMany|updateMany)\s*\(\s*\{` + PA +
          String.raw`{0,300}?\b(?:data|create|update)\s*:\s*\{` + OI + String.raw`{0,200}?(?:\b` + AIV_PRISMA_OWNER +
          String.raw`\s*:\s*(?:` + ARG + ")" + shortFor(AIV_PRISMA_OWNER_FULL) + ")",
        "g"
      ),
    ]);
  }

  // ---- SSRF: the request picks the host (a fixed host + body path is fine) ----
  {
    const CALLER = String.raw`(?<![\w$.])(?:fetch|\$fetch|ofetch|got|ky|needle|axios|superagent|undici|https?)(?:\s*\.\s*(?:get|post|put|patch|delete|head|request|fetch))?|\.goto`;
    const URL_START =
      String.raw`(?:new\s+URL\s*\(\s*|String\s*\(\s*|encodeURI\s*\(\s*)?(?:` + ARG + "|`" +
      String.raw`(?:https?:\/\/)?\$\{\s*` + ARG + ")";
    first("ssrf", [
      new RegExp("(?:" + CALLER + String.raw`)\s*\(\s*` + URL_START, "g"),
      new RegExp(String.raw`(?<![\w$.])axios(?:\s*\.\s*request)?\s*\(\s*\{[^{}]{0,200}?\burl\s*:\s*` + URL_START, "g"),
    ]);
  }

  // ---- command injection / code evaluation ----
  first("command", [
    new RegExp(
      String.raw`(?:(?<![\w$.])(?:exec|execSync|execAsync|execPromise|execP|execaCommand|execaCommandSync)|(?:child_process|childProcess|cp)\s*\.\s*(?:exec|execSync))\s*\(\s*(?:` +
        ARG + "|`[^`]{0,200}?\\$\\{\\s*" + ARG + String.raw`|(?:'[^'\n]{0,200}'|"[^"\n]{0,200}")\s*\+\s*` + ARG + ")",
      "g"
    ),
    new RegExp(
      String.raw`\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(\s*(?:` + ARG +
        String.raw`)|\bnew\s+vm\s*\.\s*Script\s*\(\s*(?:` + ARG + ")",
      "g"
    ),
  ]);

  // ---- path traversal (fs) and caller-chosen storage keys ----
  {
    const FSFN = String.raw`(?<![\w$])(?:(?:fs|fsp|fsPromises|promises)\s*\.\s*)?(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|copyFile|copyFileSync|rename|renameSync|sendFile)\s*\(\s*`;
    // ARG inside the FIRST argument only (a body value written as CONTENT is fine).
    const direct = new RegExp(
      FSFN + String.raw`(?:[^(),;\n]|\((?:[^()\n]|\([^()\n]{0,80}\)){0,200}\)){0,200}?` + AIV_LB + ARG,
      "g"
    );
    const res: RegExp[] = [direct];
    if (!aivFirstMatch(direct, c, from)) {
      // One hop: const p = path.join(DIR, body.file) / `${DIR}/${name}` … fs.readFile(p)
      const pv = new Set<string>();
      const decl = new RegExp(
        aivDecl(
          String.raw`=\s*(?:path\s*\.\s*(?:join|resolve)\s*\((?:[^()\n]|\([^()\n]{0,80}\)){0,200}?` + AIV_LB + ARG +
            "|`[^`\\n]{0,200}?\\$\\{\\s*" + ARG + ")"
        ),
        "g"
      );
      for (const m of c.matchAll(decl)) if (pv.size < 10) pv.add(m[1]);
      if (pv.size) res.push(new RegExp(FSFN + aivAlt(pv) + String.raw`(?![\w$])`, "g"));
    }
    if (AIV_STORAGE_ADMIN.test(c))
      res.push(
        new RegExp(
          String.raw`\bstorage\s*\.\s*from\s*\(\s*(?:` + ARG +
            String.raw`|[^()]{0,80}\)\s*\.\s*(?:createSignedUrls?|download|remove|upload|update|move|copy|getPublicUrl)\s*\(\s*\[?\s*(?:` +
            ARG + "|`\\$\\{\\s*" + ARG + "))",
          "g"
        )
      );
    first("path", res);
  }

  // ---- SQL text taken from the request ----
  first("sql", [
    new RegExp(
      String.raw`(?:\$queryRawUnsafe|\$executeRawUnsafe|(?<![\w$.])(?:pool|client|db|conn|connection|pg|knex|sequelize|sql|database|turso|neon)\s*\.\s*(?:query|execute|raw|unsafe|exec))\s*\(\s*(?:` +
        ARG + String.raw`)(?!\s*[\x60(])` + "|" +
        String.raw`\.rpc\s*\(\s*['"](?:exec_sql|execute_sql|run_sql|exec|sql|query|run_query|execute|raw_sql)['"]\s*,` +
        PA + "{0,200}?(?:" + AIV_LB + ARG + "|" + AIV_LB + W + NP + ")",
      "g"
    ),
  ]);

  // ---- redirect target from the body ----
  first("redirect", [
    new RegExp(
      String.raw`(?:(?<![\w$.])(?:redirect|permanentRedirect)|NextResponse\s*\.\s*redirect|\bres\s*\.\s*redirect)\s*\(\s*(?:\d{3}\s*,\s*)?(?:new\s+URL\s*\(\s*)?(?:` +
        ARG + ")",
      "g"
    ),
  ]);

  // ---- payment amount from the request (Stripe) ----
  if (/stripe/i.test(c)) {
    const re = new RegExp(
      String.raw`\.(?:paymentIntents|charges|invoiceItems|prices|paymentLinks|sessions)\s*\.\s*create\s*\(\s*\{[^;]{0,600}?\b(?:unit_amount|amount)\s*:\s*(?:Math\s*\.\s*\w{1,20}\s*\(\s*|Number\s*\(\s*|parseInt\s*\(\s*|parseFloat\s*\(\s*){0,4}(?:` +
        ARG + ")",
      "g"
    );
    const short = n.field.has("amount")
      ? new RegExp(String.raw`\.(?:paymentIntents|charges|invoiceItems)\s*\.\s*create\s*\(\s*\{[^;]{0,300}?[{,]\s*amount\s*[,}]`, "g")
      : null;
    const m = aivFirstMatch(re, c, from) || (short && aivFirstMatch(short, c, from));
    // Only when the amount is clearly a PRICE: the client also names what it
    // buys, or the value is named like a price. A bare { amount } (donation,
    // tip, wallet top-up) is a legitimate design and stays silent.
    if (m) {
      const productish =
        field.some((f) => AIV_PRODUCTISH.test(f)) ||
        (whole.length > 0 &&
          new RegExp(
            aivAlt(whole) + String.raw`\s*\??\.\s*(?:product|plan|item|cart|sku|tier|package|course|ticket|line_?items?)`,
            "i"
          ).test(c));
      if (productish || AIV_PRICE_NAMED.test(m[0])) out.push({ kind: "amount", index: m.index, text: m[0] });
    }
  }
  return out;
}

/** Is this mass-write candidate guarded by a strict schema or an in-place key filter? */
function aivMassSanitized(c: string, text: string, whole: Set<string>): boolean {
  if (AIV_STRICT_SCHEMA.test(c)) return true;
  for (const name of whole) {
    if (!text.includes(name)) continue;
    const e = aivEsc(name);
    // delete body[k] / delete body.role
    if (new RegExp(String.raw`delete\s+` + e + String.raw`\s*[\[.]`).test(c)) return true;
    // Object.keys(body)… .includes/.has: the keys are checked against a list
    if (
      new RegExp(String.raw`Object\s*\.\s*(?:keys|entries)\s*\(\s*` + e + String.raw`\s*\)`).test(c) &&
      /\.(?:includes|has)\s*\(/.test(c)
    )
      return true;
  }
  return false;
}

/** Is this candidate guarded by its kind's suppressor? */
function aivSuppressed(s: AivSink, c: string, path: string, n: AivNames): boolean {
  switch (s.kind) {
    case "mass":
      return aivMassSanitized(c, s.text, n.whole);
    case "ssrf":
      return AIV_SSRF_GUARD.test(c);
    case "command":
      return AIV_CMD_GUARD.test(c);
    case "path":
      return AIV_PATH_GUARD.test(c);
    case "redirect":
      return AIV_REDIRECT_GUARD.test(c);
    case "owner":
      return AIV_OWNER_ADMIN_PATH.test(path) || AIV_OWNER_GUARD.test(c);
    default:
      return false; // filter, sql, amount: no extra suppressor beyond the signature gate
  }
}

function scanApiRouteInput(f: ScanFile): RuleMatch[] {
  if (!AIV_USES_INPUT.test(f.content)) return [];
  if (AIV_SIG_STRONG.test(f.content) || (/createHmac/.test(f.content) && AIV_SIG_READ.test(f.content)))
    return [];
  // Comments blanked to equal-length spaces (newlines kept), so every index
  // maps 1:1 to f.content. blankWebhookComments is one linear, string-aware
  // pass: it also blanks a `//` comment at column 0 and never treats a `/*`
  // inside a string (a glob) as a comment.
  const c = blankWebhookComments(f.content);
  const firstRead = c.search(AIV_USES_INPUT);
  if (firstRead < 0) return []; // the only body read is commented out
  // Sinks are searched from the start of the line holding the first body
  // read: a helper defined above the handler cannot collide on a parameter
  // name, and an inline `.insert(req.body)` on that line is still seen.
  const from = c.lastIndexOf("\n", firstRead) + 1;
  const names = aivBodyNames(c);
  const sinks = aivFindSinks(c, names, from);
  const out: RuleMatch[] = [];
  for (const kind of AIV_ORDER) {
    const s = sinks.find((x) => x.kind === kind && !aivSuppressed(x, c, f.path, names));
    if (!s) continue;
    out.push({
      line: lineAt(f.content, s.index),
      column: columnAt(f.content, s.index),
      snippet: snippetAt(f.content, s.index),
      ...AIV_TEXT[kind],
    });
    if (out.length >= 3) break;
  }
  return out;
}

// ── nextjs/middleware-no-matcher ────────────────────────────────────────
// On 55 real Next.js+Supabase repos all 4 findings were helper modules that only
// share the file name: Supabase updateSession helpers at src/lib/supabase/
// middleware.ts and a TanStack Start request middleware under src/lib/access/.
// Next.js never loads those, so the rule now needs an entry-file location AND a
// Next.js middleware export. All 17 real entry files were still checked.

// Paths where Next.js can never load middleware: well-known helper folders as the
// immediate parent, or 2 or more directories below a src/ segment (src/lib/supabase/middleware.ts).
// Do NOT add 'app' or 'api'. Monorepo app roots (apps/app, apps/api in next-forge)
// and repos whose Next project folder is app/ hold real entry files. src/<one-dir>/
// stays in scope because that dir can be a project root (src/web/middleware.ts).
// ReDoS-safe: the directory segments are bounded ({1,100}, {2,20}) and a segment
// cannot contain the separator that ends it.
const NON_ENTRY_MW_PATH =
  /(?:^|[\/\\])(?:lib|libs|utils|util|helpers|supabase|server|pages|routes|components|middlewares)[\/\\]middleware\.(?:ts|js)$|(?:^|[\/\\])src[\/\\](?:[^\/\\]{1,100}[\/\\]){2,20}middleware\.(?:ts|js)$/;

// The file exports a Next.js middleware handler, named `middleware` or default,
// directly or through any re-export form. Case-sensitive on purpose:
// accessMiddleware / authMiddleware / clerkMiddleware do not match.
// Covers: export default ...; export (async) function middleware; export const|let|var middleware;
// export const { auth: middleware } = NextAuth(...); export { x as middleware } [from ...];
// export { default } from 'next-auth/middleware'; export { mw as default }; export * from '...'.
// ReDoS-safe: every alternative is anchored on a literal `export`, the brace
// bodies are bounded ([^}]{0,300}) and cannot run past the closing brace.
const NEXT_MW_EXPORT =
  /\bexport\s+default\b|\bexport\s+(?:async\s+)?function\s+middleware\b|\bexport\s+(?:const|let|var)\s+middleware\b|\bexport\s+(?:const|let|var)\s*\{[^}]{0,300}\bmiddleware\b|\bexport\s*\{[^}]{0,300}\b(?:middleware|default)\b|\bexport\s*\*\s*from\b/;

// A config object literal (optionally typed, as in `config: MiddlewareConfig =`) that holds a
// live `matcher` key: matcher:, "matcher":, or shorthand { matcher }. A matcher that is
// commented out does not count. A config with only { runtime } does not count.
// The old lazy [\s\S]*? search also let a `matcher` word anywhere later in the
// file (even inside a comment) suppress the finding.
// ReDoS-safe: the config prefix is bounded ({0,120}, newline-excluded), the scan
// window is capped at 4000 chars and at most 50 config objects are examined.
const MW_CONFIG_OBJ = /\bconfig\b[^=;\n]{0,120}=\s*\{/g;
const MW_MATCHER_KEY = /["']?\bmatcher\b["']?\s*[:,}]/g;
function hasLiveMatcher(content: string): boolean {
  let n = 0;
  for (const c of content.matchAll(MW_CONFIG_OBJ)) {
    if (++n > 50) break; // bound work on pathological input
    if (isCommentedOut(content, c.index!)) continue;
    const start = c.index! + c[0].length;
    const win = content.slice(start, start + 4000);
    for (const k of win.matchAll(MW_MATCHER_KEY)) {
      if (!isCommentedOut(content, start + k.index!)) return true;
    }
  }
  return false;
}

export const nextjsRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // WARNING — open redirect: redirect() target read straight from request input
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/open-redirect",
    title: "Open redirect from request input",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-601",
    message:
      "A redirect() / NextResponse.redirect() sends the user to a URL read directly from request input (a query param, req.query, or the request body) in the same call. An attacker can supply an external URL and use your domain to bounce victims to a phishing or malware site.",
    recommendation:
      "Never redirect straight to a user-supplied URL. Validate it against an allow-list of known paths/hosts first, or force it relative (only accept values starting with a single '/'). Note: this rule matches only the direct same-expression case — it does not track a tainted value across variables, so a laundered redirect can still be unsafe.",
    appliesTo: (f) => isJsLike(f),
    // Precision-first: only the narrow slice where the redirect argument LITERALLY
    // reads request input on the same call, and is NOT wrapped in new URL(...) (the
    // common, usually-safe redirect(new URL("/path", req.url)) pattern). Bounded,
    // newline-excluded quantifiers => ReDoS-safe. Measured 0 false positives across
    // 4 real Next.js repos (364 files / 19 redirect calls).
    scan: (f) =>
      matchAll(
        f,
        /\b(?:NextResponse\.)?redirect\s*\(\s*(?![^)\n]*\bnew\s+URL\b)[^)\n]*(?:searchParams\.get\s*\(|nextUrl\.searchParams|\breq(?:uest)?\.query\b|(?:await\s+)?\breq(?:uest)?\.json\s*\(\))/gi
      ),
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — Server Action mutates data without an auth check
  // (heuristic name-matching => warning, never a blocking critical)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/server-action-no-auth",
    title: "Server Action without auth check",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-862",
    message:
      'This module is a Server Action ("use server") that writes to the database but no authentication/authorization check was detected. Server Actions are callable by anyone who can reach your app — a forged POST can invoke them directly.',
    recommendation:
      "At the top of every Server Action, resolve and verify the current user (e.g. const { user } = await getUser(); if (!user) throw …) and authorize the specific operation before mutating data. If you do guard it with a custom helper, this warning is a false positive.",
    appliesTo: (f) => isJsLike(f),
    // Precision (55-repo corpus, 15 -> 0 findings): a real "use server"
    // DIRECTIVE is required (a mention in a comment is not one), the drizzle
    // import no longer counts as a write, and awaited custom guard helpers
    // (requireViewer, requireTeamRole, adminViewer…) are recognised — but only
    // when one sits in EVERY exported block that writes, so a guarded action
    // cannot hide an unguarded sibling.
    scan: (f) => {
      if (!hasUseServerDirective(f.content)) return [];
      const first = firstMutationIndex(f.content);
      if (first < 0) return [];
      if (AUTH_SIGNALS.test(f.content)) return []; // unchanged: still checked per file
      const guards = guardCallIndexes(f.content);
      let idx = first;
      if (guards.length) {
        const unguarded = firstUnguardedExportMutation(f.content, guards);
        if (unguarded < 0) return [];
        idx = unguarded; // report the write in the export that has no guard
      }
      return [
        {
          line: lineAt(f.content, idx),
          snippet: snippetAt(f.content, idx),
          message:
            "Server Action performs a database mutation with no detectable auth/authorization guard.",
        },
      ];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — secret exposed via NEXT_PUBLIC_
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/public-env-secret",
    title: "Secret exposed through NEXT_PUBLIC_",
    severity: "critical",
    category: "nextjs",
    cwe: "CWE-200",
    message:
      "A secret-looking value is exposed through a NEXT_PUBLIC_ environment variable. Anything prefixed with NEXT_PUBLIC_ is inlined into the client bundle and visible to every visitor.",
    recommendation:
      "Drop the NEXT_PUBLIC_ prefix and read the value only on the server. Publishable/anon keys are fine to expose; secret keys, tokens, and passwords are not — rotate any that have shipped.",
    appliesTo: (f) => isJsLike(f) || /\.env/.test(f.path),
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /NEXT_PUBLIC_[A-Z0-9_]+/g;
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(f.content)) !== null) {
        if (++guard > 2000) break;
        const name = m[0];
        if (PUBLIC_ENV_OK.test(name)) continue; // anon / publishable / analytics
        if (/(URL|DOMAIN)/.test(name) || /_(ID|REGION|HOST|ENV|NAME|VERSION)$/.test(name))
          continue;
        // Flag only a genuine secret: a strong fragment OR a known-secret
        // provider. A bare *_KEY / *_TOKEN is too weak to raise a critical.
        if (!STRONG_SECRET.test(name) && !SECRET_PROVIDER.test(name)) continue;
        out.push({
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
          message: `${name} is exposed to the browser bundle.`,
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — API route passes request input to a dangerous sink
  // (regex heuristics without full data flow => warning, never critical).
  // See the comment above AIV_ID for the sink kinds and residual risks.
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/api-route-no-input-validation",
    title: "API route passes request input to a dangerous sink",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-20",
    // Defaults only: every match carries its own sink-specific message and
    // recommendation (with its CWE), so these are never shown on a finding.
    message:
      "This API route passes request input to a dangerous sink: the whole body written to the database, a caller-chosen owner id, table or filter, a server-side fetch, a shell command, a filesystem path or storage key, a SQL string, a redirect, or a payment amount.",
    recommendation:
      "Build writes, filters and outgoing requests from named, validated fields; take user ids from the verified session; allow-list hosts, paths and redirect targets.",
    appliesTo: (f) => isApiRoute(f.path) && isJsLike(f),
    scan: scanApiRouteInput,
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — webhook handler without signature verification
  // (forged events: a fake "payment succeeded" that flips an order to paid)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/webhook-no-signature-verification",
    title: "Webhook without signature verification",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-345",
    message:
      "This route looks like a webhook receiver (Stripe, svix/Clerk, GitHub, …) that reads the request body but never verifies the provider's signature. Without verification, anyone who knows the URL can forge events — e.g. a fake \"payment succeeded\" that flips an order to paid.",
    recommendation:
      "Verify the signature before trusting the payload — Stripe: stripe.webhooks.constructEvent(rawBody, sig, endpointSecret); svix/Clerk: new Webhook(secret).verify(...); generic HMAC: recompute with crypto.createHmac and compare using timingSafeEqual. Read the RAW body (request.text()), not the parsed JSON. Fail closed: reject when the signature/secret header is missing or the env var is unset. If you verify in a shared helper, name it verify*Signature so it is recognised, or exclude the file in .guardlayerignore.",
    appliesTo: (f) => isJsLike(f) && (isApiRoute(f.path) || /webhook/i.test(f.path)),
    scan: (f) => {
      const c = f.content;
      // (1) Test files never ship; deployed entrypoints are never skipped.
      if (isWebhookTestFile(f.path)) return [];
      // (2) Is this actually a webhook receiver? Either the path says so, or the
      // code reads a provider signature header. SDK presence alone is NOT enough
      // — a Stripe checkout-session route uses Stripe but is not a webhook.
      const isWebhook =
        /webhook/i.test(f.path) ||
        /["'`](?:stripe|x-hub|svix|paypal|razorpay|x)[-_]?signature["'`]/i.test(c);
      if (!isWebhook) return [];
      // (3) It must read the INBOUND request body to have a payload worth
      // forging. Matched on raw content; every finding is reported here.
      const m = WEBHOOK_BODY_READ.exec(c);
      if (!m) return [];
      const fire = (message: string): RuleMatch[] => [
        { line: lineAt(c, m.index), snippet: snippetAt(c, m.index), message },
      ];
      // (4) Every suppressor runs on comment-free text (b) scoped to the
      // handler that reads the body (s), never on raw content.
      const b = blankWebhookComments(c);
      const s = scopeToWebhookHandler(b, m.index);
      // (5) Hard fires, checked before any suppressor can hide them.
      if (WEBHOOK_STUB.test(s)) return fire(MSG_WEBHOOK_STUB);
      if (WEBHOOK_FAIL_OPEN.test(s)) return fire(MSG_WEBHOOK_FAIL_OPEN);
      if (WEBHOOK_FAIL_OPEN_NESTED.test(s) && SECRET_MAY_BE_UNSET.test(b))
        return fire(MSG_WEBHOOK_FAIL_OPEN_UNSET);
      if (WEBHOOK_META.test(b)) {
        // Only a real HMAC clears a Meta webhook; the shared-secret and
        // auth-helper suppressors below would accept the verify_token compare.
        return WEBHOOK_VERIFIES_STRONG.test(s) ? [] : fire(MSG_WEBHOOK_META);
      }
      // (6) Signature verification.
      if (
        WEBHOOK_VERIFIES.test(s) ||
        (WEBHOOK_TWILIO_CALL.test(s) && /twilio/i.test(b))
      )
        return [];
      // (7) Named caller-auth or constant-time helper.
      if (WEBHOOK_AUTH_HELPER.test(s)) return [];
      // (8) Shared-secret gate. A compare or getUser() must be paired with a
      // real 401/403. An auth-header read stands in for the rejection only with
      // a credential-named DB key lookup (tenant resolution). A 401 or an auth
      // header on its own is the presence-only check and never suppresses.
      const disq =
        WEBHOOK_PUBLIC_SECRET_REF.test(b) ||
        (WEBHOOK_ANON_PRE.test(s) && WEBHOOK_ANON_CMP.test(s)) ||
        WEBHOOK_FALLBACK_LITERAL.test(b) ||
        WEBHOOK_LITERAL_SECRET.test(b) ||
        WEBHOOK_UNKEYED_HASH.test(s);
      if (disq) return fire(MSG_WEBHOOK_WEAK_SECRET);
      const rejects = WEBHOOK_REJECTS.test(s);
      if (
        ((WEBHOOK_SECRET_CMP.test(s) || WEBHOOK_GET_USER.test(s)) && rejects) ||
        (WEBHOOK_KEY_LOOKUP.test(s) && (rejects || WEBHOOK_AUTH_HEADER_READ.test(s)))
      )
        return [];
      // (9) Nothing recognised.
      return fire(MSG_WEBHOOK_DEFAULT);
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — CORS '*' where it is abusable: with credentials, on a dev
  // server, or on a standalone local/intranet HTTP server. See the comment
  // above ACAO_STAR for why a plain '*' is not reported and the accepted
  // residual risks.
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/cors-wildcard",
    title: "Permissive CORS configuration",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-942",
    message:
      "Access-Control-Allow-Origin '*' is set where it can be abused: together with Access-Control-Allow-Credentials, in a dev-server configuration, or on a standalone local/intranet HTTP server. A plain '*' on a public or token-authenticated API is not reported, because browsers never share a '*' response with a credentialed request.",
    recommendation:
      "Use an explicit origin allowlist. Never pair '*' with credentials, and never 'fix' that pairing by echoing the request Origin. On dev servers and local tools, drop the CORS header or allow only the app's exact origin.",
    // vercel.json is where many Next.js apps set CORS headers.
    appliesTo: (f) => isJsLike(f) || /(^|[\/\\])vercel\.json$/i.test(f.path),
    scan: (f) => {
      if (isTestLike(f.path)) return [];
      const out: RuleMatch[] = [];
      const creds = CORS_CREDENTIALS_TRUE.test(f.content);
      // Echoed Origin + credentials: the exploitable variant of this mistake.
      if (creds && ORIGIN_FROM_REQUEST.test(f.content) && !ORIGIN_ALLOWLIST.test(f.content)) {
        out.push(...matchAll(f, ACAO_DYNAMIC, () => ({ message: MSG_CORS_REFLECT })));
      }
      // Gates read only f.path / f.content and run once per file (no g flag);
      // ACAO_STAR is global, as matchAll requires.
      let message: string | null = null;
      if (creds) message = MSG_CORS_CREDS;
      else if (DEV_SERVER_CONFIG_PATH.test(f.path) || DEV_SERVER_CONFIG.test(f.content))
        message = MSG_CORS_DEV_SERVER;
      else if (!isEdgeFunction(f.path) && STARTS_OWN_SERVER.test(f.content))
        message = MSG_CORS_LOCAL_SERVER;
      if (message) {
        const msg = message;
        out.push(...matchAll(f, ACAO_STAR, () => ({ message: msg })));
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // INFO — middleware with no matcher config
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/middleware-no-matcher",
    title: "Middleware without a route matcher",
    severity: "info",
    category: "nextjs",
    cwe: "CWE-1188",
    // Message no longer says the missing matcher lets routes "slip through": with
    // no matcher the middleware runs EVERYWHERE. The recommendation no longer pushes
    // an allowlist of protected paths, which is exactly how middleware bypasses happen.
    message:
      "This Next.js middleware does auth or redirect logic but exports no config.matcher, so it runs on every request, including static assets and prefetches. That gives the broadest coverage, but every request pays for it, and path filtering moves into code where it is easy to get wrong. Middleware should also never be your only auth check (CVE-2025-29927): verify the session again in route handlers, server actions and RLS.",
    recommendation:
      "Add export const config = { matcher: [...] } that excludes only static internals (for example '/((?!_next/static|_next/image|favicon.ico).*)'), so every page and /api route still passes through. Don't narrow the matcher to a hand-picked list of protected paths: any route missing from that list skips the middleware entirely.",
    // Next.js only loads middleware from a project root (or its src/). Helper
    // modules that merely share the file name (Supabase updateSession helpers in
    // lib/supabase/, Express/TanStack middleware) are not entries — see
    // NON_ENTRY_MW_PATH.
    appliesTo: (f) =>
      /(^|[\/\\])middleware\.(ts|js)$/.test(f.path) && !NON_ENTRY_MW_PATH.test(f.path),
    scan: (f) => {
      // Helper modules (updateSession, accessMiddleware, astro onRequest, ...)
      // export no Next.js middleware handler, so Next.js never runs them.
      if (!NEXT_MW_EXPORT.test(f.content)) return [];
      const doesAuth = /auth|getUser|getSession|token|cookie|redirect/i.test(
        f.content
      );
      // Require a LIVE `matcher` key inside a config object — a bare
      // `export const config` (e.g. { runtime: 'edge' }) or a commented-out
      // matcher must NOT suppress the finding.
      if (doesAuth && !hasLiveMatcher(f.content)) {
        return [{ line: 1, snippet: snippetAt(f.content, 0) }];
      }
      return [];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — image optimizer allow-lists EVERY remote host ('**')
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/image-remote-wildcard-host",
    title: "Image optimizer allows any remote host",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-918",
    message:
      "images.remotePatterns allows ANY host ('**'). /_next/image is a server-side fetcher: with a match-everything allow-list, anyone can make your deployment fetch and re-encode images from any URL (bandwidth and compute you pay for), and every URL counts as allow-listed — the precondition for image-optimizer SSRF bugs such as CVE-2026-94483 (Sept 2026, High). On Next.js 16, private IPs stay blocked unless dangerouslyAllowLocalIP is set; this flags the over-broad allow-list in your config, not a confirmed exploit.",
    recommendation:
      "List the exact hosts you serve images from (e.g. { protocol: 'https', hostname: '<ref>.supabase.co', pathname: '/storage/v1/object/public/**' }). Scoped wildcards like '**.example.com' are fine. If you truly must render arbitrary user-supplied image URLs, set unoptimized on those <Image>s instead of opening the optimizer to the whole internet.",
    reference:
      "https://nextjs.org/docs/app/api-reference/components/image#remotepatterns",
    appliesTo: isNextConfig,
    scan: (f) => {
      const src = f.content;
      if (!/remotePatterns/.test(src) || imageOptimizerOff(src)) return [];
      const out: RuleMatch[] = [];
      // Exactly '**' as the WHOLE hostname, or the URL-object form
      // new URL('https://**...'). A scoped '**.example.com' never matches (the
      // closing quote must follow '**' directly), and a bare '*' is deliberately
      // excluded — it matches a single label, not every host.
      const re =
        /\bhostname\s*:\s*(['"`])\*\*\1|\bnew\s+URL\(\s*(['"`])https?:\/\/\*\*(?=[\/'"`:])/g;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(src)) !== null) {
        if (++guard > 200) break;
        if (isCommentedOut(src, m.index)) continue;
        out.push({
          line: lineAt(src, m.index),
          snippet: snippetAt(src, m.index),
          message:
            "images.remotePatterns allows any host ('**') — the image optimizer will fetch from anywhere.",
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — image optimizer explicitly allowed to fetch private IPs
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/image-allow-local-ip",
    title: "Image optimizer allowed to fetch private IPs",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-918",
    message:
      "images.dangerouslyAllowLocalIP is true, so the server-side image optimizer may fetch from private/local IP addresses. Next.js warns this could allow malicious users to access content on your internal network. It is meant only for self-hosting on a private network.",
    recommendation:
      "Remove dangerouslyAllowLocalIP (it defaults to false). If you self-host and genuinely need internal images, keep remotePatterns pinned to the exact internal hosts and paths — never combine this with a '**' hostname.",
    reference:
      "https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowlocalip",
    appliesTo: isNextConfig,
    scan: (f) => {
      const src = f.content;
      if (imageOptimizerOff(src)) return [];
      for (const m of src.matchAll(/\bdangerouslyAllowLocalIP\s*:\s*true\b/g)) {
        const idx = m.index ?? 0;
        if (isCommentedOut(src, idx)) continue;
        return [{ line: lineAt(src, idx), snippet: snippetAt(src, idx) }];
      }
      return [];
    },
  },
];
