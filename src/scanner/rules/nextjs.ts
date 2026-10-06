import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  hasUseServer,
  isApiRoute,
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

const MUTATION_SIGNALS =
  /\.(insert|update|delete|upsert)\s*\(|prisma\.[a-zA-Z]+\.(create|update|delete|upsert|deleteMany|updateMany)|db\.(insert|update|delete)|drizzle/i;

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
    scan: (f) => {
      if (!hasUseServer(f.content)) return [];
      if (!MUTATION_SIGNALS.test(f.content)) return [];
      if (AUTH_SIGNALS.test(f.content)) return [];
      const m = MUTATION_SIGNALS.exec(f.content);
      const idx = m ? m.index : 0;
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
  // WARNING — API route consumes input without validation
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/api-route-no-input-validation",
    title: "API route without input validation",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-20",
    message:
      "This API route reads the request body (request.json()) but there is no schema validation. Unvalidated input flows straight into your handler, inviting malformed data, injection, and mass-assignment bugs.",
    recommendation:
      "Validate the parsed body against a schema (e.g. zod safeParse) before use, and return 400 on failure. Consider rate limiting for unauthenticated routes.",
    appliesTo: (f) => isApiRoute(f.path) && isJsLike(f),
    scan: (f) => {
      const usesBody = /request\.(json|formData|text)\s*\(|req\.(body|json)/.test(
        f.content
      );
      if (!usesBody) return [];
      // Exempt signature-verified webhooks. They read the RAW body specifically
      // to verify an HMAC/signature BEFORE processing — that verification IS the
      // input gate, and you can't schema-parse the exact bytes you must hash.
      const signatureVerified =
        /x-hub-signature|stripe-signature|constructEvent|timingSafeEqual|createHmac|webhook[_-]?secret|verif\w*(Signature|Webhook)/i.test(
          f.content
        );
      if (signatureVerified) return [];
      // Validation can be a schema library, a real `.parse(`/`.safeParse(` (not
      // JSON/Date/Number), OR a hand-rolled guard the schema check misses: a
      // type check, a regex `.test`, an allow-list membership check, or an
      // explicit 400 rejection of bad input. Recognising these stops the rule
      // flagging routes that DO validate, just not via a schema library.
      const validates =
        /\bz\.|\bzod\b|safeParse|valibot|yup|joi|superstruct|ajv|\.validate\s*\(|(?<!JSON)(?<!Date)(?<!Number)\.parse\s*\(/.test(
          f.content
        ) ||
        /\btypeof\s+\w/.test(f.content) ||
        /\.(?:test|includes|has)\s*\(/.test(f.content) ||
        /\bstatus\b\s*[:(]\s*400\b|\bbadRequest\b/.test(f.content);
      if (validates) return [];
      const m = /request\.(json|formData|text)\s*\(|req\.(body|json)/.exec(
        f.content
      );
      const idx = m ? m.index : 0;
      return [
        {
          line: lineAt(f.content, idx),
          snippet: snippetAt(f.content, idx),
        },
      ];
    },
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
      "Verify the signature before trusting the payload — Stripe: stripe.webhooks.constructEvent(rawBody, sig, endpointSecret); svix/Clerk: new Webhook(secret).verify(...); generic HMAC: recompute with crypto.createHmac and compare using timingSafeEqual. Read the RAW body (request.text()), not the parsed JSON.",
    appliesTo: (f) => isJsLike(f) && (isApiRoute(f.path) || /webhook/i.test(f.path)),
    scan: (f) => {
      // Is this actually a webhook receiver? Either the path says so, or the code
      // reads a provider signature header. SDK presence alone is NOT enough — a
      // Stripe checkout-session route uses Stripe but is not a webhook.
      const isWebhook =
        /webhook/i.test(f.path) ||
        /["'`](?:stripe|x-hub|svix|paypal|razorpay|x)[-_]?signature["'`]/i.test(
          f.content
        );
      if (!isWebhook) return [];
      // It must read the request body to have a payload worth forging.
      const readsBody =
        /request\.(?:text|json|arrayBuffer|formData)\s*\(|req\.(?:body|rawBody)|await\s+[\w.]+\.text\s*\(/.test(
          f.content
        );
      if (!readsBody) return [];
      // Any recognised signature verification present -> not a finding.
      const verifies =
        /constructEvent(?:Async)?|webhooks\.constructEvent|\bnew\s+Webhook\s*\(|verif\w*(?:Signature|Webhook|Header)|timingSafeEqual|createHmac/i.test(
          f.content
        );
      if (verifies) return [];
      const m =
        /request\.(?:text|json|arrayBuffer|formData)\s*\(|req\.(?:body|rawBody)/.exec(
          f.content
        );
      const idx = m ? m.index : 0;
      return [
        {
          line: lineAt(f.content, idx),
          snippet: snippetAt(f.content, idx),
          message:
            "Webhook route reads the request body but no signature verification (constructEvent / HMAC) was detected.",
        },
      ];
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — CORS wildcard with credentials
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "nextjs/cors-wildcard",
    title: "Permissive CORS configuration",
    severity: "warning",
    category: "nextjs",
    cwe: "CWE-942",
    message:
      "Access-Control-Allow-Origin is set to '*'. Combined with credentials or auth cookies, a wildcard origin lets any website make authenticated requests on a user's behalf.",
    recommendation:
      "Reflect a specific allowlist of trusted origins instead of '*', especially on routes that read cookies or Authorization headers.",
    appliesTo: (f) => isJsLike(f),
    scan: (f) =>
      matchAll(f, /["']Access-Control-Allow-Origin["']\s*[:,]\s*["']\*["']/g),
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
    message:
      "middleware.ts performs auth/routing logic but exports no config.matcher. Without a matcher it runs on every request (including static assets), which is easy to get subtly wrong and can let protected routes slip through if the logic is path-dependent.",
    recommendation:
      "Export an explicit config = { matcher: [...] } that lists exactly the protected paths, and confirm it covers every route that requires auth.",
    appliesTo: (f) => /(^|[\/\\])middleware\.(ts|js)$/.test(f.path),
    scan: (f) => {
      const doesAuth = /auth|getUser|getSession|token|cookie|redirect/i.test(
        f.content
      );
      // Require an actual `matcher` key — a bare `export const config` (e.g.
      // { runtime: 'edge' }) must NOT suppress the finding.
      const hasMatcher = /config\s*=\s*\{[\s\S]*?\bmatcher\b/.test(f.content);
      if (doesAuth && !hasMatcher) {
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
