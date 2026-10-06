import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  isTestPath,
  looksLikePlaceholder,
  matchAll,
  matchLines,
  snippetAt,
  lineAt,
  columnAt,
} from "../helpers";

const isJsLike = (f: ScanFile) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(f.path);

/** High-precision provider secret patterns. */
const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g },
  { name: "Stripe secret key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g },
  { name: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b/g },
  { name: "GitHub fine-grained PAT", re: /\bgithub_pat_[0-9A-Za-z_]{50,}\b/g },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  // Supabase's NEW secret key format (replacing the legacy service_role JWT,
  // which is deprecated end-2026). Server-only: it bypasses every RLS policy.
  // Its sibling `sb_publishable_` is public by design and is already
  // whitelisted in PUBLIC_KEY_PREFIX — do NOT add it here.
  { name: "Supabase secret key", re: /\bsb_secret_[A-Za-z0-9_-]{16,}\b/g },
  {
    name: "Private key block",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  // Note: Twilio Account SID (AC+32hex) intentionally NOT included — it is a
  // public identifier, not a secret, and collides with md5-like cache keys.
];

// Firebase web apps embed a public `apiKey` (AIza…) by design; suppress the
// Google-API-key pattern when the file is clearly Firebase config.
const FIREBASE_MARKER =
  /firebaseConfig|initializeApp|authDomain|firebase\/app|getFirestore|getAuth\(|firebase/i;

// Known PUBLIC key prefixes — safe to commit, must not be flagged as secrets.
const PUBLIC_KEY_PREFIX = /^(pk_|sb_publishable_|pub_|pk\.eyJ|6L[0-9A-Za-z_-]{38})/;
// Stripe ephemeral client secrets are designed to be sent to the browser.
const STRIPE_CLIENT_SECRET = /^(pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$/;

/** A GitHub Actions workflow file. */
const IS_WORKFLOW = /\.github[\/\\]workflows[\/\\][^\/\\]+\.ya?ml$/i;

/** `pull_request_target` used as a workflow trigger, in any of the four YAML
 *  shapes GitHub accepts. Matching the trigger POSITION (not a bare mention)
 *  keeps prose and comments out. */
const PRT_TRIGGER = new RegExp(
  [
    String.raw`^\s{0,8}pull_request_target\s*:`, // on:\n  pull_request_target:
    String.raw`^\s{0,8}-\s*pull_request_target\s*$`, // on:\n  - pull_request_target
    String.raw`\bon\s*:\s*pull_request_target\b`, // on: pull_request_target
    String.raw`\bon\s*:\s*\[[^\]\n]{0,160}\bpull_request_target\b`, // on: [push, pull_request_target]
  ].join("|"),
  "m"
);

/** An explicit checkout of the PULL REQUEST HEAD — i.e. the untrusted fork code.
 *  `pull_request_target` on its own checks out the BASE repo and is the safe
 *  default, so this second marker is what turns the pair into a finding. */
const PR_HEAD_CHECKOUT =
  /ref\s*:\s*["']?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}|refs\/pull\/[^\s"']{0,40}\/(?:merge|head)/i;

/** Curated, conservative advisory list (sample set for the MVP).
 *  `fixedBelow` = a single global floor (simple deps). `fixedByMajor` = a floor
 *  per major release branch, for packages (like Next.js) that backport fixes to
 *  several maintained majors — a single global floor there is WRONG, because a
 *  higher major always compares "greater" and slips through even when it has its
 *  own known-vulnerable range. `fixedByBranch` = a floor per "major.minor"
 *  branch, for packages (like react-server-dom-*) that patch several parallel
 *  MINORS of the same major: CVE-2026-44907 was fixed in 19.0.8, 19.1.9 AND
 *  19.2.8, so both of the coarser shapes would flag 19.1.9 — a fully patched
 *  version — as vulnerable. */
const KNOWN_VULN_DEPS: {
  name: string;
  fixedBelow?: [number, number, number];
  fixedByMajor?: Record<number, [number, number, number]>;
  fixedByBranch?: Record<string, [number, number, number]>;
  /** A floor INSIDE a prerelease line, e.g. 5.0.0-beta.32. `parseVersion` drops
   *  the tag, so `5.0.0-beta.31` (vulnerable) and `-beta.32` (patched) both
   *  collapse to [5,0,0] and are invisible to every numeric compare above. This
   *  is the only way to catch a critical advisory that is fixed within a beta
   *  line, which is where next-auth v5 has lived for a long time. */
  fixedByPrerelease?: { base: string; tag: string; below: number };
  advisory: string;
}[] = [
  {
    name: "next",
    // Next.js maintains parallel branches, and Active LTS MOVED 16.2 -> 16.3 in
    // the August 2026 release (published 2026-08-25): two CRITICAL unauthenticated
    // RCEs — Image Optimization via a crafted AVIF (GHSA-2xp9-vwfh-vxw4, upstream
    // libheif/sharp) and Windows-hosted servers (CVE-2026-75604, no workaround).
    // NOTE: 16.2.11 — an EARLIER floor — is itself vulnerable, so the 16 key
    // must point at the 16.3 branch, not 16.2. 14.x and older have no fix branch,
    // so any major below 15 is flagged outright.
    //
    // 2026-09-22 out-of-band update: CVE-2026-94545 (CVSS 9.5, CRITICAL) — RCE in
    // the Node.js `ImageResponse` from next/og, via improper SVG escaping in
    // upstream Satori. Affected `>=16.2.0 <16.3.6`, so the 16 floor moves
    // 16.3.3 -> 16.3.6. Next.js 15.x is explicitly NOT affected by this RCE
    // (15.5.26 is hardening only), so the 15 floor deliberately STAYS at 15.5.24
    // — raising it would flag 15.5.24/.25 for a bug they do not have.
    //
    // 2026-09-30 September security release: 7 advisories (1 high, 5 medium,
    // 1 low), patched in 16.3.8 / 15.5.27. Unlike the next/og RCE, 15.x IS
    // affected this time (both SSG/ISR cache-poisoning advisories list
    // >=15.0.0), so BOTH floors move. NOTE: 16.3.7 (2026-09-29) is on npm but
    // is NOT the patched release — the floor is 16.3.8, so 16.3.7 must fire.
    // The repo GHSA records carry placeholder ranges ("16.3.?"), so these floors
    // come from the release post, not the range strings. Vercel postponed one
    // further critical + one high fix pending upstream dependencies.
    fixedByMajor: { 15: [15, 5, 27], 16: [16, 3, 8] },
    advisory:
      "September 2026 security release (2026-09-30): HIGH SSRF in Image Optimization via an attacker-controlled, allow-listed remote URL — CVE-2026-94483 / GHSA-cjq9-62q9-8jv4 (16.x; not affected if no images.remotePatterns) — plus five medium issues (SSG/ISR cache poisoning CVE-2026-94543 and CVE-2026-94484, which also affect 15.x; metadata-image dynamicParams bypass CVE-2026-94485; two 'use cache' leaks incl. Draft Mode content CVE-2026-94544) and a low-severity next dev MCP endpoint disclosure (CVE-2026-94486). This is on top of the 2026-09-22 CRITICAL RCE in next/og ImageResponse (CVE-2026-94545, CVSS 9.5, 16.x only), the August 2026 critical unauthenticated RCEs (GHSA-2xp9-vwfh-vxw4, CVE-2026-75604), the July 2026 set (CVE-2026-64641 through CVE-2026-64649) and the earlier CVE-2025-29927 middleware bypass. Patch to 16.3.8+ (16.x) or 15.5.27+ (15.x) — note 16.3.7 is NOT the patched release; 14.x and older have no fix branch. Vercel has postponed one further critical and one high fix pending upstream dependencies, so expect another release.",
  },
  {
    // The upstream package behind CVE-2026-94545. Next.js bundles its own copy
    // (covered by the `next` floor above), so this entry is for apps that depend
    // on satori DIRECTLY to generate OG images.
    name: "satori",
    fixedBelow: [0, 33, 5],
    advisory:
      "CVE-2026-94545 / GHSA-wx4j-mvgx-mqwp (Moderate, CVSS 5.3): satori does not properly escape certain values before including them in generated SVG output, so crafted input can be interpreted as SVG markup. Downstream this became a critical RCE in Next.js next/og. Affects >=0.0.27 <0.33.5 — upgrade to 0.33.5; there is no complete workaround besides upgrading.",
  },
  {
    name: "@supabase/auth-js",
    // GHSA-8r88-6cj9-9fh5 lists affected as "<= 2.69.1" and patched as "2.70.0".
    // 2.69.1 shipped 2025-03-24, BEFORE the May-2025 disclosure, so it is
    // vulnerable — the floor is 2.70.0, not 2.69.1.
    fixedBelow: [2, 70, 0],
    advisory:
      "Insecure path routing (CVE-2025-48370): getUserById / deleteUser / updateUserById / listFactors / deleteFactor accepted non-UUID ids, allowing URL path traversal into a different API function. Fixed in 2.70.0, which requires a valid UUID v4.",
  },
  // React Server Components DoS advisories. These affect ONLY the
  // react-server-dom-* packages — every one of the four advisories explicitly
  // lists react-server-dom-webpack / -parcel / -turbopack and NOT `react` or
  // `react-dom`. Flagging `react` itself would be a false positive (and a false
  // claim). Next.js vendors its own copy of these packages, so Next apps are
  // covered by the `next` floor instead; these entries catch other RSC setups.
  // Floors are the LATEST fix, CVE-2026-44907 (GHSA-wx67-qw84-cm4g, 2026-07-21),
  // which subsumes CVE-2026-23864 / -23869 / -23870. 18.x and 19.3+ are
  // unlisted branches and stay silent (see depFixTarget).
  ...["react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"].map(
    (name) => ({
      name,
      fixedByBranch: {
        "19.0": [19, 0, 8] as [number, number, number],
        "19.1": [19, 1, 9] as [number, number, number],
        "19.2": [19, 2, 8] as [number, number, number],
      },
      advisory:
        "React Server Components denial of service via crafted requests to Server Function endpoints (out-of-memory / CPU exhaustion) — CVE-2026-44907 (July 2026), the latest of four such advisories this year (CVE-2026-23864, -23869, -23870). Patched in 19.0.8, 19.1.9 and 19.2.8.",
    })
  ),
  {
    name: "@auth/core",
    fixedBelow: [0, 41, 3],
    advisory:
      "CVE-2026-73419: OAuth state, nonce and PKCE check cookies are not bound to the provider that issued them, enabling provider confusion and unauthorized account linking in multi-provider setups. Fixed in 0.41.3.",
  },
  {
    name: "next-auth",
    // v4 uses the numeric branch floor; the v5 BETA line needs prerelease-aware
    // comparison, because beta.31 (vulnerable) and beta.32 (patched) both parse
    // to [5,0,0]. A 5.0.0 stable release matches neither and stays silent, which
    // is correct — the fix landed before stable.
    fixedByMajor: { 4: [4, 24, 15] },
    fixedByPrerelease: { base: "5.0.0", tag: "beta", below: 32 },
    advisory:
      "CRITICAL fail-open in Auth.js v5 — CVE-2026-73421 / GHSA-8fpg-xm3f-6cx3 (CVSS 9.1): from 5.0.0-beta.0 until 5.0.0-beta.32, an app that gates access by checking only that the `auth()` object exists can FAIL OPEN when Auth.js hits a server configuration error (a provider missing issuer/authorization endpoints, or an unset AUTH_SECRET) — the object is populated with an error instead of being null, so routes protected only by session existence silently grant access to every visitor. Also CVE-2026-73419: OAuth state/nonce/PKCE check cookies are not bound to the issuing provider, enabling provider confusion and unauthorized account linking. Fixed in 4.24.15 (v4) and 5.0.0-beta.32 (v5).",
  },
  { name: "lodash", fixedBelow: [4, 17, 21], advisory: "Prototype pollution / ReDoS fixed in lodash 4.17.21." },
  { name: "axios", fixedBelow: [1, 8, 0], advisory: "SSRF / credential leak advisories fixed in axios 1.8.0." },
  { name: "jsonwebtoken", fixedBelow: [9, 0, 0], advisory: "Signature bypass issues fixed in jsonwebtoken 9.0.0." },
  { name: "minimist", fixedBelow: [1, 2, 6], advisory: "Prototype pollution fixed in minimist 1.2.6." },
  { name: "semver", fixedBelow: [7, 5, 2], advisory: "ReDoS fixed in semver 7.5.2." },
  { name: "ws", fixedBelow: [8, 17, 1], advisory: "DoS via many headers fixed in ws 8.17.1." },
];

/** Packages that are deprecated / unmaintained — still installable, but no
 *  longer receiving security or bug fixes. A `prefix` match catches a whole
 *  family (e.g. every @supabase/auth-helpers-* package) with zero FP risk,
 *  since no legitimate package shares these namespaces. */
const KNOWN_DEPRECATED_DEPS: { prefix: string; advisory: string }[] = [
  {
    prefix: "@supabase/auth-helpers",
    advisory:
      "@supabase/auth-helpers-* is deprecated — Supabase moved server-side auth to @supabase/ssr and no longer ships fixes here, so an app still on auth-helpers is running an unmaintained auth layer. Migrate to @supabase/ssr.",
  },
];

function parseVersion(v: string): [number, number, number] | null {
  const cleaned = v.replace(/^[\^~>=<\s]+/, "").trim();
  const m = cleaned.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function lt(a: [number, number, number], b: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return false;
}

/** The patched version an advisory says to reach, if `ver` is vulnerable — else
 *  null. Handles both a single global floor and per-major branch floors. */
function depFixTarget(
  ver: [number, number, number],
  adv: {
    fixedBelow?: [number, number, number];
    fixedByMajor?: Record<number, [number, number, number]>;
    fixedByBranch?: Record<string, [number, number, number]>;
  }
): [number, number, number] | null {
  // Branch-level floors are the most specific shape, so they win outright.
  if (adv.fixedByBranch) {
    const branch = `${ver[0]}.${ver[1]}`;
    const own = Object.prototype.hasOwnProperty.call(adv.fixedByBranch, branch)
      ? adv.fixedByBranch[branch]
      : undefined;
    // An UNLISTED branch stays silent in BOTH directions. This deliberately
    // differs from fixedByMajor, which flags anything older than its lowest
    // patched major. An advisory that patches 19.0/19.1/19.2 tells us nothing
    // about whether 18.x was ever affected — guessing there would produce a
    // false positive, and for this product a miss is always the better error.
    if (!own) return null;
    return lt(ver, own) ? own : null;
  }
  if (adv.fixedByMajor) {
    const major = ver[0];
    const own = adv.fixedByMajor[major];
    if (own) return lt(ver, own) ? own : null;
    const majors = Object.keys(adv.fixedByMajor).map(Number);
    const minMajor = Math.min(...majors);
    // Older than any patched branch → no fix exists for it: flag, pointing at
    // the lowest maintained branch. Newer than every known branch → assume the
    // future major carries the fix, so stay silent (precision over coverage).
    if (major < minMajor) return adv.fixedByMajor[minMajor];
    return null;
  }
  if (adv.fixedBelow) return lt(ver, adv.fixedBelow) ? adv.fixedBelow : null;
  return null;
}

const UUID_VALUE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Does this literal look like a CREDENTIAL, or like a readable phrase?
 *
 * A real credential carries a long unbroken alphanumeric run. Dummy values in
 * real code read as separator-joined words — "refresh-token-r2",
 * "jwt.accesstoken.signature" — whose longest run is short. Measured on real
 * repos, that shape was the bulk of this rule's false positives.
 *
 * A bare UUID is exempt: assigned to a secret-named variable it is a plausible
 * secret (e.g. GOTRUE_JWT_SECRET), even though its runs are only 8 chars.
 */
function looksCredentialLike(value: string): boolean {
  if (UUID_VALUE.test(value)) return true;
  let longest = 0;
  for (const run of value.match(/[A-Za-z0-9]+/g) ?? []) {
    if (run.length > longest) longest = run.length;
  }
  if (longest < 12) return false;
  // A long single-case run with no digits is still a word, not a token.
  return /[0-9]/.test(value) || /[A-Z]/.test(value);
}

export const generalRules: Rule[] = [
  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — hardcoded provider secret
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/hardcoded-secret",
    title: "Hardcoded secret in source",
    severity: "critical",
    category: "general",
    cwe: "CWE-798",
    message:
      "A credential that matches a known provider format is hardcoded in source. Anything committed to git is effectively public to anyone who can read the repo or its history.",
    recommendation:
      "Move the secret to an environment variable, purge it from git history (e.g. git filter-repo / BFG), and rotate it at the provider.",
    scan: (f) => {
      const out: RuleMatch[] = [];
      const firebaseCtx = FIREBASE_MARKER.test(f.content);
      for (const { name, re } of SECRET_PATTERNS) {
        const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        rx.lastIndex = 0;
        let m: RegExpExecArray | null;
        let guard = 0;
        while ((m = rx.exec(f.content)) !== null) {
          if (++guard > 1000) break;
          const token = m[0];
          // Firebase public web apiKey — not a secret.
          if (name === "Google API key" && firebaseCtx) continue;
          // Placeholder-check the matched TOKEN, never the whole line.
          if (name !== "Private key block" && looksLikePlaceholder(token)) continue;
          out.push({
            line: lineAt(f.content, m.index),
            column: columnAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            message: `${name} detected in source.`,
          });
        }
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // CRITICAL — generic assigned secret (key/token/password = "literal")
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/assigned-secret-literal",
    title: "Credential assigned to a string literal",
    severity: "critical",
    category: "general",
    cwe: "CWE-798",
    message:
      "A variable named like a secret (apiKey / token / password / secret) is assigned a long string literal. This is a hardcoded credential rather than a configuration reference.",
    recommendation:
      "Replace the literal with process.env.<NAME>, keep the real value in an untracked .env, and rotate the exposed value.",
    appliesTo: (f) =>
      isJsLike(f) || /\.(json|yml|yaml|env)$/.test(f.path) || /\.env/.test(f.path),
    scan: (f) => {
      // Test / fixture / mock files are full of deliberately fake credentials.
      // Measured on real repos, they were the largest false-positive source for
      // this NAME-based heuristic. general/hardcoded-secret is unaffected and
      // still matches provider formats in every file.
      if (isTestPath(f.path)) return [];
      const firebaseCtx = FIREBASE_MARKER.test(f.content);
      return matchLines(f, (line) => {
        // Optional identifier prefix so dbPassword / myApiKey / stripeSecret
        // are caught, not just the bare keyword.
        const m = line.match(
          /(?:^|[^A-Za-z0-9_])([A-Za-z0-9_]*?(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?token|auth[_-]?token))\s*[:=]\s*["'`]([^"'`]{12,})["'`]/i
        );
        if (!m) return null;
        const value = m[2];
        if (looksLikePlaceholder(value)) return null;
        if (/\s/.test(value)) return null; // UI/i18n/help copy, design tokens
        if (PUBLIC_KEY_PREFIX.test(value)) return null; // publishable/public keys
        // A Supabase anon/publishable JWT (eyJ….eyJ….) is PUBLIC by design and
        // safe to commit — measured as the #1 false positive on AI-built Supabase
        // apps (they hardcode it in vite.config/client). Skip it here; the
        // dangerous variant, a service_role JWT, still fires — its payload carries
        // the service_role marker (and supabase/service-role-jwt-literal catches it).
        if (
          /^eyJ[A-Za-z0-9_-]+\.eyJ/.test(value) &&
          !/service_role|c2VydmljZV9yb2xl/.test(value)
        ) {
          return null;
        }
        if (STRIPE_CLIENT_SECRET.test(value)) return null; // ephemeral client secret
        // Firebase web apiKey (AIza…) is public by design.
        if (firebaseCtx && /^AIza[0-9A-Za-z_-]{35}$/.test(value)) return null;
        // Require credential-like STRUCTURE, not a readable phrase.
        if (!looksCredentialLike(value)) return null;
        return {
          column: (m.index ?? 0) + 1,
          message: `Hardcoded value assigned to "${m[1]}".`,
        };
      });
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — known-vulnerable dependency
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/vulnerable-dependency",
    title: "Dependency with a known advisory",
    severity: "warning",
    category: "general",
    cwe: "CWE-1395",
    message:
      "A dependency is pinned below a version that fixes a known security advisory.",
    recommendation:
      "Upgrade to the patched version and run npm audit to confirm the advisory is resolved.",
    appliesTo: (f) => /(^|[\/\\])package\.json$/.test(f.path),
    scan: (f) => {
      let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      try {
        pkg = JSON.parse(f.content);
      } catch {
        return [];
      }
      // Pull only the two known keys — never spread arbitrary uploaded JSON
      // into an object (prototype-pollution hygiene).
      const deps: Record<string, string> = {};
      if (pkg && typeof pkg.dependencies === "object") {
        for (const [k, v] of Object.entries(pkg.dependencies)) {
          if (k !== "__proto__") deps[k] = v as string;
        }
      }
      if (pkg && typeof pkg.devDependencies === "object") {
        for (const [k, v] of Object.entries(pkg.devDependencies)) {
          if (k !== "__proto__" && !(k in deps)) deps[k] = v as string;
        }
      }
      const out: RuleMatch[] = [];
      for (const adv of KNOWN_VULN_DEPS) {
        const raw = deps[adv.name];
        if (!raw || typeof raw !== "string") continue;

        // Prerelease line first — the numeric compare below cannot see the tag.
        const pre = adv.fixedByPrerelease;
        if (pre) {
          const base = pre.base.replace(/\./g, "\\.");
          const pm = new RegExp(`^[\\^~>=<\\s]*${base}-${pre.tag}\\.(\\d+)`).exec(
            raw.trim()
          );
          if (pm) {
            if (Number(pm[1]) < pre.below) {
              const idx = f.content.indexOf(`"${adv.name}"`);
              out.push({
                line: idx >= 0 ? lineAt(f.content, idx) : 1,
                column: idx >= 0 ? columnAt(f.content, idx) : undefined,
                snippet:
                  idx >= 0 ? snippetAt(f.content, idx) : `"${adv.name}": "${raw}"`,
                message: `${adv.name}@${raw}: ${adv.advisory} (upgrade to >= ${pre.base}-${pre.tag}.${pre.below}).`,
              });
            }
            // A recognised prerelease is fully decided here, either way.
            continue;
          }
        }

        const ver = parseVersion(raw);
        if (!ver) continue;
        const target = depFixTarget(ver, adv);
        if (target) {
          const idx = f.content.indexOf(`"${adv.name}"`);
          out.push({
            line: idx >= 0 ? lineAt(f.content, idx) : 1,
            // The column is what keeps two advisories declared on the SAME line
            // (a single-line / minified package.json) as two distinct findings —
            // finding ids are built from file+line+column+snippet, so without it
            // the second one is silently deduplicated away.
            column: idx >= 0 ? columnAt(f.content, idx) : undefined,
            snippet:
              idx >= 0 ? snippetAt(f.content, idx) : `"${adv.name}": "${raw}"`,
            message: `${adv.name}@${raw}: ${adv.advisory} (upgrade to >= ${target.join(".")}).`,
          });
        }
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // INFO — deprecated / unmaintained dependency
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/deprecated-dependency",
    title: "Deprecated, unmaintained dependency",
    severity: "info",
    category: "general",
    cwe: "CWE-1104",
    message:
      "A dependency is deprecated and no longer receives security or bug fixes. Staying on an unmaintained package means any future advisory against it will never be patched.",
    recommendation:
      "Migrate to the maintained replacement. For @supabase/auth-helpers, move to @supabase/ssr — see Supabase's auth-helpers → SSR migration guide.",
    appliesTo: (f) => /(^|[\/\\])package\.json$/.test(f.path),
    scan: (f) => {
      let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      try {
        pkg = JSON.parse(f.content);
      } catch {
        return [];
      }
      // Pull only the two known keys — never spread arbitrary uploaded JSON
      // (prototype-pollution hygiene), matching general/vulnerable-dependency.
      const deps: Record<string, string> = {};
      if (pkg && typeof pkg.dependencies === "object") {
        for (const [k, v] of Object.entries(pkg.dependencies)) {
          if (k !== "__proto__") deps[k] = v as string;
        }
      }
      if (pkg && typeof pkg.devDependencies === "object") {
        for (const [k, v] of Object.entries(pkg.devDependencies)) {
          if (k !== "__proto__" && !(k in deps)) deps[k] = v as string;
        }
      }
      const out: RuleMatch[] = [];
      for (const name of Object.keys(deps)) {
        const adv = KNOWN_DEPRECATED_DEPS.find((d) => name.startsWith(d.prefix));
        if (!adv) continue;
        const idx = f.content.indexOf(`"${name}"`);
        out.push({
          line: idx >= 0 ? lineAt(f.content, idx) : 1,
          // See general/vulnerable-dependency — the column is what keeps two
          // deprecated packages on one line from collapsing into one finding.
          column: idx >= 0 ? columnAt(f.content, idx) : undefined,
          snippet: idx >= 0 ? snippetAt(f.content, idx) : `"${name}": "${deps[name]}"`,
          message: `${name} is deprecated. ${adv.advisory}`,
        });
      }
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — SQL built by string interpolation / concatenation
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/sql-injection",
    title: "Possible SQL injection",
    severity: "warning",
    category: "general",
    cwe: "CWE-89",
    message:
      "A SQL statement is assembled with template interpolation or string concatenation. User-controlled values spliced into SQL text enable injection.",
    recommendation:
      "Use parameterised queries / prepared statements (placeholders + bound values) instead of building SQL strings. With Supabase prefer the query builder or .rpc() with typed args.",
    appliesTo: (f) => isJsLike(f),
    scan: (f) => {
      const out: RuleMatch[] = [];
      // Template literal that contains a DML statement AND an interpolation.
      // Every run is bounded and newline-excluded => ReDoS-safe. The negative
      // lookbehind excludes parameterised tagged templates (sql`…`), which are
      // safe. Requiring a real DML verb (not a bare WHERE/FROM) avoids flagging
      // ordinary prose that happens to contain SQL keywords.
      // A REAL SQL statement shape, not a bare keyword: SELECT…FROM, INSERT
      // INTO, UPDATE…SET, DELETE FROM. Requiring the companion keyword stops
      // ordinary prose ("An update about …", "select an option") from matching.
      out.push(
        ...matchAll(
          f,
          /(?<![A-Za-z0-9_$.])`\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^`\n]{1,200}\bFROM\b[^`\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^`\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^`\n]{0,250}\$\{[^}\n]{1,150}\}[^`\n]{0,150}`/gi
        )
      );
      // Concatenation: "<sql shape>" + variable
      out.push(
        ...matchAll(
          f,
          /["']\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^"'\n]{1,200}\bFROM\b[^"'\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^"'\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^"'\n]{0,200}["']\s*\+\s*[A-Za-z_$]/gi
        )
      );
      return out;
    },
  },

  // ──────────────────────────────────────────────────────────────────────
  // WARNING — eval / Function constructor
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/dangerous-eval",
    title: "Use of eval()",
    severity: "warning",
    category: "general",
    cwe: "CWE-95",
    message:
      "eval() (or the Function constructor) executes arbitrary code. If any part of the argument is attacker-influenced, this is remote code execution.",
    recommendation:
      "Remove eval()/new Function(). Parse data with JSON.parse, dispatch via a lookup table, or use a safe expression evaluator.",
    appliesTo: (f) => isJsLike(f),
    // Require a non-empty argument so the bare word "eval()" in prose, strings,
    // docs, or comments about security isn't flagged — only real calls.
    scan: (f) => matchAll(f, /\beval\s*\(\s*[^)\s]|new\s+Function\s*\(\s*[^)\s]/g),
  },

  // ──────────────────────────────────────────────────────────────────────
  // INFO — dangerouslySetInnerHTML (potential XSS)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/dangerous-inner-html",
    title: "dangerouslySetInnerHTML usage",
    severity: "info",
    category: "general",
    cwe: "CWE-79",
    message:
      "dangerouslySetInnerHTML injects raw HTML, bypassing React's escaping. If the HTML includes any user-provided content it becomes a stored/reflected XSS vector.",
    recommendation:
      "Avoid raw HTML where possible. If you must render it, sanitise first with a vetted library (e.g. DOMPurify) and never pass unsanitised user input.",
    appliesTo: (f) => /\.(tsx|jsx)$/.test(f.path),
    // Require the JSX prop assignment so prose mentioning the API isn't flagged.
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /dangerouslySetInnerHTML\s*=/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.content)) !== null) {
        // Exempt JSON-LD structured-data scripts — the universal, SAFE pattern
        // (<script type="application/ld+json" dangerouslySetInnerHTML=...>): the
        // payload is serialized data, not author-written markup. Confirm the
        // ld+json type sits in the SAME unclosed tag (no '>' between it and the
        // prop), so an unrelated dangerouslySetInnerHTML nearby still flags.
        const before = f.content.slice(Math.max(0, m.index - 300), m.index);
        const ld = before.lastIndexOf("application/ld+json");
        if (ld !== -1 && !before.slice(ld).includes(">")) continue;
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
  // WARNING — pull_request_target that checks out the untrusted PR head
  // (the classic "pwn request": fork code running with the base repo's secrets)
  // ──────────────────────────────────────────────────────────────────────
  {
    id: "general/workflow-prt-head-checkout",
    title: "Workflow runs untrusted PR code with secrets",
    severity: "warning",
    category: "general",
    cwe: "CWE-829",
    message:
      "This workflow is triggered by pull_request_target — which runs with the BASE repository's secrets and a read/write GITHUB_TOKEN — and then explicitly checks out the pull request HEAD, i.e. code from the contributor's fork. Anyone who can open a pull request can therefore run their own code with your secrets in scope.",
    recommendation:
      "Either switch the trigger to pull_request (fork PRs get no secrets there), or keep pull_request_target but do NOT check out the PR head — split the job so that any step touching untrusted code runs without secrets, and pass results between jobs via artifacts.",
    reference:
      "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    appliesTo: (f) => IS_WORKFLOW.test(f.path),
    scan: (f) => {
      // BOTH markers are required. pull_request_target alone checks out the base
      // repo and is safe; a head checkout under an ordinary pull_request trigger
      // gets no secrets. Only the pair is dangerous — and requiring the pair is
      // what keeps this rule near-zero-false-positive.
      if (!PRT_TRIGGER.test(f.content)) return [];
      const m = PR_HEAD_CHECKOUT.exec(f.content);
      if (!m) return [];
      return [
        {
          line: lineAt(f.content, m.index),
          column: columnAt(f.content, m.index),
          snippet: snippetAt(f.content, m.index),
        },
      ];
    },
  },
];
