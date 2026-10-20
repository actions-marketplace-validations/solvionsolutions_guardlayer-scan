import type { Rule, RuleMatch, ScanFile } from "../types";
import {
  hasUseServer,
  isApiRoute,
  isEdgeFunction,
  isTestPath,
  looksLikePlaceholder,
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

/**
 * Longest run of consecutive ascending characters of the same class
 * ([0-9], [A-Z] or [a-z]), e.g. "abcdefgh" -> 8, "123456789" -> 9.
 * A plain O(n) loop (no regex), so it is ReDoS-free on any input.
 */
function longestAscendingRun(s: string): number {
  const cls = (c: number) =>
    c >= 48 && c <= 57 ? 1 : c >= 65 && c <= 90 ? 2 : c >= 97 && c <= 122 ? 3 : 0;
  let best = 1;
  let cur = 1;
  for (let i = 1; i < s.length; i++) {
    const a = s.charCodeAt(i - 1);
    const b = s.charCodeAt(i);
    if (b === a + 1 && cls(a) !== 0 && cls(a) === cls(b)) {
      cur++;
      if (cur > best) best = cur;
    } else {
      cur = 1;
    }
  }
  return best;
}

/**
 * Documented dummy tokens that pass looksLikePlaceholder() but can never be a
 * live credential: AWS's published "AKIAIOSFODNN7EXAMPLE", and alphabet/digit
 * sequences like "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123" or
 * "xoxb-1234567890-…" that redaction/parser tests use (measured false
 * positives on the 55-repo corpus). An 8-run has roughly a 62^-7 chance per
 * position in a random base62 key, so a real key (even one with a 7-char run)
 * keeps firing. Kept separate from looksLikePlaceholder, which
 * assigned-secret-literal shares.
 */
const isDummySecretToken = (token: string) =>
  /example/i.test(token) || longestAscendingRun(token) >= 8;

/**
 * True when a real-looking key body follows a PEM private-key header INLINE.
 * A bare header is not a secret: test helpers wrap runtime-generated keys
 * (`-----BEGIN…${b64}…`), parsers strip armor with a regex, and validation
 * tests use stub bodies ("X", "not a key"). Only the window up to the next
 * END/BEGIN marker (max 400 chars) is searched.
 *
 * The window is NORMALIZED first, because real keys are also committed as
 * concatenated chunks shorter than 40 chars, and short keys (Ed25519/X25519/
 * EC) in PHP- (\/), .NET- (JSON unicode escape) or HTML-escaped (&#43;) form would
 * otherwise lose every 40-char run — the pre-change rule fired on all of them.
 * Every regex here is a single character class or a literal alternation over a
 * bounded window, so there is no ReDoS surface.
 */
function hasInlineKeyBody(content: string, headerEnd: number): boolean {
  let win = content.slice(headerEnd, headerEnd + 400);
  const stop = win.search(/-----(?:END|BEGIN) /);
  if (stop !== -1) win = win.slice(0, stop);
  win = win
    .replace(/["'`]\s*(?:\+\s*)?["'`]/g, "") // join concat glue: "abc" +\n  "def" -> abcdef
    .replace(/&#(?:43|x2b);|\\u002b|%2b/gi, "+") // HTML-entity, JSON-unicode and URL-escaped '+'
    .replace(/&#(?:47|x2f);|\\u002f|\\\/|%2f/gi, "/"); // the same for '/', including PHP json_encode's \/
  const run = /[A-Za-z0-9+\/]{40,}/g;
  run.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = run.exec(win)) !== null) {
    const r = m[0];
    // Real base64 mixes all three classes; a long run of one class is prose
    // or an identifier, not key material.
    if (/[A-Z]/.test(r) && /[a-z]/.test(r) && /[0-9]/.test(r)) return true;
  }
  return false;
}

/**
 * A base64 private-key body WITHOUT PEM armor. The prefixes are the base64 of
 * the opening DER bytes of a PRIVATE key only — SEQUENCE{INTEGER 0|1, …}:
 *   - PKCS#1 RSA/DSA                "MIIEowIBAAK…"
 *   - PKCS#8 RSA/DSA/EC             "MIIEvQIBAD…", "MIGHAgEA…", Apple .p8 "MIGTAgEA…"
 *   - SEC1 EC                       "MHcCAQEE…", "MHQCAQEE…", "MIGkAgEB…", "MIHcAgEB…"
 *   - PKCS#8 Ed25519/X25519/Ed448   "MC4CAQAwBQYDK2V…", "MEcCAQAw…"
 *   - the OpenSSH magic "openssh-key-v1" ("b3BlbnNzaC1rZXktdjE")
 * They do NOT match SPKI public keys ("MIIBIjAN…"), PKCS#1 public keys
 * ("MIIBCgKC…"), X.509 certificates ("MIID..TCC…"), CSRs or PKCS#12 ("…IBAz").
 *
 * Why: hasInlineKeyBody() correctly drops body-less headers, but such a header
 * used to be the only signal for a key body kept in a constant and armored in
 * code (template interpolation, '+' concatenation, array spread, a toPem()
 * helper, a pemToDer() edge function). This keeps those firing, reported at
 * the actual secret — and, since it needs no header in the same file, also
 * catches a body in its own module or an Apple .p8 pasted on one .env line.
 * A literal-prefixed alternation plus one greedy class: linear, no nesting.
 */
const PRIVATE_KEY_DER_B64 =
  /(?:MII[A-Za-z0-9+\/]{2}[AQgw]IBA[AD]|MI[E-H][A-Za-z0-9+\/]AgE[AB]|M[A-P][A-Za-z0-9+\/]CAQ(?:EE|AwBQYDK2V)|b3BlbnNzaC1rZXktdjE)[A-Za-z0-9+\/]{45,}/g;

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
    //
    // 2026-10-14 out-of-band release (the fixes postponed from 09-30): two
    // CRITICAL unauthenticated RCEs (GHSA-2464-fhr4-w9xw / CVE-2026-96889 SVG
    // Image Optimization via upstream sharp/librsvg; GHSA-673q-mjm6-r5xr
    // `use cache` returning typed arrays) and one HIGH DoS (GHSA-p3m5-59mp-jv5r,
    // Server Actions), patched in 16.4.1 (Active LTS) / 15.5.28 (Maintenance
    // LTS). There is NO patched 16.3.x — Active LTS moved 16.3 -> 16.4 and every
    // 16.x <= 16.4.0 is in range — so the 16 floor jumps 16.3.8 -> 16.4.1 and the
    // whole 16.3 line (incl. the old 16.3.8 floor) fires. 15.x IS affected
    // (GHSA-2464 lists >=10.0.0 <=15.5.27, GHSA-p3m5 >=13.0.0 <=15.5.27), so the
    // 15 floor moves 15.5.27 -> 15.5.28. This time the repo GHSA ranges are
    // concrete (no placeholders) and match the release post. 16.4.2 (2026-10-15)
    // is a bugfix-only follow-up; the patched floor is 16.4.1.
    fixedByMajor: { 15: [15, 5, 28], 16: [16, 4, 1] },
    advisory:
      "October 2026 out-of-band security release (2026-10-14), the fixes Vercel postponed from September: two CRITICAL unauthenticated RCEs — in the Image Optimization API when SVG files are used, via a memory bug in an upstream library (sharp/librsvg) on glibc-based Linux (CVE-2026-96889 / GHSA-2464-fhr4-w9xw; affects >=10.0.0 <=15.5.27 and 16.x <=16.4.0; workaround: make sure Next.js uses sharp 0.35.5+), and in `use cache` functions returning multiple typed arrays with Cache Components (GHSA-673q-mjm6-r5xr; 16.x <=16.4.0; no workaround) — plus a HIGH denial of service in App Router apps with at least one Server Action (GHSA-p3m5-59mp-jv5r; >=13.0.0 <=15.5.27 and 16.x <=16.4.0). There is no patched 16.3.x: patch to 16.4.1+ (16.x) or 15.5.28+ (15.x); 14.x and older have no fix branch. This is on top of the 2026-09-30 September release (HIGH Image Optimization SSRF CVE-2026-94483 plus medium/low issues CVE-2026-94484, -94485, -94486, -94543, -94544), the 2026-09-22 CRITICAL next/og RCE (CVE-2026-94545), the August 2026 critical unauthenticated RCEs (GHSA-2xp9-vwfh-vxw4, CVE-2026-75604), the July 2026 set (CVE-2026-64641 through CVE-2026-64649) and the earlier CVE-2025-29927 middleware bypass.",
  },
  {
    // The upstream package behind CVE-2026-96889. Next.js 16.4.1+ / 15.5.28+
    // make package managers pull a fixed sharp themselves (covered by the `next`
    // floor above), so this entry is for apps that depend on sharp DIRECTLY.
    // Floor 0.35.5 = GHSA-wq5f-xc86-pv6w (librsvg, affected < 0.35.5), which
    // subsumes GHSA-rgj7-g3m4-5g8c (libheif, < 0.35.4) and GHSA-f88m-g3jw-g9cj
    // (libvips, < 0.35.0).
    name: "sharp",
    fixedBelow: [0, 35, 5],
    advisory:
      "CVE-2026-96889 / GHSA-wq5f-xc86-pv6w (High, CVSS 8.9): a use-after-free in the bundled librsvg can lead to possible remote code execution on glibc-based Linux; downstream this became a critical unauthenticated RCE in the Next.js Image Optimization API for SVG files. Affects < 0.35.5 — upgrade to 0.35.5 (ships librsvg 2.63.2). Older versions also carry GHSA-rgj7-g3m4-5g8c (libheif heap overflow, fixed in 0.35.4) and GHSA-f88m-g3jw-g9cj (libvips CVE-2026-33327, -33328, -35590, -35591, fixed in 0.35.0). Workaround if you cannot upgrade yet: stop sharp decoding SVG with sharp.block({ operation: [\"VipsForeignLoadSvg\"] }).",
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

/** Directory names that hold test / fixture / eval-harness projects. A
 *  package.json nested under one is a throwaway manifest that is never
 *  installed into a deployed app. Deliberately differs from isTestPath():
 *  - no bare `mocks?` (a monorepo can ship a real app at apps/mock, e.g. a
 *    mock-exam product); `__mocks__` stays because it is unambiguous;
 *  - adds `selftests?` (eval self-test trees such as
 *    evals/<gate>/selftest/fail/tree/).
 *  Anchored alternation, no nested quantifiers, tested once per path segment,
 *  so it is ReDoS-safe. */
const DEP_FIXTURE_DIR =
  /^(?:__tests__|__mocks__|__fixtures__|tests?|e2e|cypress|fixtures?|testdata|selftests?)$/i;

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

// ── general/assigned-secret-literal — measured FP shapes (55 repos) ─────────
// Each exemption below removed a real false positive and is narrowed so the
// real findings on the same corpus (a hardcoded API-key UUID, a default admin
// TOTP secret used as a fallback, an owner password in a createUser script)
// keep firing. Every pattern is anchored or linear with bounded counts.

/**
 * Deno names its test files foo_test.ts, but `_test.ts` is also an ordinary
 * production name (ab_test.ts, smoke_test.mjs). So the underscore form only
 * counts as a test when the file also loads a test runner: Deno.test(), the
 * Deno std assert/testing/expect modules (jsr:@std/… or deno.land/std@…), or
 * node:test / vitest / @jest/globals. A production module or a plain script
 * that happens to end in _test stays scanned.
 */
const DENO_TEST_PATH = /_test\.[cm]?[jt]sx?$/i;
const TEST_RUNNER_MARKER =
  /\bDeno\.test\s*\(|@std\/(?:assert|testing|expect)\b|deno\.land\/std@[^\s"'\/]{1,20}\/(?:assert|testing|expect)\/|from\s*["'](?:node:test|vitest|@jest\/globals)["']/;

/**
 * A comment line (JSDoc `*`, `/*` or `//`) whose backtick code span names a
 * code identifier: "never includes the secret: `ProviderSecretRejected`",
 * "Read the token: `useSessionToken()`". CODE_REF allows no digits and only an
 * optional trailing (), and the caller also requires a lowercase letter, so a
 * credential documented in a code span (`AcmeShopAdmin2024!`, an all-caps
 * base32 `JBSWYTPEHPKKZXPQ`) still fires, as does any "…" or '…' literal on a
 * commented-out line.
 */
const COMMENT_LINE = /^\s*(?:\*|\/\*|\/\/)/;
const CODE_REF = /^[A-Za-z_$][A-Za-z_$.]*(?:\(\))?$/;

/**
 * A public EVM contract address (0x + 40 hex) under a token-named key, e.g. a
 * chain config's `token: "0x…"` (the ERC-20 contract). Only a *token* name and
 * only the exact address length: 0x+40 hex under secret/apiKey/password, and a
 * 0x+64-hex private key under any name, still fire.
 */
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * A local/preview password that declares itself dev-only TWICE: in the
 * identifier (LOCAL_PASSWORD, PREVIEW_PASSWORD, devPassword, E2E_PASSWORD) and
 * in the value ("localpassword42", "testpassword2024"). A bare `password:` key
 * never qualifies (a dev-looking value can still create a production admin),
 * nor does a privileged identifier (DEFAULT_ADMIN_PASSWORD), nor any file that
 * authenticates requests (see authSurface in the rule).
 */
const DEV_PASSWORD_ID = /(?:pass(?:word)?|passwd|pwd)$/i;
const DEV_SCOPE_WORDS = new Set(["dev", "local", "test", "demo", "seed", "e2e", "preview"]);
const DEV_PASSWORD_VALUE =
  /^(?:dev|local|test|demo|seed|e2e)[-_.]?pass(?:word)?[-_.]?[0-9]{0,6}[!@#$%^&*._-]{0,3}$/i;
const PRIVILEGED_ID =
  /default|fallback|admin|root|master|prod|live|staging|owner|super|service/i;

/** Does the identifier itself carry a dev scope word (devPassword → dev)? */
function hasDevScopeWord(id: string): boolean {
  return id
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[_-]+/)
    .some((w) => DEV_SCOPE_WORDS.has(w));
}

/**
 * Every identifier the file uses as a `||` / `??` fallback or as an `==`,
 * `===`, `!=` or `!==` operand. `gateOperands(content).has(id)` gives the same
 * answer as testing the content against the per-identifier regex
 *   (?:\|\||\?\?|[=!]==?)\s*ID\b|\bID\s*[=!]==?
 * (ID is [A-Za-z0-9_]+, so each side of it is a whole word token), but
 * collected in two linear passes once per file instead of one full-content
 * scan per matching line: a file with thousands of dev-password lines took
 * ~1.5 s per 200 KB the per-line way. The lookbehind starts the left-operand
 * match only at a token start, so a long word run is never rescanned.
 */
function gateOperands(content: string): Set<string> {
  const out = new Set<string>();
  const right = /(?:\|\||\?\?|[=!]==?)\s*([A-Za-z0-9_]+)/g;
  const left = /(?<![A-Za-z0-9_])([A-Za-z0-9_]+)\s*[=!]=/g;
  for (const rx of [right, left]) {
    rx.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rx.exec(content)) !== null) out.add(m[1]);
  }
  return out;
}

/**
 * Doubly self-declared dev password (see DEV_PASSWORD_VALUE). The checks run
 * cheapest first; the whole-file operand scan (gateOperands) runs last, and
 * only when every other condition holds. It keeps the finding when the dev
 * password is used anywhere in the file as a `||` / `??` fallback or an
 * `===` / `!==` operand, i.e. when it can still unlock something.
 */
function isSelfDeclaredDevPassword(
  id: string,
  value: string,
  authSurface: boolean,
  usedAsGate: (id: string) => boolean
): boolean {
  if (!DEV_PASSWORD_ID.test(id)) return false;
  if (!hasDevScopeWord(id)) return false;
  if (!DEV_PASSWORD_VALUE.test(value)) return false;
  if (PRIVILEGED_ID.test(id)) return false;
  if (authSurface) return false;
  return !usedAsGate(id);
}

// ── general/sql-injection — which files and which matches count ───────────
//
// Measured on 55 real repos (20,802 JS/TS files), most of this rule's findings
// were in code that never ships (test suites, Playwright specs, seed and
// one-off CLI scripts run against a throwaway local DB), postgres.js tagged
// templates the old lookbehind did not recognise as tags, error-message prose
// that reads like DELETE FROM, and read-only Google Ads (GAQL) queries.

/** Directory names that hold test, fixture or mock code. */
const NON_DEPLOYED_DIRS = new Set([
  "__tests__",
  "__mocks__",
  "__fixtures__",
  "e2e",
  "cypress",
  "playwright",
  "testdata",
  "test",
  "tests",
  "fixture",
  "fixtures",
  "mock",
  "mocks",
]);

// A test or scripts dir BELOW one of these is deployed code that happens to use
// the name (app/api/test/, src/app/api/scripts/, supabase/functions/test/,
// src/tests/tests.service.ts, lib/tests/). That is why this rule does not use
// isTestPath, which matches the directory name anywhere in the path.
const DEPLOYED_ANCESTORS = new Set([
  "src",
  "app",
  "pages",
  "api",
  "functions",
  "routes",
  "actions",
  "lib",
  "server",
  "services",
  "middleware",
  "controllers",
  "handlers",
  "modules",
]);

// Real runtime exports. An empty `export {}` (TypeScript module marker) and
// type-only exports do not count. Line-anchored, no nested repetition: one
// linear pass per file.
const HAS_MODULE_EXPORT =
  /^[ \t]*export[ \t]*(?:\{[ \t]*[A-Za-z_$]|\*)|^[ \t]*export[ \t]+(?:default|async|function|const|let|var|class|abstract|enum)\b|\bmodule\.exports\b|^[ \t]*exports\.[A-Za-z_$]/m;

/** Is this file test, fixture, mock or CLI-script code that never deploys? */
function isNonDeployedSqlFile(f: ScanFile): boolean {
  const segs = f.path.toLowerCase().replace(/\\/g, "/").split("/");
  const file = segs[segs.length - 1];
  const dirs = segs.slice(0, -1);
  // (a) Test file by name. Not under pages/: the Pages Router routes every file there.
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(file) && !dirs.includes("pages")) return true;
  // (b) A Server Action is deployed wherever it lives.
  if (hasUseServer(f.content)) return false;
  // (c) A test, fixture, mock or scripts directory that sits outside every source or routing tree.
  const firstDeployed = dirs.findIndex((d) => DEPLOYED_ANCESTORS.has(d));
  for (let i = 0; i < dirs.length; i++) {
    const d = dirs[i];
    if (d !== "scripts" && !NON_DEPLOYED_DIRS.has(d)) continue;
    if (firstDeployed !== -1 && firstDeployed < i) continue;
    if (d === "scripts" && HAS_MODULE_EXPORT.test(f.content)) continue; // deployed code may import a scripts/ module that exports runtime code
    return true;
  }
  return false;
}

// Template literal that contains a DML statement AND an interpolation. Every
// run is bounded and newline-excluded => ReDoS-safe. Requiring a real statement
// shape — SELECT…FROM, INSERT INTO, UPDATE…SET, DELETE FROM — and not a bare
// keyword stops ordinary prose ("An update about …", "select an option") from
// matching.
// The two fixed-width lookbehinds exclude TAGGED templates, which are
// parameterised and safe: an identifier or member tag (sql`…`, db.sql`…`), a
// non-null assertion (db!`…`), a call result (sql()`…`), an index (x[0]`…`),
// and a generic type argument (sql<Row[]>`…`, also when the SQL starts on the
// next line). `=>` (an arrow returning a plain template) and a spaced `a > `
// comparison are not tags and still match.
const SQL_TEMPLATE =
  /(?<![A-Za-z0-9_$.!)\]])(?<![^=\s]>)`\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^`\n]{1,200}\bFROM\b[^`\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^`\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^`\n]{0,250}\$\{[^}\n]{1,150}\}[^`\n]{0,150}`/gi;
// Concatenation: "<sql shape>" + variable
const SQL_CONCAT =
  /["']\s*(?:SELECT\s+\*\s+FROM\b|SELECT\b[^"'\n]{1,200}\bFROM\b[^"'\n]{0,200}\b(?:WHERE|JOIN|GROUP|ORDER|LIMIT|HAVING|UNION)\b|INSERT\s+INTO\b|UPDATE\b[^"'\n]{1,150}\bSET\b|DELETE\s+FROM\b)[^"'\n]{0,200}["']\s*\+\s*[A-Za-z_$]/gi;

// One ${…} interpolation. Used only with String.replace, so the match text can
// be judged on its literal SQL and never on the JavaScript inside ${…}.
const INTERP = /\$\{[^}\n]{0,150}\}/g;

/**
 * Is this match a sentence rather than a query? Both must hold: the verb is
 * Title-case and its companion keyword lowercase (the regex has NO i flag), and
 * no SQL operator appears outside the interpolations. `Delete from Drive
 * failed: ${text}` is skipped; `Select * from users where email = '${e}'`,
 * `Delete From ${table}` and all UPPER or lower case SQL still fire.
 */
function isProse(m0: string): boolean {
  if (
    !/^[`"']\s*(?:Select\b[^`"'\n]{0,200}\bfrom\b|Insert\s+into\b|Update\b[^`"'\n]{0,150}\bset\b|Delete\s+from\b)/.test(
      m0
    )
  ) {
    return false;
  }
  return !/[=*(<>;]/.test(m0.replace(INTERP, " "));
}

// Google Ads Query Language is read-only and runs against the Google Ads API,
// not the app's database, so it cannot inject into it. Only files that talk to
// Google Ads are considered, and only SELECTs whose literal text names a GAQL
// resource AND a GAQL field. SELECT *, JOIN, UNION and `;` do not exist in GAQL,
// so any of them means real SQL.
const GADS_FILE = /\bgaql|googleads\.googleapis\.com|["']google-ads-api["']|googleAds:search/i;
const NOT_GAQL = /\bSELECT\s{0,20}\*|\bJOIN\b|\bUNION\b|;/i;
const GAQL_FROM =
  /\b[Ff][Rr][Oo][Mm]\s{1,20}(?:customer|customer_client|campaign|campaign_budget|campaign_criterion|ad_group|ad_group_ad|ad_group_asset|ad_group_criterion|asset|asset_group|asset_group_asset|conversion_action|geo_target_constant|bidding_strategy|change_event|label|[a-z_]{1,40}_view)\b/;
const GAQL_FIELD =
  /\b(?:metrics|segments|customer|campaign|campaign_budget|campaign_criterion|ad_group|ad_group_ad|ad_group_criterion|asset_group|conversion_action|geo_target_constant|bidding_strategy|[a-z_]{1,40}_view)\.[a-z_]{2,60}\b|\bDURING\s{1,20}[A-Z0-9_]{4,30}\b/;

function isGaql(m0: string, isAdsFile: boolean): boolean {
  if (!isAdsFile) return false;
  if (!/^[`"']\s*SELECT\b/i.test(m0)) return false; // INSERT, UPDATE and DELETE are never GAQL
  // Judge only the literal text: ${row.campaign.name} is a JS path, not GAQL.
  const t = m0.replace(INTERP, " ");
  return !NOT_GAQL.test(t) && GAQL_FROM.test(t) && GAQL_FIELD.test(t);
}

// ── general/dangerous-inner-html — values that provably carry no user input ─
//
// On 55 real repos most of this rule's findings were values that cannot carry
// attacker input: string literals (theme pre-paint scripts, inline CSS), module
// constants built only from other literals, constants imported from another
// module, the stock shadcn/ui ChartStyle, and HTML that a vetted sanitiser
// (DOMPurify, sanitize-html, xss) or escaping renderer (KaTeX, Shiki) produced.
// Each shape is accepted only in a form one file can PROVE; anything else (a
// concatenation, a .replace() after the sanitiser, a prop, state, a
// reassignment) still flags. A silenced XSS is worse than a noisy finding.
// Literal and paren scanning are hand-written loops with hard caps, and every
// regex is bounded or linear, so a hostile file cannot stall the scan.

// Static ES imports. The clause excludes quotes so a side-effect import
// (`import "./x.css"`) cannot swallow the next statement; `import type` binds
// nothing at runtime.
const IMPORT_STMT =
  /^import\s(?!\s*type\s)([^;'"`]{1,600}?)\sfrom\s*["']([^"'\n]{1,200})["'];?/gm;
const DOMPURIFY_SRC = /^(?:dompurify|isomorphic-dompurify)$/;
const BARE_SANITIZER_SRC = /^(?:sanitize-html|xss|dompurify|isomorphic-dompurify)$/;
const KATEX_IMPORT = /(?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*)["']katex["']/;
const SHIKI_IMPORT =
  /(?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*)["'](?:shiki|@shikijs\/[\w-]{1,40})["']/;
// A sanitiser configured to let scripts, event handlers or javascript: URLs
// through is no longer a sanitiser, and KaTeX with `trust` renders \href and
// \htmlData. Any of these anywhere in the file voids every sanitiser exemption
// in it. Benign options (ADD_ATTR: ['target'], ALLOWED_TAGS: ['mark']) do not.
const WEAK_SANITIZER_CONFIG =
  /\b(?:ALLOW_UNKNOWN_PROTOCOLS|ALLOWED_URI_REGEXP|CUSTOM_ELEMENT_HANDLING|allowVulnerableTags|addHook)\b|\b(?:allowedTags|allowedAttributes)\s*:\s*false\b|\btrust\s*:\s*(?!false\b)|\b(?:ADD_TAGS|ADD_ATTR|ALLOWED_TAGS|ALLOWED_ATTR|allowedTags|allowedAttributes|allowedSchemes|allowedSchemesByTag|whiteList)\b[^;]{0,300}?["'](?:script|javascript|srcdoc|on[a-z]{3,20})["']/;
// A static inline script is unsafe only when it reads a DOM XSS source AND
// writes to a DOM sink (location.hash into innerHTML, a postMessage handler
// into document.write). The literal itself is author-written.
const DOM_XSS_SOURCE =
  /\blocation\b|document\.(?:referrer|URL|documentURI|baseURI|cookie)\b|window\.name\b|URLSearchParams|["']message["']/;
const DOM_XSS_SINK =
  /\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc)\b|document\.write|\beval\s*\(|\bnew\s+Function\b|\bsetTimeout\s*\(\s*["'`]/;
const TS_CAST = /^\s*as\s+(?:unknown\s+as\s+)?[A-Za-z_$][\w$.]{0,63}/;
const HTML_PROP_VALUE = /^dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*/;
// The stock shadcn/ui chart.tsx: THEMES maps theme names to constant CSS
// selector prefixes. A light-only THEMES is a common trim and still constant.
const SHADCN_THEMES =
  /^const\s+THEMES\s*(?::[^=\n]{1,80})?=\s*\{\s*(?:[A-Za-z_$][\w$]{0,20}\s*:\s*["'][^"'\n]{0,40}["']\s*,\s*){0,6}[A-Za-z_$][\w$]{0,20}\s*:\s*["'][^"'\n]{0,40}["']\s*,?\s*\}/m;

/** Per-file facts, built at most once per file and only when a sink needs them. */
type HtmlFileInfo = {
  content: string;
  /** Local name -> module specifier, from static imports. */
  imports: Map<string, string>;
  /** content with every import statement replaced by spaces (same indices). */
  blanked: string;
  weak: boolean;
  /** Answers that depend only on the file, so thousands of sinks pay once. */
  cache: Map<string, boolean>;
  constMemo: Map<string, boolean>;
  constBudget: number;
};

function htmlFileInfo(content: string): HtmlFileInfo {
  const imports = new Map<string, string>();
  for (const m of content.matchAll(IMPORT_STMT)) {
    const toks = m[1].split(/[\s,{}]+/).filter(Boolean);
    for (let k = 0; k < toks.length; k++) {
      const t = toks[k];
      // Syntax tokens bind nothing, and in `a as b` only b is a local name.
      if (t === "as" || t === "type" || t === "*" || toks[k + 1] === "as") continue;
      imports.set(t, m[2]);
    }
  }
  return {
    content,
    imports,
    blanked: content.replace(IMPORT_STMT, (x) => " ".repeat(x.length)),
    weak: WEAK_SANITIZER_CONFIG.test(content),
    cache: new Map(),
    constMemo: new Map(),
    constBudget: 64,
  };
}

function cachedFact(info: HtmlFileInfo, key: string, compute: () => boolean): boolean {
  let v = info.cache.get(key);
  if (v === undefined) {
    v = compute();
    info.cache.set(key, v);
  }
  return v;
}

/** Identifiers can contain `$`, the only regex metacharacter they allow. */
const escapeName = (name: string) => name.replace(/\$/g, "\\$");

/**
 * Is `name` (re)bound anywhere in `text`: a declaration (for-of included), a
 * destructured prop or parameter (with a default or a rename like `{ a: name }`),
 * or a bare arrow parameter. Uses as a call argument, array element or object
 * value also match. That is deliberately conservative: the finding stays.
 */
function isBound(text: string, name: string): boolean {
  const n = escapeName(name);
  const t = text.replace(new RegExp("__html\\s*:\\s*" + n + "\\b|\\$\\{\\s*" + n + "\\s*\\}", "g"), "");
  return new RegExp(
    "\\b(?:const|let|var|function|class)\\s+" + n + "\\b" +
      "|[{,(\\[]\\s*(?:\\.\\.\\.\\s*)?" + n + "\\s*[,}=)\\]:]" +
      "|:\\s*" + n + "\\s*[,}=]" +
      "|(?<![.\\w$])" + n + "\\s*=>"
  ).test(t);
}

/** isBound over the whole file minus its import statements, cached per name. */
function boundInFile(info: HtmlFileInfo, name: string): boolean {
  return cachedFact(info, "bound|" + name, () => isBound(info.blanked, name));
}

type StringLiteral = { end: number; interps: string[]; text: string };

/**
 * Parse the string or template literal opening at s[i]. A newline ends a quoted
 * string (so it fails); each `${…}` must close within 200 chars and is recorded
 * as trimmed text. Returns null on anything else or past the cap.
 */
function parseLiteral(s: string, i: number, cap = 20000): StringLiteral | null {
  const q = s[i];
  if (q !== '"' && q !== "'" && q !== "`") return null;
  const interps: string[] = [];
  const limit = Math.min(s.length, i + cap);
  for (let j = i + 1; j < limit; j++) {
    const c = s[j];
    if (c === "\\") {
      j++;
      continue;
    }
    if (q !== "`" && c === "\n") return null;
    if (q === "`" && c === "$" && s[j + 1] === "{") {
      const stop = Math.min(s.length, j + 201);
      let close = -1;
      for (let k = j + 2; k < stop; k++) {
        if (s[k] === "}") {
          close = k;
          break;
        }
      }
      if (close === -1) return null;
      interps.push(s.slice(j + 2, close).trim());
      j = close;
      continue;
    }
    if (c === q) return { end: j + 1, interps, text: s.slice(i + 1, j) };
  }
  return null;
}

/**
 * s[i] must be '('. Returns the index just after its matching ')', or -1. Skips
 * '…' and "…" strings and template text (a `${` re-enters code). ANY '/' in code
 * gives up: a regex, a division and a comment cannot be told apart here, and
 * giving up keeps the finding.
 */
function scanBalanced(s: string, i: number, cap = 3000): number {
  if (s[i] !== "(") return -1;
  const limit = Math.min(s.length, i + cap);
  // "T" marks template-literal text; every other entry is the closer expected.
  const stack: string[] = [")"];
  let j = i + 1;
  while (j < limit) {
    const c = s[j];
    if (stack[stack.length - 1] === "T") {
      if (c === "\\") j += 2;
      else if (c === "`") {
        stack.pop();
        j++;
      } else if (c === "$" && s[j + 1] === "{") {
        stack.push("}");
        j += 2;
      } else j++;
      continue;
    }
    if (c === '"' || c === "'") {
      let k = j + 1;
      while (k < limit && s[k] !== c) {
        if (s[k] === "\\") k++;
        else if (s[k] === "\n") return -1;
        k++;
      }
      if (k >= limit) return -1;
      j = k + 1;
      continue;
    }
    if (c === "`") stack.push("T");
    else if (c === "/") return -1;
    else if (c === "(") stack.push(")");
    else if (c === "[") stack.push("]");
    else if (c === "{") stack.push("}");
    else if (c === ")" || c === "]" || c === "}") {
      if (stack.pop() !== c) return -1;
      if (stack.length === 0) return j + 1;
    }
    j++;
  }
  return -1;
}

/** Skip an optional TypeScript cast (`as string`, `as unknown as Html`). */
function skipCast(s: string, k: number): number {
  const m = TS_CAST.exec(s.slice(k, k + 120));
  return m ? k + m[0].length : k;
}

/** The expression ending at k is the WHOLE value of an object-literal property. */
function endsInValueSlot(s: string, k: number): boolean {
  k = skipCast(s, k);
  while (k < s.length && /\s/.test(s[k])) k++;
  return s[k] === "," || s[k] === "}";
}

/**
 * The expression ending at k is the WHOLE initializer of its statement. A
 * continuation (`+ x`, `.replace(…)`, `|| raw`, `? :`) returns false, which
 * keeps the finding; so does one on the next line.
 */
function endsStatement(s: string, k: number): boolean {
  k = skipCast(s, k);
  while (k < s.length && (s[k] === " " || s[k] === "\t")) k++;
  if (k >= s.length || s[k] === ";" || s[k] === "}") return true;
  if (s[k] !== "\n" && s[k] !== "\r") return false;
  while (k < s.length && /\s/.test(s[k])) k++;
  if (k >= s.length) return true;
  const c = s[k];
  if (c === "}") return true;
  if (c === "/" && (s[k + 1] === "/" || s[k + 1] === "*")) return true;
  return /[A-Za-z_$]/.test(c);
}

function isStaticOk(text: string): boolean {
  return !(DOM_XSS_SOURCE.test(text) && DOM_XSS_SINK.test(text));
}

/**
 * Is a vetted sanitiser or escaping renderer called at content[i]? Returns the
 * index just after the call's ')', or -1. Only names this file binds to the
 * library count, so a homegrown `sanitize()` regex never does.
 */
function sanitizerCallEnd(info: HtmlFileInfo, i: number, noHelper = false): number {
  if (info.weak) return -1;
  const { content } = info;
  const head = content.slice(i, i + 160);
  let m: RegExpExecArray | null;
  let ok = false;
  if ((m = /^(?:await\s+)?([A-Za-z_$][\w$]{0,63})\s*\.\s*sanitize\s*(?=\()/.exec(head))) {
    // DOMPurify.sanitize(...): the object must BE DOMPurify (imported or
    // required) and never rebound to something else in the file.
    const obj = m[1];
    ok = cachedFact(info, "dompurify|" + obj, () => {
      const req = new RegExp(
        "\\b(?:const|let|var)\\s+" + escapeName(obj) +
          "\\s*=\\s*require\\(\\s*[\"'](?:isomorphic-)?dompurify[\"']",
        "g"
      );
      const src = info.imports.get(obj);
      if (!(src !== undefined && DOMPURIFY_SRC.test(src)) && !req.test(content)) return false;
      req.lastIndex = 0;
      return !isBound(info.blanked.replace(req, ""), obj);
    });
  } else if ((m = /^(?:await\s+)?katex\s*\.\s*renderToString\s*(?=\()/.exec(head))) {
    // KaTeX escapes its input; `trust` (which re-opens raw HTML) is in WEAK.
    ok = cachedFact(info, "katex", () => KATEX_IMPORT.test(content));
  } else if ((m = /^(?:await\s+)?([A-Za-z_$][\w$]{0,63})\s*(?=\()/.exec(head))) {
    const fn = m[1];
    const src = info.imports.get(fn);
    if (fn === "codeToHtml") {
      // Shiki escapes the code it highlights.
      ok = cachedFact(info, "shiki", () => SHIKI_IMPORT.test(content)) && !boundInFile(info, fn);
    } else if (src !== undefined && BARE_SANITIZER_SRC.test(src)) {
      // sanitizeHtml(), xss(), filterXSS(), a named `sanitize` import. A bare
      // DOMPurify(...) call is the factory, not a sanitiser.
      ok = fn !== "DOMPurify" && !boundInFile(info, fn);
    } else if (!noHelper && /^(?:sanitize|sanitizeHtml|sanitizeHTML)$/.test(fn)) {
      ok = cachedFact(info, "helper|" + fn, () => isSanitizerHelper(info, fn));
    }
  }
  if (!ok || !m) return -1;
  return scanBalanced(content, i + m[0].length);
}

/**
 * A local `sanitize` helper counts only when its whole body is one vetted
 * sanitiser call: `const sanitize = (s) => DOMPurify.sanitize(s, …)` or
 * `function sanitize(s) { return DOMPurify.sanitize(s); }`. A regex replace or
 * a concatenation does not, even when a sanitiser library is imported.
 */
function isSanitizerHelper(info: HtmlFileInfo, fn: string): boolean {
  const { content } = info;
  const f = escapeName(fn);
  const defs = [
    ...content.matchAll(
      new RegExp(
        "\\b(?:(?:const|let|var)\\s+" + f + "\\s*=\\s*(?:async\\s*)?(?=\\()|function\\s+" + f + "\\s*(?=\\())",
        "g"
      )
    ),
  ];
  const binds = content.match(new RegExp("\\b(?:const|let|var|function)\\s+" + f + "\\b", "g")) ?? [];
  if (defs.length !== 1 || binds.length !== 1) return false;
  const def = defs[0];
  const close = scanBalanced(content, (def.index ?? 0) + def[0].length, 400);
  if (close === -1) return false;
  const rest = content.slice(close, close + 200);
  const lead = def[0].startsWith("function")
    ? /^\s*(?::\s*[\w$<>\[\]| .]{1,60}?)?\s*\{\s*return\s+/.exec(rest)
    : /^\s*(?::\s*[\w$<>\[\]| .]{1,60}?)?\s*=>\s*/.exec(rest);
  if (!lead) return false;
  const end = sanitizerCallEnd(info, close + lead[0].length, true);
  return end !== -1 && endsStatement(content, end);
}

/**
 * Is `name` a column-0 `const` whose initializer is a number, boolean or static
 * literal, with every `${…}` itself such a constant in this file? A
 * SCREAMING_CASE name alone proves nothing. Memoised, depth <= 3, cycles fail,
 * and at most 64 resolutions per file.
 */
function isLiteralConst(info: HtmlFileInfo, name: string, depth: number, seen: Set<string>): boolean {
  if (depth > 3 || seen.has(name)) return false;
  const key = name + (depth === 0 ? "|sink" : "|interp");
  const hit = info.constMemo.get(key);
  if (hit !== undefined) return hit;
  if (--info.constBudget < 0) return false;
  seen.add(name);
  const r = literalConstUncached(info, name, depth, seen);
  info.constMemo.set(key, r);
  return r;
}

function literalConstUncached(info: HtmlFileInfo, name: string, depth: number, seen: Set<string>): boolean {
  const { content } = info;
  const n = escapeName(name);
  const decls = [
    ...content.matchAll(new RegExp("^(?:export\\s+)?const\\s+" + n + "\\s*(?::\\s*string\\s*)?=\\s*", "gm")),
  ];
  if (decls.length !== 1) return false;
  // Keep the group: `\bconst|let|var\s+X\b` would match every `const` in the file.
  const all = content.match(new RegExp("\\b(?:const|let|var)\\s+" + n + "\\b", "g")) ?? [];
  if (all.length !== 1) return false;
  const declAt = decls[0].index ?? 0;
  const start = declAt + decls[0][0].length;
  if (depth === 0) {
    // The identifier read at the sink: no parameter, prop or local may shadow it.
    const without =
      info.blanked.slice(0, declAt) + " ".repeat(decls[0][0].length) + info.blanked.slice(start);
    if (isBound(without, name)) return false;
  } else if (new RegExp("\\b(?:function|class)\\s+" + n + "\\b").test(content)) {
    // An interpolation inside a column-0 initializer is evaluated in module
    // scope, where the single const is the binding unless a hoisted
    // declaration of the same name exists.
    return false;
  }
  let end: number;
  const scalar = /^(?:-?\d[\d_.]{0,40}|true|false)\b/.exec(content.slice(start, start + 50));
  if (scalar) {
    end = start + scalar[0].length;
  } else {
    const lit = parseLiteral(content, start);
    if (!lit || !isStaticOk(lit.text)) return false;
    for (const x of new Set(lit.interps)) {
      if (!/^[A-Za-z_$][\w$]{0,63}$/.test(x)) return false;
      if (!isLiteralConst(info, x, depth + 1, new Set(seen))) return false;
    }
    end = lit.end;
  }
  // The literal must be the whole initializer: `"a" + userValue` is not constant.
  let k = end;
  const asConst = /^\s*as\s+const\b/.exec(content.slice(k, k + 20));
  if (asConst) k += asConst[0].length;
  while (k < content.length && (content[k] === " " || content[k] === "\t")) k++;
  return k >= content.length || content[k] === ";" || content[k] === "\n" || content[k] === "\r";
}

/** The exact shadcn/ui ChartStyle value: THEMES -> CSS rules keyed by [data-chart=id]. */
function isShadcnChartStyle(info: HtmlFileInfo, v: number): boolean {
  const { content } = info;
  const m = /^Object\.entries\(\s*THEMES\s*\)/.exec(content.slice(v, v + 40));
  if (!m) return false;
  if (!cachedFact(info, "themes", () => SHADCN_THEMES.test(content))) return false;
  let k = v + m[0].length;
  const chain: { kind: string; open: number; close: number }[] = [];
  for (let step = 0; step < 4; step++) {
    let p = k;
    while (p < content.length && /\s/.test(content[p])) p++;
    const cm = /^\.\s*(map|join)\s*(?=\()/.exec(content.slice(p, p + 20));
    if (!cm) break;
    const open = p + cm[0].length;
    const close = scanBalanced(content, open, 2500);
    if (close === -1) return false;
    chain.push({ kind: cm[1], open, close });
    k = close;
  }
  if (chain.length !== 2 || chain[0].kind !== "map" || chain[1].kind !== "join") return false;
  if (!/^\(\s*(["'])\\n\1\s*\)$/.test(content.slice(chain[1].open, chain[1].close))) return false;
  if (!content.slice(chain[0].open, chain[0].close).includes("[data-chart=")) return false;
  return endsInValueSlot(content, k);
}

/**
 * d3: `name` is a local whose LAST declaration before the sink, in the same
 * function, is initialised with a vetted sanitiser call and nothing else, and
 * nothing writes to or rebinds it between that declaration and the sink.
 */
function isSanitizedLocal(info: HtmlFileInfo, name: string, idx: number): boolean {
  const { content } = info;
  const n = escapeName(name);
  const ws = Math.max(0, idx - 4000);
  const win = content.slice(ws, idx);
  // Only a declaration WITH an initializer counts. A bare reassignment or a
  // property write (`cache.html = …`) does not.
  const declRe = new RegExp(
    "(?<![\\w$.])(?:const|let|var)\\s+" + n + "\\s*(?::[^=;\\n]{1,80})?=(?![=>])\\s*",
    "g"
  );
  let last: RegExpExecArray | null = null;
  for (let mm = declRe.exec(win); mm !== null; mm = declRe.exec(win)) last = mm;
  if (!last) return false;
  const declAt = ws + last.index;
  // A column-0 line in between means the sink is in another function (a
  // sibling component), where `name` is some other binding.
  if (/\n\S/.test(content.slice(declAt, idx))) return false;
  const end = sanitizerCallEnd(info, declAt + last[0].length);
  if (end === -1 || !endsStatement(content, end)) return false;
  const after = content.slice(end, idx).replace(new RegExp("__html\\s*:\\s*" + n + "\\b", "g"), "");
  if (
    new RegExp(
      "(?<![.\\w$])" + n + "\\s*(?:=(?![=>])|(?:\\+|-|\\*\\*?|\\/|%|<<|>>>?|&&?|\\|\\|?|\\^|\\?\\?)=|\\+\\+|--)"
    ).test(after)
  ) {
    return false;
  }
  if (new RegExp("(?:\\+\\+|--)\\s*" + n + "\\b").test(after)) return false;
  return !isBound(after, name);
}

/** The `__html` value starting at v is one of the provably safe shapes. */
function isProvablySafeHtml(info: HtmlFileInfo, v: number, idx: number): boolean {
  const { content } = info;
  // (a) A static string or template literal with no interpolation.
  const lit = parseLiteral(content, v);
  if (lit && lit.interps.length === 0 && endsInValueSlot(content, lit.end) && isStaticOk(lit.text)) {
    return true;
  }
  // (b) The stock shadcn/ui ChartStyle.
  if (isShadcnChartStyle(info, v)) return true;
  // (c) A vetted sanitiser call is the whole value.
  const ce = sanitizerCallEnd(info, v);
  if (ce !== -1 && endsInValueSlot(content, ce)) return true;
  // (d) A bare identifier.
  const id = /^([A-Za-z_$][\w$]{0,63})\s*[,}]/.exec(content.slice(v, v + 200));
  if (!id) return false;
  const name = id[1];
  // d1: imported (a module constant elsewhere) and never shadowed here.
  if (info.imports.has(name) && !boundInFile(info, name)) return true;
  // d2: a module-level literal constant.
  if (isLiteralConst(info, name, 0, new Set())) return true;
  // d3: a local initialised from a sanitiser call.
  return isSanitizedLocal(info, name, idx);
}

function ldJsonTypeInOpenTag(s: string): boolean {
  const ld = s.lastIndexOf("application/ld+json");
  return ld !== -1 && !s.slice(ld).includes(">");
}

/**
 * JSON-LD structured data (<script type="application/ld+json"
 * dangerouslySetInnerHTML=...>) is serialized data, not author-written markup.
 * The ld+json type must sit in the SAME unclosed tag (no '>' between it and the
 * prop) so an unrelated sink nearby still flags, and comment text can never
 * create the exemption: a comment that merely mentions ld+json does not count,
 * and a comment between the type and the prop exempts only an escaped payload.
 */
function isJsonLdScript(content: string, idx: number): boolean {
  const rawBefore = content.slice(Math.max(0, idx - 300), idx);
  const before = rawBefore
    .replace(/\/\*[\s\S]{0,1000}?\*\//g, "")
    .replace(/(^|\n)[ \t]*\/\/[^\n]*/g, "$1");
  if (!ldJsonTypeInOpenTag(before)) return false;
  if (ldJsonTypeInOpenTag(rawBefore)) return true;
  const w = content.slice(idx, idx + 600);
  const e = w.indexOf("}}");
  return /\.replace\(\s*\/<\/g|\\u003c/.test(e === -1 ? w : w.slice(0, e));
}

// ── general/dangerous-eval — calls that cannot run attacker code ────────────
//
// On 55 real repos 19 of this rule's 20 findings could not run attacker code:
// test and build tooling, a Redis client's or an evaluator object's own
// `.eval()` method, Puppeteer's `$eval`, the word inside comments and strings,
// and arguments made only of literals. Everything here works on ONE file, lexes
// only the hit's own line, caps every loop and regex, and answers "code" (keep
// the finding) whenever it is unsure. An argument is skipped only when the
// file PROVES it is literal text. A silenced RCE is worse than a noisy one.

// Test files, and test/tool directories. The __tests__-style tool dirs count at
// any depth; plain test/, e2e/, fixtures/ ... only at the repo root or an
// apps/* or packages/* workspace root. helpers.isTestPath is deliberately NOT
// used: its unanchored tests?/ mocks?/ fixtures?/ also match product folders
// such as src/components/test/ (a coding-test feature), src/lib/mocks/ (mock
// exams) or src/components/fixtures/ (sports fixtures), whose eval() ships. A
// route (app/, pages/) or an edge function inside such a dir is deployed code.
const EVAL_TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$/;
const EVAL_TOOL_DIR_ANY = /(?:^|\/)(?:__tests__|__mocks__|__fixtures__|cypress)\//;
const EVAL_TEST_DIR_ROOT =
  /^(?:(?:apps|packages)\/[^\/]{1,100}\/)?(?:(?:src\/)?tests?|e2e|fixtures?|testdata|playwright)\//;
const EVAL_ROUTE_DIR = /(?:^|\/)(?:src\/)?(?:app|pages)\//;
// Repo-root or workspace-root build tooling only: public/scripts/ (shipped to
// the browser) and src/scripts/ (app code) keep firing.
const EVAL_ROOT_SCRIPTS = /^(?:(?:apps|packages)\/[^\/]{1,100}\/)?scripts\//;

function isEvalToolingPath(path: string): boolean {
  const p = path.toLowerCase().replace(/\\/g, "/");
  if (EVAL_TEST_FILE.test(p)) return true;
  if (
    (EVAL_TOOL_DIR_ANY.test(p) || EVAL_TEST_DIR_ROOT.test(p)) &&
    !EVAL_ROUTE_DIR.test(p) &&
    !isEdgeFunction(p)
  ) {
    return true;
  }
  return EVAL_ROOT_SCRIPTS.test(p);
}

// `x.eval(` is the GLOBAL eval only on a window-like receiver: window,
// contentWindow, popupWindow, top, parent, opener, frames[i],
// document.defaultView, globalThis, self, global, and their `?.` forms. Any
// other receiver (redis.eval, client.eval, evaluator.eval) is that object's
// own method. Tested on at most the 120 chars before the dot.
const EVAL_WIN_RECV =
  /(?:^|[^\w$])(?:[\w$]{0,60}[Ww]indow|defaultView|globalThis|self|global|top|parent|opener|win)\s{0,20}\??\s{0,20}$|(?:^|[^\w$])frames\s{0,20}\[[^\]\n]{0,60}\]\s{0,20}\??\s{0,20}$/;

function isGlobalEvalReceiver(content: string, idx: number): boolean {
  let j = idx - 1;
  for (let k = 0; j >= 0 && k < 20 && /\s/.test(content[j]); k++) j--;
  if (j < 0 || content[j] !== ".") return true; // a plain eval( call
  return EVAL_WIN_RECV.test(content.slice(Math.max(0, j - 120), j));
}

const EVAL_LINE_CAP = 20000;
// After one of these a '/' starts a regex literal, not a division. ')' and ']'
// are deliberately absent: `(a) / b` and `x[i] / y` divide.
const EVAL_REGEX_PREV = "(,=:[!&|?{};+-*%<>~^";
// A string holding eval( is skipped unless the text before it on the line
// shows the string is itself executed: an inline script (__html, .innerHTML =,
// .textContent = on a <script>, srcdoc, document.write), a Function body, a
// setTimeout/setInterval string, Puppeteer's evaluate, or node:vm.
const EVAL_CODE_SINK =
  /__html|\bnew\s{1,20}Function\s{0,20}\(|(?<![\w$.])Function\s{0,20}\(|\bset(?:Timeout|Interval)\s{0,20}\(|\.(?:textContent|innerHTML|outerHTML|innerText|text|srcdoc)\s{0,20}=(?!=)|\binsertAdjacentHTML\s{0,20}\(|\bdocument\.write(?:ln)?\s{0,20}\(|\bevaluate\s{0,20}\(|\brunIn(?:New|This)?Context\s{0,20}\(|\bScript\s{0,20}\(/;

const isAsciiLetter = (c: string | undefined) =>
  c !== undefined && ((c >= "A" && c <= "Z") || (c >= "a" && c <= "z"));
const isIdentStart = (c: string) =>
  (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "_" || c === "$";
const isIdentChar = (c: string) => isIdentStart(c) || (c >= "0" && c <= "9");

/**
 * Does `idx` sit in code, a comment, or a '…'/"…" string (answered as that
 * string's quote char)? A hand-written char loop over the CURRENT LINE only
 * (no regex runs over the line), so a hostile file cannot stall it, and a
 * whole-file comment strip can never be fooled by a `/*` glob in a string.
 * Every unsure path answers "code", which keeps the finding: an over-long
 * (minified) line, an unclosed or match-spanning regex literal, a template
 * literal, a quote that never closes on its line.
 */
function lineStateAt(content: string, idx: number): "code" | "comment" | "'" | '"' {
  const lineStart = content.lastIndexOf("\n", idx - 1) + 1;
  if (idx - lineStart > EVAL_LINE_CAP) return "code";
  let q = ""; // the open quote, "" outside strings
  let prev = ""; // last significant char outside strings, "" at line start
  for (let i = lineStart; i < idx; i++) {
    const c = content[i];
    if (q) {
      if (c === "\\") i++;
      else if (c === q) {
        q = "";
        prev = c;
      }
      continue;
    }
    if (c === "\\") {
      // Outside strings a backslash only occurs inside a regex literal.
      i++;
      prev = "a";
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") continue;
    // An apostrophe between letters is JSX text (Don't, it's), not a quote.
    if (c === "'" && isAsciiLetter(content[i - 1]) && isAsciiLetter(content[i + 1])) {
      prev = "a";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      q = c;
      continue;
    }
    if (c === "/") {
      const n = content[i + 1];
      // `https://` in JSX text (or a regex) is not a comment.
      if (n === "/" && content[i - 1] !== ":") return "comment";
      if (n === "*") {
        const rel = content.slice(i + 2, idx).indexOf("*/");
        if (rel === -1) return "comment";
        i += rel + 3; // the loop's i++ lands just past the "*/"
        continue;
      }
      if (prev === "" || EVAL_REGEX_PREV.includes(prev)) {
        // A regex literal: find its closing '/' (unescaped, outside a [...]
        // class) on this line. Missing, or at/after idx: bail out to "code".
        // This bail-out is mandatory: retrying each '/' is quadratic.
        const lim = Math.min(content.length, i + EVAL_LINE_CAP);
        let end = -1;
        let inClass = false;
        for (let j = i + 1; j < lim; j++) {
          const d = content[j];
          if (d === "\n") break;
          if (d === "\\") {
            j++;
            continue;
          }
          if (inClass) {
            if (d === "]") inClass = false;
          } else if (d === "[") {
            inClass = true;
          } else if (d === "/") {
            end = j;
            break;
          }
        }
        if (end === -1 || end >= idx) return "code";
        i = end;
        prev = "a";
        continue;
      }
    }
    prev = c;
  }
  if (q === '"' || q === "'") {
    // A real '…' or "…" string closes on its own line. No closer means the
    // lexer lost track (e.g. a trailing apostrophe in JSX text): stay "code".
    const lim = Math.min(content.length, idx + EVAL_LINE_CAP);
    for (let j = idx; j < lim; j++) {
      const d = content[j];
      if (d === "\n") break;
      if (d === "\\") {
        j++;
        continue;
      }
      if (d !== q) continue;
      if (q === "'" && isAsciiLetter(content[j - 1]) && isAsciiLetter(content[j + 1])) continue;
      return q;
    }
    return "code";
  }
  if (q === "`") return "code"; // a multi-line template can't be resolved per line
  // A line starting with `*` continues a block/JSDoc comment only while a `/*`
  // above it is still open; otherwise the `*` is a multiplication.
  const before = content.slice(lineStart, idx);
  if (/^\s{0,200}\*(?!\/)/.test(before) && !before.includes("*/")) {
    const win = content.slice(Math.max(0, lineStart - EVAL_LINE_CAP), lineStart);
    const open = win.lastIndexOf("/*");
    if (open !== -1 && win.indexOf("*/", open + 2) === -1) return "comment";
  }
  return "code";
}

/**
 * Index just past the string or template literal opening at src[i], or -1: a
 * newline inside '…'/"…", a `${` inside a template (built at runtime), or no
 * closer within the cap.
 */
function readStringLiteral(src: string, i: number, cap = 1_000_000): number {
  const q = src[i];
  const limit = Math.min(src.length, i + cap);
  for (let j = i + 1; j < limit; j++) {
    const c = src[j];
    if (c === "\\") {
      j++;
      continue;
    }
    if (c === q) return j + 1;
    if (q === "`" ? c === "$" && src[j + 1] === "{" : c === "\n") return -1;
  }
  return -1;
}

// Every `const|let|var NAME` in the file (one linear pass).
const EVAL_DECL = /(?<![\w$.])(?:const|let|var)\s{1,20}([A-Za-z_$][\w$]{0,63})(?![\w$])/g;
// Every other place a SCREAMING_CASE name can be (re)bound: destructuring
// ({NAME}, [NAME]), parameters ((NAME) {, (NAME) =>, (NAME: T), (NAME?: T),
// NAME =>), multi-declarators and reassignment. A false hit (an object key, a
// ternary) only makes the call fire.
const EVAL_SHADOW =
  /(?<![\w$.])([A-Z][A-Z0-9_]{0,63})(?![\w$])\s{0,20}(?:[,}\]:?]|=(?!=)|\)\s{0,20}(?:=>|\{))/g;
// A next line that would CONTINUE a `const X = "…"` written without ';'
// (`+ input`, `.concat(x)`, `? a : b`), so ASI does not end it at the newline.
const EVAL_EXPR_CONTINUES = /^(?:[+\-*%?.,|&^<>=(\[`]|\/(?![\/*]))/;

type EvalConstIndex = {
  decl: Map<string, { count: number; keyword: number; name: number; nameEnd: number }>;
  shadow: Map<string, number[]>;
};

function buildEvalConstIndex(content: string): EvalConstIndex {
  const decl: EvalConstIndex["decl"] = new Map();
  for (const m of content.matchAll(EVAL_DECL)) {
    const e = decl.get(m[1]);
    if (e) {
      e.count++;
    } else {
      const nameEnd = m.index + m[0].length;
      decl.set(m[1], { count: 1, keyword: m.index, name: nameEnd - m[1].length, nameEnd });
    }
  }
  const shadow: EvalConstIndex["shadow"] = new Map();
  for (const m of content.matchAll(EVAL_SHADOW)) {
    const at = shadow.get(m[1]);
    if (at) at.push(m.index);
    else shadow.set(m[1], [m.index]);
  }
  return { decl, shadow };
}

/**
 * Is `name` a module-level SCREAMING_CASE `const` bound exactly once, to one
 * plain string literal, and never re-bound anywhere in the file? Lowercase
 * names are never trusted: `const code = "…"` is routinely shadowed by a
 * `code` parameter or a `const { expression } = await req.json()` field.
 * Imported or undeclared names fail the single-declaration test.
 */
function isLiteralModuleConst(content: string, index: EvalConstIndex, name: string): boolean {
  const d = index.decl.get(name);
  if (!d || d.count !== 1) return false;
  if ((index.shadow.get(name) ?? []).some((at) => at !== d.name)) return false;
  if (!content.startsWith("const", d.keyword)) return false;
  const lineStart = content.lastIndexOf("\n", d.keyword - 1) + 1;
  if (d.keyword - lineStart > 40) return false;
  if (!/^(?:export\s{1,20})?$/.test(content.slice(lineStart, d.keyword))) return false;
  const init = /^\s{0,20}(?::\s{0,20}string\s{0,20})?=\s{0,20}/.exec(
    content.slice(d.nameEnd, d.nameEnd + 64)
  );
  if (!init) return false;
  const qi = d.nameEnd + init[0].length;
  if (content[qi] !== '"' && content[qi] !== "'" && content[qi] !== "`") return false;
  const end = readStringLiteral(content, qi);
  if (end === -1) return false;
  const tail = /^\s{0,20}(?:as\s{1,20}const\s{0,20})?(?:;|\r?\n|$)/.exec(content.slice(end, end + 32));
  if (!tail) return false;
  if (tail[0].endsWith(";")) return true;
  // No ';': the statement ends at the newline only if the next line cannot
  // continue the expression (`const SRC = "…"\n  + location.hash`).
  const from = end + tail[0].length;
  const next = content.slice(from, from + 200).trimStart();
  if (next === "") return from + 200 >= content.length;
  return !EVAL_EXPR_CONTINUES.test(next);
}

/**
 * Per-file, memoized isLiteralModuleConst. Only SCREAMING_CASE names can pass,
 * and the index is built once, on the first such name.
 */
function makeEvalConstCheck(content: string): (name: string) => boolean {
  let index: EvalConstIndex | null = null;
  const memo = new Map<string, boolean>();
  return (name) => {
    let ok = memo.get(name);
    if (ok === undefined) {
      ok = false;
      if (/^[A-Z][A-Z0-9_]{0,63}$/.test(name)) {
        if (!index) index = buildEvalConstIndex(content);
        ok = isLiteralModuleConst(content, index, name);
      }
      memo.set(name, ok);
    }
    return ok;
  };
}

/**
 * Classify the argument list that starts just after the '(' at argStart.
 * "empty": `eval()`. "constant": only string literals and trusted module
 * constants joined by '+' or ','. Anything else (a call, a member access, a
 * template with `${…}`, a comment, an untrusted identifier, a trailing '+',
 * or the 64-operand / 1.1M-char cap) is "dynamic" and keeps the finding.
 *
 * `inString` is the quote of the executed string the call sits in (an inline
 * script, a Function body), else "". There a quote of that kind ENDS the
 * string, so `"eval(" + input + ")"` splices outside text into the call: any
 * literal that starts with or contains it is dynamic. Callers pass an isConst
 * that trusts nothing, as names inside the string are the runtime script's
 * bindings, not this file's constants.
 */
function evalArgsKind(
  content: string,
  argStart: number,
  isConst: (name: string) => boolean,
  inString = ""
): "empty" | "constant" | "dynamic" {
  const limit = Math.min(content.length, argStart + 1_100_000);
  const idents: string[] = [];
  let tokens = 0;
  let expectOperand = true;
  let lastOp = "";
  let i = argStart;
  while (i < limit && tokens < 64) {
    const c = content[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      i++;
      continue;
    }
    if (c === ")") {
      if (tokens === 0) return "empty";
      if (expectOperand && lastOp !== ",") return "dynamic"; // `a + )`
      return idents.every((id) => isConst(id)) ? "constant" : "dynamic";
    }
    if (expectOperand) {
      if (c === '"' || c === "'" || c === "`") {
        if (c === inString) return "dynamic";
        const end = readStringLiteral(content, i);
        if (end === -1) return "dynamic";
        if (inString && content.slice(i, end).includes(inString)) return "dynamic";
        i = end;
      } else if (isIdentStart(c)) {
        let j = i + 1;
        while (j < limit && j - i < 64 && isIdentChar(content[j])) j++;
        idents.push(content.slice(i, j));
        i = j;
      } else {
        return "dynamic";
      }
      tokens++;
      expectOperand = false;
      continue;
    }
    if (c === "+" || c === ",") {
      lastOp = c;
      expectOperand = true;
      i++;
      continue;
    }
    return "dynamic";
  }
  return "dynamic";
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
          // Documented dummies (AKIA…EXAMPLE, abcdefgh…/12345678… sequences).
          // Content-only, so a real-looking key in a test file still fires.
          if (name !== "Private key block" && isDummySecretToken(token)) continue;
          // A PEM header alone is not a secret — require a key body inline.
          // A body kept elsewhere is caught by the armor-less pass below.
          if (name === "Private key block" && !hasInlineKeyBody(f.content, m.index + token.length)) {
            continue;
          }
          out.push({
            line: lineAt(f.content, m.index),
            column: columnAt(f.content, m.index),
            snippet: snippetAt(f.content, m.index),
            message: `${name} detected in source.`,
          });
        }
      }

      // Armor-less private-key body (see PRIVATE_KEY_DER_B64). Runs on every
      // file regardless of path: a committed key is live even in a test.
      const der = new RegExp(PRIVATE_KEY_DER_B64.source, "g");
      der.lastIndex = 0;
      let dm: RegExpExecArray | null;
      let dguard = 0;
      while ((dm = der.exec(f.content)) !== null) {
        if (++dguard > 1000) break;
        const idx = dm.index;
        const end = idx + dm[0].length;
        // A truncated doc example (body followed by "..." or "…") is not a key.
        if (f.content.slice(end, end + 3) === "..." || f.content[end] === "…") continue;
        // An armored body is owned by the header path above — don't report
        // the same key twice. Armored = an unclosed "-----BEGIN … PRIVATE
        // KEY-----" within the preceding 200 chars.
        const pre = f.content.slice(Math.max(0, idx - 200), idx);
        const b = pre.lastIndexOf("-----BEGIN ");
        if (b !== -1 && pre.indexOf("PRIVATE KEY-----", b) !== -1 && pre.indexOf("-----END ", b) === -1) {
          continue;
        }
        out.push({
          line: lineAt(f.content, idx),
          column: columnAt(f.content, idx),
          snippet: snippetAt(f.content, idx),
          message: "Private key material (a base64 key body without PEM armor) detected in source.",
        });
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
      // Deno's foo_test.ts, only when the file really loads a test runner
      // (see DENO_TEST_PATH): ab_test.ts / smoke_test.mjs stay scanned.
      if (DENO_TEST_PATH.test(f.path) && TEST_RUNNER_MARKER.test(f.content)) return [];
      const firebaseCtx = FIREBASE_MARKER.test(f.content);
      // Files that authenticate requests: an API route, middleware/proxy, or a
      // 'use server' module. A dev-labelled password there is a live gate, so
      // the dev-password exemption below never applies to them.
      const authSurface =
        isApiRoute(f.path) ||
        /(^|[\/\\])(?:middleware|proxy)\.[cm]?[jt]sx?$/i.test(f.path) ||
        hasUseServer(f.content);
      // Built lazily, at most once per file (see gateOperands).
      let gateIds: Set<string> | null = null;
      const usedAsGate = (id: string) => (gateIds ??= gateOperands(f.content)).has(id);
      return matchLines(f, (line) => {
        // Optional identifier prefix so dbPassword / myApiKey / stripeSecret
        // are caught, not just the bare keyword. The opening quote is captured
        // so a backtick code span in a comment can be told apart below.
        const m = line.match(
          /(?:^|[^A-Za-z0-9_])([A-Za-z0-9_]*?(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?token|auth[_-]?token))\s*[:=]\s*(["'`])([^"'`]{12,})["'`]/i
        );
        if (!m) return null;
        const id = m[1];
        const quote = m[2];
        const value = m[3];
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
        // Comment prose naming a code identifier in backticks
        // ("the secret: `ProviderSecretRejected`") — see CODE_REF.
        if (quote === "`" && COMMENT_LINE.test(line) && CODE_REF.test(value) && /[a-z]/.test(value)) {
          return null;
        }
        // Public EVM contract address under a token key — see EVM_ADDRESS.
        if (/token$/i.test(id) && EVM_ADDRESS.test(value)) return null;
        // Local/preview password labelled dev in BOTH name and value, outside
        // any auth surface and never used as a fallback or comparison operand.
        if (isSelfDeclaredDevPassword(id, value, authSurface, usedAsGate)) return null;
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
      // Skip manifests nested INSIDE a test / fixture / eval directory.
      // The FIRST path segment is never consulted: in a folder upload
      // (webkitRelativePath) it is the user's own project folder, and a project
      // named "test", "e2e" or "fixtures" is a real app that must keep firing.
      // The last segment (package.json itself) is excluded too. Deliberately
      // NO guard on the package name ("fixture" is a real sports-schedule app)
      // and NO top-level archive/ guard (Vercel's Root Directory is a dashboard
      // setting, so a nested legacy project may still be deployed).
      const segs = f.path.replace(/\\/g, "/").replace(/^\.?\/+/, "").split("/");
      if (segs.slice(1, -1).some((s) => DEP_FIXTURE_DIR.test(s))) return [];

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
          // A ^/~ range is NOT suppressed: a committed lockfile can pin it to
          // the vulnerable lower bound (4 of 13 measured true positives were
          // caret specs). The note only tells the user what to verify.
          const rangeNote = /^\s*[\^~]/.test(raw)
            ? ` Your package.json declares the range "${raw}"; the installed version is whatever your lockfile pins, so confirm it resolves to >= ${target.join(".")} and raise the floor to ^${target.join(".")}.`
            : "";
          out.push({
            line: idx >= 0 ? lineAt(f.content, idx) : 1,
            // The column is what keeps two advisories declared on the SAME line
            // (a single-line / minified package.json) as two distinct findings —
            // finding ids are built from file+line+column+snippet, so without it
            // the second one is silently deduplicated away.
            column: idx >= 0 ? columnAt(f.content, idx) : undefined,
            snippet:
              idx >= 0 ? snippetAt(f.content, idx) : `"${adv.name}": "${raw}"`,
            message: `${adv.name}@${raw}: ${adv.advisory} (upgrade to >= ${target.join(".")}).${rangeNote}`,
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
    // Test, fixture and CLI-script code never deploys, so it cannot be reached
    // by an attacker. Measured as most of this rule's false positives.
    appliesTo: (f) => isJsLike(f) && !isNonDeployedSqlFile(f),
    scan: (f) => {
      const out: RuleMatch[] = [];
      const content = f.content;
      // Once per file, not per match: a linear scan.
      const isAdsFile = GADS_FILE.test(content);
      // An explicit loop instead of matchAll, so each match can be dropped by
      // the per-match filters below. Same guards as matchAll.
      for (const re of [SQL_TEMPLATE, SQL_CONCAT]) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let guard = 0;
        while ((m = re.exec(content)) !== null) {
          if (++guard > 5000) break; // pathological input guard
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          // The filters read only the match text, which the bounded regexes
          // above cap at about 1 KB.
          if (isProse(m[0]) || isGaql(m[0], isAdsFile)) continue;
          out.push({
            line: lineAt(content, m.index),
            column: columnAt(content, m.index),
            snippet: snippetAt(content, m.index),
          });
        }
      }
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
    // Only calls that can run attacker code (see the dangerous-eval helpers
    // above): not in test/build tooling, not a non-window `.eval()` method or
    // Puppeteer's `$eval`, not inside a comment or a plain string, and not on
    // provably literal arguments. Every unsure case keeps the finding.
    scan: (f) => {
      if (isEvalToolingPath(f.path)) return [];
      const content = f.content;
      const out: RuleMatch[] = [];
      const isConst = makeEvalConstCheck(content);
      // The lookbehind excludes $eval / $$eval (Puppeteer, Playwright) and
      // identifiers such as _eval.
      const re = /(?<![\w$])eval\s{0,20}\(|\bnew\s{1,20}Function\s{0,20}\(/g;
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(content)) !== null) {
        if (++guard > 5000) break; // pathological input guard
        if (m[0].startsWith("eval") && !isGlobalEvalReceiver(content, m.index)) continue;
        const st = lineStateAt(content, m.index);
        if (st === "comment") continue;
        const argStart = m.index + m[0].length;
        if (st === "code") {
          if (evalArgsKind(content, argStart, isConst) !== "dynamic") continue;
        } else {
          // Text in a string is inert unless the string itself is executed.
          const lineStart = content.lastIndexOf("\n", m.index - 1) + 1;
          const pre = content.slice(Math.max(lineStart, m.index - EVAL_LINE_CAP), m.index);
          if (!EVAL_CODE_SINK.test(pre)) continue;
          if (evalArgsKind(content, argStart, () => false, st) !== "dynamic") continue;
        }
        out.push({
          line: lineAt(content, m.index),
          column: columnAt(content, m.index),
          snippet: snippetAt(content, m.index),
        });
      }
      return out;
    },
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
    // A sink is skipped only when its value provably carries no user input
    // (see isProvablySafeHtml); everything else, including any value this
    // single-file pass cannot follow, still flags.
    scan: (f) => {
      const out: RuleMatch[] = [];
      const re = /dangerouslySetInnerHTML\s*=/g;
      let info: HtmlFileInfo | null = null;
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.content)) !== null) {
        if (isJsonLdScript(f.content, m.index)) continue;
        const hv = HTML_PROP_VALUE.exec(f.content.slice(m.index, m.index + 600));
        if (hv) {
          if (!info) info = htmlFileInfo(f.content);
          if (isProvablySafeHtml(info, m.index + hv[0].length, m.index)) continue;
        }
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
