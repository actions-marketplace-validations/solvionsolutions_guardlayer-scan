import type { RuleMatch, ScanFile } from "./types";

/** Map a 0-based string index to a 1-based line number. */
export function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

/** Column (1-based) of an index within its line. */
export function columnAt(content: string, index: number): number {
  let col = 1;
  for (let i = index - 1; i >= 0; i--) {
    if (content[i] === "\n") break;
    col++;
  }
  return col;
}

const SNIPPET_CAP = 200;

/** Extract and tidy the source line containing `index`. */
export function snippetAt(content: string, index: number): string {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  let end = content.indexOf("\n", index);
  if (end === -1) end = content.length;
  const raw = content.slice(start, end).trim();
  return raw.length > SNIPPET_CAP ? raw.slice(0, SNIPPET_CAP) + "…" : raw;
}

/**
 * Run a regex over a whole file and return one RuleMatch per hit, with
 * accurate line/column/snippet. The regex MUST be global (`g`).
 */
export function matchAll(
  file: ScanFile,
  regex: RegExp,
  build?: (m: RegExpExecArray) => Partial<RuleMatch> | void
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const content = file.content;
  let m: RegExpExecArray | null;
  // Defensive: ensure global flag so exec advances.
  const re = regex.global ? regex : new RegExp(regex.source, regex.flags + "g");
  re.lastIndex = 0;
  let guard = 0;
  while ((m = re.exec(content)) !== null) {
    if (++guard > 5000) break; // pathological input guard
    // Skip zero-width matches outright: advance and don't record a spurious
    // finding. Keeps matchAll correct for any future rule whose regex can
    // match the empty string.
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    const extra = build ? build(m) || {} : {};
    out.push({
      line: lineAt(content, m.index),
      column: columnAt(content, m.index),
      snippet: snippetAt(content, m.index),
      ...extra,
    });
  }
  return out;
}

/** Per-line scan: invoke `test` on each line; collect matches. */
export function matchLines(
  file: ScanFile,
  test: (line: string, lineNo: number) => Omit<RuleMatch, "line" | "snippet"> | null
): RuleMatch[] {
  const out: RuleMatch[] = [];
  const lines = file.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const res = test(lines[i], i + 1);
    if (res) {
      const raw = lines[i].trim();
      out.push({
        line: i + 1,
        snippet: raw.length > SNIPPET_CAP ? raw.slice(0, SNIPPET_CAP) + "…" : raw,
        ...res,
      });
    }
  }
  return out;
}

/** Best-effort language label from the file extension. */
export function languageOf(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    ts: "typescript",
    tsx: "tsx",
    js: "javascript",
    jsx: "jsx",
    mjs: "javascript",
    cjs: "javascript",
    sql: "sql",
    json: "json",
    env: "dotenv",
    py: "python",
    go: "go",
    rb: "ruby",
    php: "php",
    yml: "yaml",
    yaml: "yaml",
    toml: "toml",
    sh: "bash",
  };
  if (path.endsWith(".env") || path.includes(".env.")) return "dotenv";
  return map[ext] ?? "text";
}

const CODE_EXT = new Set([
  "ts",
  "tsx",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "sql",
  "json",
  "env",
  "py",
  "go",
  "rb",
  "php",
  "yml",
  "yaml",
  "toml",
  "sh",
  "txt",
]);

/** Should this path be scanned at all (skip binaries, lockfiles, vendored)? */
export function isScannable(path: string): boolean {
  const lower = path.toLowerCase();
  if (
    lower.includes("/node_modules/") ||
    lower.startsWith("node_modules/") ||
    lower.includes("/.next/") ||
    lower.includes("/dist/") ||
    lower.includes("/.git/") ||
    lower.endsWith("package-lock.json") ||
    lower.endsWith("pnpm-lock.yaml") ||
    lower.endsWith("yarn.lock")
  ) {
    return false;
  }
  if (lower.endsWith(".env") || lower.includes(".env.")) return true;
  const ext = lower.split(".").pop() ?? "";
  return CODE_EXT.has(ext);
}

/** True when a TS/JS file runs on the client (`"use client"` directive). */
export function isClientComponent(content: string): boolean {
  // Directive must be near the top, before imports.
  const head = content.slice(0, 400);
  return /^[\s\n]*['"]use client['"]/.test(head) || /\n\s*['"]use client['"]/.test(head);
}

/**
 * True when a TS/JS file MENTIONS "use server" anywhere, comments included.
 * Deliberately loose: general/sql-injection uses it to keep possible Server
 * Action files in scope, where over-inclusion is the safe direction. Rules that
 * need a real directive use hasUseServerDirective() below.
 */
export function hasUseServer(content: string): boolean {
  return /['"]use server['"]/.test(content);
}

// JS `\s`: WhiteSpace + LineTerminator, the exact set the regex class matches.
function isJsSpace(c: number): boolean {
  return (
    (c >= 9 && c <= 13) || c === 32 || c === 0xa0 || c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 ||
    c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff
  );
}

/** Ascending start offsets of every `needle` in `s`. */
function offsetsOf(s: string, needle: string): number[] {
  const out: number[] = [];
  for (let k = s.indexOf(needle); k !== -1; k = s.indexOf(needle, k + needle.length)) out.push(k);
  return out;
}

/** First value in ascending `arr` that is >= x, or -1. */
function firstAtOrAfter(arr: number[], x: number): number {
  let lo = 0,
    hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo < arr.length ? arr[lo] : -1;
}

/**
 * Inline directive: the first statement of a function body. Up to 5 comments
 * may sit between `{` and it. Exactly the language of
 *   /\{\s{0,200}(?:(?:\/\/[^\n]{0,300}\n|\/\*(?:[^*]|\*(?!\/)){0,1000}\*\/)\s{0,200}){0,5}['"]use server['"]/
 * but as a walk instead of that regex. The regex is ReDoS-safe yet re-scans up
 * to ~1000 chars from EVERY `{`, so dense `{/*` input cost 1.7 s/MB (340 ms at
 * the 200 KB GitHub file cap). The parse is deterministic (each comment starts
 * with '/', which \s cannot match, and a comment ends at its FIRST `\n` / `*\/`),
 * so a walk with O(log n) comment-end lookups and memoised converging paths
 * gives the same answer in linear time (~10 ms on 1 MB adversarial input).
 */
function hasInlineUseServer(content: string): boolean {
  const n = content.length;
  let newlines: number[] | null = null; // built lazily: most files never need them
  let closers: number[] | null = null;
  const memo = new Map<number, boolean>(); // walks converge after a shared comment end
  // From `i` (just after `{` or a comment), with `d` comments consumed so far.
  const walk = (i: number, d: number): boolean => {
    for (let run = 0; i < n && isJsSpace(content.charCodeAt(i)); i++) {
      if (++run > 200) return false; // \s{0,200}: a 201st space can start nothing
    }
    const c = content.charCodeAt(i);
    if ((c === 34 || c === 39) && content.startsWith("use server", i + 1)) {
      const q = content.charCodeAt(i + 11);
      if (q === 34 || q === 39) return true;
    }
    if (d >= 5 || c !== 47) return false;
    const c2 = content.charCodeAt(i + 1);
    let next: number;
    if (c2 === 47) {
      // `//` comment: at most 300 chars, then its newline.
      newlines ??= offsetsOf(content, "\n");
      const e = firstAtOrAfter(newlines, i + 2);
      if (e < 0 || e - (i + 2) > 300) return false;
      next = e + 1;
    } else if (c2 === 42) {
      // `/* */` comment: at most 1000 chars, closed by the FIRST `*/` after `/*`.
      closers ??= offsetsOf(content, "*/");
      const e = firstAtOrAfter(closers, i + 2);
      if (e < 0 || e - (i + 2) > 1000) return false;
      next = e + 2;
    } else return false;
    const key = next * 8 + d + 1;
    let r = memo.get(key);
    if (r === undefined) {
      r = walk(next, d + 1);
      memo.set(key, r);
    }
    return r;
  };
  for (let p = content.indexOf("{"); p !== -1; p = content.indexOf("{", p + 1)) {
    if (walk(p + 1, 0)) return true;
  }
  return false;
}

/**
 * True when "use server" is an actual DIRECTIVE: the module's first statement
 * (after whitespace/BOM, comments and an optional 'use strict'), or the first
 * statement of a function body (an inline Server Action). A mention inside a
 * comment or an ordinary string does not count — on the 55-repo corpus that
 * mention-only case flagged a plain library module that is never callable from
 * the browser. Deliberately NOT built on stripJsComments: glob strings such as
 * '/**' fool a regex comment stripper.
 */
export function hasUseServerDirective(content: string): boolean {
  if (!/['"]use server['"]/.test(content)) return false; // cheap pre-check
  const n = content.length;
  let i = 0;
  // Module directive: the first statement after whitespace or BOM, comments, and an optional leading 'use strict'.
  for (let guard = 0; guard < 500 && i < n; guard++) {
    while (i < n && isJsSpace(content.charCodeAt(i))) i++;
    if (content.startsWith("//", i)) {
      const e = content.indexOf("\n", i);
      i = e === -1 ? n : e + 1;
      continue;
    }
    if (content.startsWith("/*", i)) {
      const e = content.indexOf("*/", i + 2);
      i = e === -1 ? n : e + 2;
      continue;
    }
    const strict = /^(['"])use strict\1[ \t]{0,20};?/.exec(content.slice(i, i + 40));
    if (strict) {
      i += strict[0].length;
      continue;
    }
    break;
  }
  if (/^['"]use server['"]/.test(content.slice(i, i + 12))) return true;
  return hasInlineUseServer(content);
}

/**
 * Recognise obvious non-secrets so the hardcoded-secret rule stays precise.
 * Placeholders, env references, and example values are ignored.
 */
export function looksLikePlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  // Strong, unambiguous markers — substring match is fine.
  if (
    v.includes("process.env") ||
    v.includes("import.meta.env") ||
    v.includes("your_") ||
    v.includes("your-") ||
    v.includes("placeholder") ||
    v.includes("changeme") ||
    v.includes("change_me") ||
    v.includes("xxxx") ||
    v.includes("...") ||
    v.includes("<") ||
    v.includes("${") ||
    v.includes("redacted") ||
    /^[*•x]+$/.test(v) ||
    v.length < 8
  ) {
    return true;
  }
  // Weak words (test/sample/dummy/example/fake) only count as placeholders
  // when they appear as standalone tokens — not as base62 noise inside a real
  // secret (e.g. "attestation", "latest") which would suppress a live key.
  return /(?:^|[^a-z0-9])(?:test|sample|dummy|example|fake|demo)(?:[^a-z0-9]|$)/.test(
    v
  );
}

/**
 * Is this a test / fixture / mock file?
 *
 * Test files are full of deliberately fake credentials ("refresh-token-r2",
 * access_token: "jwt.accesstoken.signature"), and reporting those as leaked
 * secrets is noise, not security. Measured on real repos: this is the single
 * largest false-positive source for the NAME-based secret heuristic.
 *
 * Only the heuristic rules consult this. A provider-FORMAT match (sk_live_,
 * AKIA…, a real service_role JWT) still fires anywhere, because those are
 * unambiguous and a live key committed to a test file is still a live key.
 *
 * The dot form also covers .mjs/.cjs (foo.test.mjs is a node:test / Vitest
 * file). Deno's underscore form (foo_test.ts) is deliberately NOT matched
 * here: ab_test.ts and smoke_test.mjs are ordinary production names, so a
 * caller that wants it must also check the file for a test-runner import.
 */
export function isTestPath(path: string): boolean {
  const p = path.toLowerCase().replace(/\\/g, "/");
  return (
    /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(p) ||
    /(^|\/)(__tests__|__mocks__|__fixtures__|tests?|e2e|cypress|fixtures?|mocks?|testdata)\//.test(
      p
    )
  );
}

/**
 * Is this path a Supabase edge function?
 *
 * The directory segment may carry a suffix: repos that keep a second Supabase
 * project in a sibling directory (supabase-saas/, with its own config.toml)
 * put real, deployed edge functions under supabase-saas/functions/. Missing
 * those means edge-function-no-auth never runs on them. The segment must
 * START a path component, so "my-supabase/functions" does not count; and
 * [\w.-]* is followed by the disjoint [\/\\], so the match stays linear.
 */
export function isEdgeFunction(path: string): boolean {
  return /(^|[\/\\])supabase[\w.-]*[\/\\]functions[\/\\]/i.test(path);
}

/** Is this path a Next.js API route handler? */
export function isApiRoute(path: string): boolean {
  return /app[\/\\].*route\.(ts|js|tsx|jsx)$/.test(path) || /pages[\/\\]api[\/\\]/.test(path);
}

/** Is this a SQL/migration file? */
export function isSql(path: string): boolean {
  return path.toLowerCase().endsWith(".sql");
}

/**
 * Blank out SQL comments while PRESERVING line structure (so line numbers
 * computed against the original content still line up). The SQL counterpart of
 * `stripJsComments` — lets a migration warn *about* a footgun in a comment
 * without the rule flagging the comment itself.
 *
 * Known trade-off: a literal `--` inside a string literal blanks the rest of
 * that line. That can only ever cause a false NEGATIVE, never a false positive.
 */
export function stripSqlComments(content: string): string {
  // Block comments: same length, newlines preserved.
  let out = content.replace(/\/\*[\s\S]*?\*\//g, (block) =>
    block.replace(/[^\n]/g, " ")
  );
  // Line comments: `--` to end of line.
  out = out.replace(/--[^\n]*/g, (c) => " ".repeat(c.length));
  return out;
}

/**
 * String-aware sibling of `stripSqlComments`: blanks `--` and `/* … *\/`
 * comments (same length, newlines kept) but steps OVER '…' literals and "…"
 * identifiers. The regex version blanks from a `/*` or `--` inside a literal —
 * `ARRAY['image/*']` followed by a later real block comment, or a policy named
 * "Allow all -- temp" — which silently hides live SQL. Here that can't happen.
 *
 * One left-to-right, indexOf-driven pass (linear). Deliberate limits, all of
 * which fail LOUD (leave text visible) rather than blank live SQL:
 *  - An unterminated '…' or "…" stops processing; the rest is left as-is.
 *  - An unterminated `/*` is left unblanked, and no later `/*` opens a comment
 *    (keeps the pass linear). Block comments are matched non-nested: a
 *    nested-comment lexer measured 25 s on adversarial input.
 *  - Dollar-quoted bodies are lexed as ordinary SQL on purpose — DO-block and
 *    EXECUTE bodies hold real policies that must stay visible. An apostrophe
 *    in dollar-quoted prose, or an E'…\'…' escape, can misalign the lexer.
 */
export function stripSqlCommentsQuoted(content: string): string {
  const n = content.length;
  let out = "";
  let copied = 0; // content[copied, i) is not yet in `out`
  const blank = (from: number, to: number) => {
    out += content.slice(copied, from) + content.slice(from, to).replace(/[^\n]/g, " ");
    copied = to;
  };
  let noBlockClose = false;
  let i = 0;
  while (i < n) {
    const ch = content[i];
    if (ch === "'") {
      // '…' literal; '' is an escaped quote, not the end.
      let j = content.indexOf("'", i + 1);
      while (j !== -1 && content[j + 1] === "'") j = content.indexOf("'", j + 2);
      if (j === -1) break;
      i = j + 1;
    } else if (ch === '"') {
      const j = content.indexOf('"', i + 1);
      if (j === -1) break;
      i = j + 1;
    } else if (ch === "-" && content[i + 1] === "-") {
      let j = content.indexOf("\n", i + 2);
      if (j === -1) j = n;
      blank(i, j);
      i = j;
    } else if (ch === "/" && content[i + 1] === "*" && !noBlockClose) {
      const j = content.indexOf("*/", i + 2);
      if (j === -1) {
        noBlockClose = true;
        i += 2;
        continue;
      }
      blank(i, j + 2);
      i = j + 2;
    } else {
      i++;
    }
  }
  return out + content.slice(copied);
}

const isIdentCode = (c: number) =>
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const DOLLAR_TAG_AT = /^\$(?:[A-Za-z_][A-Za-z0-9_]{0,62})?\$/;

/**
 * Every occurrence of every well-formed dollar tag, keyed by tag, ascending.
 * A tag holds no inner "$", so an occurrence of "$name$" at k is exactly
 * content[k .. the next "$" after k]: one walk over the "$" signs finds every
 * hit `indexOf(tag, from)` could return, overlapping ones ("$a$a$") included.
 * Why not indexOf: distinct nested tags ($t0$ $t1$ … $t1$ $t0$) make each
 * opener search to its own close, one pass per level (16 s on 1 MB).
 */
function dollarTagIndex(content: string): Map<string, number[]> {
  const occ = new Map<string, number[]>();
  let k = content.indexOf("$");
  while (k !== -1) {
    const e = content.indexOf("$", k + 1);
    if (e === -1) break;
    if (e - k <= 64) {
      const tag = content.slice(k, e + 1);
      if (DOLLAR_TAG_AT.test(tag)) {
        const list = occ.get(tag);
        if (list) list.push(k);
        else occ.set(tag, [k]);
      }
    }
    k = e;
  }
  return occ;
}

/**
 * Quote- AND dollar-body-aware SQL comment blanker. Same contract as
 * `stripSqlComments`: the output has the input's length and keeps every "\n",
 * so an index into the result is an index into the original (lineAt and
 * snippetAt keep working on `content`).
 *
 * Why a third variant:
 *  - The regex `stripSqlComments` blanks from a `--` or `/*` inside a literal
 *    (`VALUES ('--')`, `ARRAY['image/*']` plus a later real block comment),
 *    which silently hides a live CREATE TABLE. It is also O(n²) on
 *    unterminated `/*` input (2.8 s on 200 KB of "/* x ").
 *  - `stripSqlCommentsQuoted` lexes dollar-quoted bodies as plain SQL, so an
 *    apostrophe in function prose can run on past `$$` and swallow the rest
 *    of the file. Here each `$tag$ … $tag$` body is a hard limit: it is still
 *    lexed as code (comments inside function and DO bodies are blanked), but
 *    nothing inside it — a quote, a comment — can run past its closing tag.
 *
 * One left-to-right pass; every inner scan stops at the current body limit,
 * so the pass stays linear. The limits all fail LOUD (leave text visible)
 * rather than blank live SQL:
 *  - Block comments nest, as in Postgres. An unterminated `/*` blanks nothing,
 *    and no later `/*` in the same body opens a comment.
 *  - After 64 `$tag$` openers with no closing tag inside the current body,
 *    `$` is an ordinary character. Closing tags are found through a one-pass
 *    index of every tag occurrence (dollarTagIndex), built on the first
 *    opener, so neither a failure nor a deep nest of bodies rescans the file.
 */
export function stripSqlCommentsQuoteAware(content: string): string {
  const n = content.length;
  let out = "";
  let copied = 0; // content[copied, i) is not yet in `out`; `i` only grows
  const blank = (from: number, to: number) => {
    if (to <= from) return;
    out += content.slice(copied, from) + content.slice(from, to).replace(/[^\n]/g, " ");
    copied = to;
  };
  const identAt = (k: number) => k >= 0 && k < n && isIdentCode(content.charCodeAt(k));

  // Stack of dollar-body limits (index of the closing tag) and their tags.
  const limits: number[] = [n];
  const tags: string[] = [""];
  let dollarFailures = 0;
  let noBlockUntil = -1; // after an unterminated `/*`: no openers until here
  let tagIndex: Map<string, number[]> | undefined; // built on the first opener
  /** First occurrence of `tag` at or after `from` (-1 if none): indexOf's answer. */
  const nextTagAt = (tag: string, from: number): number => {
    const list = (tagIndex ??= dollarTagIndex(content)).get(tag);
    if (!list) return -1;
    let lo = 0;
    let hi = list.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (list[mid] < from) lo = mid + 1;
      else hi = mid;
    }
    return lo < list.length ? list[lo] : -1;
  };
  let i = 0;
  while (i < n) {
    const lim = limits[limits.length - 1];
    if (i >= lim) {
      // End of a dollar body: step over its closing tag.
      limits.pop();
      i = lim + (tags.pop() ?? "").length;
      continue;
    }
    const ch = content[i];
    const next = content[i + 1];
    if (ch === "-" && next === "-") {
      let e = i + 2;
      while (e < lim && content[e] !== "\n") e++;
      blank(i, e);
      i = e;
    } else if (ch === "/" && next === "*" && i >= noBlockUntil) {
      let depth = 1;
      let j = i + 2;
      while (j < lim && depth > 0) {
        if (content[j] === "/" && content[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (content[j] === "*" && content[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      if (depth > 0) {
        noBlockUntil = lim; // unterminated: blank nothing, never rescan this body
        i += 2;
      } else {
        blank(i, j);
        i = j;
      }
    } else if (ch === "'") {
      // '…' literal; '' is an escaped quote. In an E'…' string (the E not
      // part of a longer identifier) a backslash escapes the next character.
      const prev = content[i - 1];
      const eString = (prev === "e" || prev === "E") && !identAt(i - 2);
      let j = i + 1;
      while (j < lim) {
        const c = content[j];
        if (eString && c === "\\") {
          j += 2;
          continue;
        }
        if (c === "'") {
          if (content[j + 1] === "'") {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      i = Math.min(j + 1, lim);
    } else if (ch === '"') {
      let j = i + 1;
      while (j < lim && content[j] !== '"') j++;
      i = Math.min(j + 1, lim);
    } else if (ch === "$" && dollarFailures < 64 && !identAt(i - 1)) {
      // `$1` positional params never match: the tag must close with `$`.
      const m = DOLLAR_TAG_AT.exec(content.slice(i, i + 66));
      if (m) {
        const tag = m[0];
        const close = nextTagAt(tag, i + tag.length);
        if (close !== -1 && close + tag.length <= lim) {
          limits.push(close);
          tags.push(tag);
          i += tag.length;
          continue;
        }
        dollarFailures++;
      }
      i++;
    } else {
      i++;
    }
  }
  return out + content.slice(copied);
}

/**
 * End index (exclusive) of the SQL statement starting at `from` — the first
 * top-level `;`, skipping dollar-quoted bodies so a `;` inside a function body
 * doesn't terminate the statement early. Capped so a pathological input can't
 * make a rule walk the whole file.
 */
export function sqlStatementEnd(src: string, from: number, cap = 8000): number {
  const limit = Math.min(src.length, from + cap);
  let i = from;
  while (i < limit) {
    const ch = src[i];
    if (ch === "$") {
      // A dollar-quote tag ($$ or $tag$). Note `$1` positional params do NOT
      // match — the closing `$` is required.
      const tag = /^\$[A-Za-z0-9_]*\$/.exec(src.slice(i, i + 64));
      if (tag) {
        const close = src.indexOf(tag[0], i + tag[0].length);
        if (close === -1) return limit; // unterminated body
        i = close + tag[0].length;
        continue;
      }
    }
    if (ch === ";") return i;
    i++;
  }
  return limit;
}

/**
 * Blank out JS/TS comments while PRESERVING line structure (so line numbers
 * computed against the original content still line up). Used by prose-sensitive
 * rules so a defensive comment that merely mentions a term isn't flagged.
 */
export function stripJsComments(content: string): string {
  // Block comments: replace with same number of newlines + spaces. An indexOf
  // walk with the exact output of /\/\*[\s\S]*?\*\//g: that regex rescanned to
  // the end of the file from every unterminated `/*` (2.7 s on 200 KB of
  // "/* x "). Once a `/*` has no later `*/`, no later `/*` can close either.
  let out = "";
  let copied = 0; // content[copied, …) is not yet in `out`
  let open = content.indexOf("/*");
  while (open !== -1) {
    const close = content.indexOf("*/", open + 2);
    if (close === -1) break;
    out += content.slice(copied, open) + content.slice(open, close + 2).replace(/[^\n]/g, " ");
    copied = close + 2;
    open = content.indexOf("/*", copied);
  }
  out += content.slice(copied);
  // Line comments (avoid http:// by requiring the // not be preceded by ':').
  out = out.replace(/([^:"'`\n]|^)\/\/[^\n]*/g, (_m, p1: string) => p1);
  return out;
}
