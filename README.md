# GuardLayer Scan — free security scanner for Next.js + Supabase (GitHub Action)

**GuardLayer Scan is a free, open-source (MIT) GitHub Action that statically scans your Next.js + Supabase repo for exposed secrets, missing Row Level Security, unguarded Server Actions, unverified webhooks and known-vulnerable dependencies.** It marks findings as annotations on the exact file and line, lists them in a summary on the workflow run, and can fail the build on critical issues. No signup, no account, no API key, and your code never leaves the runner.

It runs the same static engine as [guardlayer.io](https://www.guardlayer.io). Want to try the rules before wiring up CI? Paste a migration into the [free in-browser checker](https://www.guardlayer.io/supabase-security-checker) — it runs client-side, nothing is uploaded.

## Quick start

Add `.github/workflows/guardlayer.yml`:

```yaml
name: GuardLayer
on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: solvionsolutions/guardlayer-scan@v1
        with:
          fail-on: critical   # critical | warning | never
```

That's it. Findings appear as annotations on the exact file and line, plus a summary on the run. By default the build fails only on **critical** issues. A failed run blocks a merge only if you make this job a required status check in your branch protection rules.

## What's new (October 2026)

- **A vulnerable dependency can now fail the build.** When a dependency's latest security fix is for an advisory its publisher rates **Critical**, GuardLayer reports it as a critical finding, so the default `fail-on: critical` fails the run. Today that covers `next` below 16.4.1 on 16.x or 15.5.28 on 15.x (the October 14, 2026 release fixed two critical unauthenticated remote code execution bugs), `react-server-dom-*` below the 19.x patch releases, and `minimist`.
- **To fix it,** upgrade the package, for example `npm install next@latest` (or `next@15.5.28` on 15.x).
- **To report without failing** while you upgrade, set `fail-on: never`.
- Also new: far fewer false positives across the board, and a table that a migration creates without RLS and grants to `anon` is now critical.

## What it checks

36 checks across six areas:

- **Supabase RLS** — tables with RLS disabled or missing, `USING (true)` policies, policies not scoped to the user, policies keyed off user-editable `user_metadata`, tables `GRANT`ed to `anon` without RLS, `SECURITY DEFINER` functions with an unpinned `search_path`.
- **Exposed secrets** — service-role keys and `sb_secret_` keys leaked through `NEXT_PUBLIC_`, hardcoded service_role JWTs, hardcoded provider keys. (A publishable `sb_publishable_` / anon key is *not* flagged — it's public by design.)
- **Next.js app layer** — Server Actions and API routes with no auth check, wildcard CORS, open redirects built from request input, missing middleware matchers, `getSession()` trusted in server code.
- **Dependencies** — known-vulnerable versions of `next` and the React Server Components packages `react-server-dom-*` (per release branch), `@supabase/auth-js`, `next-auth` and `@auth/core`, plus deprecated packages like `@supabase/auth-helpers-*`.
- **Webhooks** — Stripe/webhook handlers that never verify the signature.
- **MCP / AI-agent config** — secrets committed in `.mcp.json` / `.cursor/mcp.json`, including credentials passed as command-line `args`; a Supabase MCP server without `--read-only`; and GitHub Actions workflows that let any user trigger an AI coding agent, or run untrusted pull-request code with your secrets.

These last checks flag *configuration* — an agent's blast radius and committed credentials. They do not detect prompt injection, tool poisoning, or anything about how an agent behaves at runtime.

Precision-first: rules are tuned to stay quiet on safe code (a publishable Supabase anon key is *not* flagged as a secret, a zod-validated route is *not* flagged as unvalidated).

## Inputs

| Input | Default | Description |
|---|---|---|
| `fail-on` | `critical` | Fail the build on `critical`, on `warning` (and above), or `never` (report only). |

## Outputs

| Output | Description |
|---|---|
| `score` | Security score out of 100. |
| `grade` | Letter grade A–F. |
| `critical` / `warning` / `findings` | Finding counts. |

## Ignoring paths

Add a `.guardlayerignore` (gitignore syntax) to your repo root to exclude test fixtures or intentional examples. Vendor and build directories (`node_modules`, `.next`, `dist`, …) are always skipped.

## How it works

The Action walks your checked-out repo, runs GuardLayer's static analysis in-process, emits GitHub annotations and writes the job summary. It doesn't post pull request comments. It's pure static analysis — nothing is uploaded, no API key is required, and it works on private repos.

Want pull request comments, a GuardLayer check on every push and pull request, and a hosted dashboard? That's the hosted [GuardLayer](https://www.guardlayer.io) GitHub App, with the same checks: free for public repos, with paid plans for private ones.

## Badge

To show that a repo is scanned by GuardLayer, add this to its README:

```markdown
[![Scanned by GuardLayer](https://www.guardlayer.io/badge.svg)](https://www.guardlayer.io/?utm_source=badge&utm_medium=readme)
```

The badge is a static image, the same for every repo. It shows no score and no findings, so it says nothing about how secure a repo is.

## License

MIT © GuardLayer / Solvion Solutions
