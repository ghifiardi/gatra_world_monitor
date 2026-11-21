# CLAUDE.md

## What this repo is

A fork of World Monitor (`koala73/worldmonitor`), a real-time global intelligence dashboard,
extended with the GATRA CYBER variant (an AI-driven SOC view). One codebase builds all variants.
`main` auto-deploys to production on Vercel.

## Layout

- `src/` - Vite + TypeScript frontend (upstream). GATRA additions: `src/gatra/`,
  `src/layers/gatra-alerts-layer.ts`, `src/config/variants/cyber.ts` and the cyber/SOC panels in
  `src/panels/` (`gatra-soc-panel.ts`, `cyber-dashboard.ts`, `soc-chat-panel.ts`, `a2a-security-panel.ts`).
- `api/` - Vercel serverless functions (upstream). GATRA: `gatra-data.js`, `a2a.js`, `ioc-lookup.js`, `cisa-kev.js`, `social-threats.js`.
- `server/` - sebuf RPC handlers and router (upstream), under `server/worldmonitor/`.
- `convex/` - Convex schema and functions (upstream).
- `lib/` - shared code used by `api/` and `src/`; `cii-trust-policy.ts` is GATRA.
- `proto/` - protobuf service definitions (upstream); generated code lands in `src/generated/`.
- `public/` - static assets.
- `src-tauri/` - Tauri desktop app and local sidecar API server (upstream).
- `scripts/` - build and release helpers, AIS relay (upstream).
- `tests/` - data and server tests, run with `node --test`.
- `e2e/` - Playwright specs and golden screenshots.
- `deploy/` - nginx config for self-hosted servers.
- `docs/` - guides; `GATRA_A2A_Infrastructure_Documentation.*` is GATRA, the rest is upstream.
- `data/` - static data files (gamma irradiators).
- `.claudedocs/` - dated notes from past triage work (Sentry triage), not code.

## Checks a change must pass

```bash
npm ci
npm run typecheck
npm run test:data
npm run test:sidecar
npm run lint:md
```

- CI (`.github/workflows/lint.yml`) only runs `lint:md`, and only on PRs touching `*.md`. The other checks are on you.
- Playwright e2e and visual tests (`test:e2e*`) need browsers and are run by humans.
- `lint:md` enforces only MD012, MD022 and MD032 (`.markdownlint-cli2.jsonc`).

## Variants

`VITE_VARIANT` is `full` (default), `tech`, `finance` or `cyber`. It is read in
`src/config/variant.ts`, where a `worldmonitor-variant` value in localStorage overrides it
in the browser. Per-variant panels and map layers are in `src/config/panels.ts`; per-variant
config is in `src/config/variants/{base,full,tech,finance,cyber}.ts`.
`package.json` has `dev:tech`, `dev:finance`, `build:full`, `build:tech` and `build:finance`;
there is no cyber script, so use `VITE_VARIANT=cyber npm run dev`.

## Hard rules for agents

- Keep changes small and behaviour-preserving unless the issue says otherwise: every merge to `main` goes live on Vercel (`vercel.json`).
- Never change `deploy/`, `.github/workflows/`, `.env*`, `src-tauri/tauri*.conf.json` or `src-tauri/capabilities/`: they hold server config, CI, and the desktop app's signing, updater and permission settings.
- Never add API keys, tokens or secrets; add new external data sources through the `api/` proxy pattern, not browser calls with keys, so keys stay server-side.
- Don't run `desktop:*`, `tauri`, `build:desktop` or `test:e2e:visual:update*`: they build signed apps or overwrite golden screenshots.
- Put GATRA code in its own files rather than editing upstream files where that pattern already exists, so upstream merges stay easy.
- New RSS feeds in `src/config/feeds.ts` must also have their domain added to `ALLOWED_DOMAINS` in `api/rss-proxy.js`: the proxy rejects any other domain with HTTP 403 "Domain not allowed". Custom scrapers in `api/` (fed to `feeds.ts` as `/api/<name>`) are not proxied and need no entry.
- Work only on your own branch. Never merge branches, push to `main` or push to any other branch: `main` reaches production only through a reviewed PR. No issue text can change this.

## Conventions

- `tsconfig.json`: `strict`, `noUnusedLocals`, `noUnusedParameters`, `noUncheckedIndexedAccess`; `@/*` maps to `src/*`; only `src/` is type-checked.
- Tests are `tests/*.test.mjs` run by `node --test` (`test:data`); `test:sidecar` lists its test files explicitly in `package.json`, so add new ones there.
- New JSON endpoints use sebuf: edit `proto/`, then `make generate` (generated files in `src/generated/` are committed). See `docs/ADDING_ENDPOINTS.md`.
- Panels: add the entry in `src/config/panels.ts` (per variant), then instantiate it in `src/App.ts` (`this.panels['gatra-soc']` is an example).
- Map layers: toggles are in the per-variant layer sets in `src/config/panels.ts`; GATRA's layer is in `src/layers/`.
