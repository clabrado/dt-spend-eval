---
name: dt-spend-eval
description: >-
  DPS spend evaluation for one or more Dynatrace tenants — explains why consumption is high or
  trending to overage and where to save. Needs only a tenant URL/ID. Pulls BILLING_USAGE_EVENT
  records from Grail via dtctl, prices every capability at DPS list, finds new cost lines,
  spikes and day-of-week patterns, breaks top lines down by host / synthetic monitor / metric key
  / query user / RUM app, then runs a Full-Stack value test per host (traces, app runtimes, vulns,
  attacks, Davis problems, utilization) to bucket hosts into move-to-Infrastructure vs keep.
  Adversarial QA subagent verifies claims. Optional PowerBI Dynatrace ONE commit/consumption-rate
  context. Output format=md (default) or format=html. Triggers: DPS spend, overage, consumption
  review, why is usage so high, cost reduction, save money on Dynatrace, Full-Stack vs Infra value,
  license optimization, spend forecast.
---

# dt-spend-eval — DPS Spend Evaluation

Codifies a field-proven customer engagement (≈22% of annual run rate identified as savings) so it
runs against any tenant. The mechanical work (serial queries, pricing, bucketing, HTML render) lives in
`scripts/spend_eval.py` so numbers are deterministic; Claude does judgment, QA, and the write-up.

## Invocation

```
/dt-spend-eval <tenant> [<tenant> ...] [format=md|html] [since=YYYY-MM-DD] [until=YYYY-MM-DD]
               [account="<SFDC account name>"] [out=<dir>] [-clean]
```

| Arg | Default | Notes |
|---|---|---|
| `<tenant>` | required | `https://abc12345.apps.dynatrace.com`, `abc12345`, or an existing dtctl context name. Repeatable. |
| `format=` | `md` | `md` or `html` (html = md rendered by the script, self-contained, light/dark) |
| `since=` / `until=` | ~4 months back / yesterday | Billing window. Keep `until` ≥1 day before now (billing lags ~1 day). |
| `account=` | none | Enables optional PowerBI step. Omit if the user has no PowerBI MCP. |
| `out=` | current working directory | Report lands here as `<Account-or-tenant>_DPS_Spend_Eval_<date>.<ext>` |
| `-clean` | off | Replace hostnames, emails, tenant IDs, entity IDs with placeholders (for artifacts leaving the account team) |

If no tenant is given, ask for it. Nothing else is required.

## Hard rules

1. **dtctl strictly serial** — never `&`, `xargs -P`, or parallel subagents running dtctl. Concurrent dtctl races the OAuth refresh and can delete the token file. The script is serial; QA subagents run *after* collection and must also be serial.
2. **Read-only.** Never create/modify anything in the tenant.
3. **Don't guess.** Every number in the report comes from `analysis.json` or a query you ran this session. If a signal is missing (e.g. no process-technology data), say so; don't infer.
4. **Dollars = DPS list price**, labeled as such. Never present as contracted cost.
5. Span absence claims require ≤1-day windows with no "stopped after" scan warning (the script enforces this; check `span_scan_partial`).

## Phase 0 — Load references (once)

Read `~/.claude/skills/dt-dql-essentials/SKILL.md` (DQL syntax) before writing any ad-hoc query, and `references/queries.md` in this skill for the query library and gotchas.

## Phase 1 — Connect each tenant (serial)

For each tenant, derive `<id>` and URL (`https://<id>.apps.dynatrace.com`; sprint/labs URLs pass through as given).

```bash
dtctl config get-contexts --plain --no-agent -o json    # reuse a context whose Environment matches
dtctl auth status --context <ctx>
# if missing or expired:
dtctl auth login --context <id> --environment https://<id>.apps.dynatrace.com
```
Use the user's preferred browser if they state one (macOS Chrome: prepend a PATH shim whose `open` runs `/usr/bin/open -a "Google Chrome" "$@"`, and set `BROWSER` to it). Poll `dtctl auth status` after login; don't ask the user to run commands.

## Phase 2 — Collect (serial, per tenant)

```bash
S=~/.claude/skills/dt-spend-eval/scripts/spend_eval.py
W=<scratchpad>/spend-eval/<ctx>
python3 $S collect --context <ctx> --out $W [--since ..] [--until ..]     # ~20 queries, 2–6 min
python3 $S analyze --out $W                                                 # writes $W/analysis.json + console summary
```
Run in the foreground with a long timeout (or background + wait for the completion notification). If any line shows `ERR`, read `$W/<name>.json` → `stderr`/`dql`, fix via dt-dql-essentials, re-run that query by hand and overwrite the file in the same `{"records": [...]}` shape, then re-run `analyze`.

## Phase 3 — Optional PowerBI context

Only if `account=` given **and** `mcp__powerBI__dynatrace_one_grid` is available:
`dynatrace_one_grid(account_filter="<account>")` → confirm the exact account row (filter is a substring match — a short name can match several unrelated accounts). Capture: annual commit, annualized consumption, consumption rate (latest + 6-mo avg), DPS forecast, renewal date, health score. If unavailable, write "Commit/consumption-rate data not available (PowerBI not connected)" and continue.

## Phase 4 — Interpret (judgment)

Work from `analysis.json`:

- **Where spend goes:** `monthly_total`, `capabilities[].monthly`, `share_last_full_month`, `run_rate_annual`. Partial months → compare `$/day`, never raw totals.
- **New cost lines:** `new_cost_line=true` with `first_nonzero_day` — top finding if material. Identify the source (e.g. `metric_keys[].source` for Metrics).
- **Spikes:** `outlier_days` per capability; drill in with a targeted query before explaining any spike.
- **Patterns:** `dow_skew` (e.g. RVA/RAP up on Fridays = weekly patch window).
- **Full-Stack value:** `fullstack.rows` grouped:
  | Group | Rule | Recommendation |
  |---|---|---|
  | A | 0 spans (7 one-day windows) and no app runtime | Move to Infrastructure |
  | B | 0 spans, app runtime present **or runtime data unavailable** | Validate role (standby/DR/idle?) then move; flag `crit_high` vulns — moving ends RVA coverage |
  | C | < 5,000 spans / 7d | Validate then move |
  | D | Actively traced | Keep |
  Use `other_tech`, `exes`, and host names to state the observed role (Citrix, DC, SQL…) — only what the data shows. Host-level Davis problems (`host_probs90d`) are covered by Infra mode; service/app problems are not.
- **Infra hygiene:** `infra.nonprod` is a name-regex *candidate* list — eyeball the names and drop false positives before quoting a number.
- **Synthetics:** top monitors by `share`; halving frequency ≈ halves that monitor's `annual`.
- **Metrics:** `metric_keys` top keys and sources; suggest disabling unused metric groups / lengthening polling.
- **Query spend:** `query_spend` by user/app/source (auto-refreshing dashboards are the usual cause). Emails are customer PII → placeholders under `-clean`.
- **RUM:** `rum_apps` month-over-month (e.g. Session Replay reduced = savings already realized).
- `unpriced_types`: call out as "not priced" rather than dropping silently.

Savings math (list): Full-Stack → Infra per host/yr = `fs_year − 350.40` (already in `save_year`). Synthetic/metric reductions = proportional share of `annual`.

## Phase 5 — Adversarial QA (mandatory before writing)

Write findings to `$W/draft.md`, then spawn **one** Sonnet subagent (model: sonnet) — after collection finishes, so dtctl stays serial:

> Adversarially QA `$W/draft.md` against tenant context `<ctx>` (already authenticated — do NOT log in or switch context). dtctl strictly serial, read-only, `--plain`, strip noise with `2>&1 | sed '/--- Query Metadata ---/,$d'`. Max ~12 queries. Independently re-derive: (1) every zero-span host claim using ≤1-day span windows, confirming no "stopped after" warning; (2) host roles vs actual processes; (3) the top 3 dollar figures from billing events; (4) any "new cost line" start date. Return a table: claim · verdict (CONFIRMED / WRONG / UNVERIFIED) · evidence query · correction.

Fix or remove everything not CONFIRMED. Multi-tenant: one QA agent per tenant, run sequentially.

## Phase 6 — Write the report

Structure (exec-summary first, clean tables, no fluff):

1. **Executive Summary** — run rate (list), overage framing (PowerBI if available), the 3–5 drivers, total est. savings and % of run rate, recommendation table `# · Recommendation · Est. annual savings (list) · Effort`.
2. **Context** — how DPS bills each capability; all figures at list.
3. **Where the Spend Goes** — monthly $ by capability + last-full-month share; one-line key point.
4. **Observed Changes and Anomalies** — `When · Observation · Impact`.
5. **Full-Stack Value Analysis** — groups A–D with host tables (Host · Role · Memory · Traces 7d · Vulns (C/H) · Savings/yr).
6. **Additional Recommendations** — Infra hygiene, synthetics, metrics, query dashboards, RUM.
7. **Suggested Next Steps** — this week / next 2 weeks / 30-day re-review.
8. **Methodology** — windows, data sources, "DPS list price", caveats (partial scans, missing runtime data, unpriced types).

Multi-tenant: one combined report — portfolio roll-up table first, then sections 3–6 per tenant.

Output:
- `format=md` → write `<out>/<Name>_DPS_Spend_Eval_<YYYY-MM-DD>.md`
- `format=html` → write the md to the scratchpad, then `python3 $S render --md <that.md> --html <out>/<Name>_DPS_Spend_Eval_<YYYY-MM-DD>.html`, then open it in a browser and render-check (tables, headings) before calling it done.
- `-clean` → scrub hostnames → `host-01…`, emails → `user-01@<customer>`, tenant IDs → `<tenant-id>`, entity IDs → `HOST-XXXX`; then `grep` the output for `HOST-[0-9A-F]{8}`, `@`, and the tenant ID to prove the scrub.

Finish with a 3–5 line summary in chat: run rate, top driver, total savings, file path.
