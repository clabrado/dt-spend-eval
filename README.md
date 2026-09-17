# dt-spend-eval

A Claude Code skill that works out **why a Dynatrace Platform Subscription (DPS) tenant is spending what it spends, and where the savings are.** All it needs is a tenant URL.

It reads the tenant's billing records with [`dtctl`](https://github.com/dynatrace-oss/dtctl) and prices every capability at DPS list price. It flags new cost lines, spikes and weekly patterns, then breaks the biggest costs down by host, synthetic monitor, metric key, query user and RUM app. It also checks every Full-Stack host for real application value (traces, app runtimes, vulnerabilities, attacks, Davis problems, utilization) and recommends which hosts can move to Infrastructure mode. A second Claude agent re-runs the queries to try to disprove the findings before the report is written.

Output: an executive-ready report in **Markdown or HTML**.

---

## What you get

| Section | Contents |
|---|---|
| Executive summary | Annual run rate (list), top cost drivers, total estimated savings, recommendation table (action · $/yr · effort) |
| Where the spend goes | Monthly $ by capability and each capability's share |
| Changes & anomalies | New cost lines, daily outliers, day-of-week patterns |
| Full-Stack value analysis | Every Full-Stack host sorted into four groups: **A** move to Infra · **B** check role, then move · **C** barely traced · **D** keep |
| Additional recommendations | Non-production Infra hosts, synthetic frequency, metric groups, query-heavy dashboards, Session Replay |
| Next steps + methodology | Timeline, time windows, data sources, caveats |

## Requirements

| Need | Required |
|---|---|
| [Claude Code](https://claude.com/claude-code) | Yes |
| [`dtctl`](https://github.com/dynatrace-oss/dtctl) on `PATH` | Yes |
| Tenant user that can read `dt.system.events`, `spans`, `security.events`, `dt.davis.problems` | Yes |
| Python 3.9+ (standard library only) | Yes |
| `dt-dql-essentials` skill (from the Dynatrace skills package) | Recommended |
| PowerBI MCP exposing a `dynatrace_one_grid` tool (Dynatrace ONE dataset) | Optional: adds commit, consumption rate and forecast |

## Install

```bash
git clone https://github.com/clabrado/dt-spend-eval.git ~/.claude/skills/dt-spend-eval
```

(Or clone anywhere and symlink it into `~/.claude/skills/`.) Restart Claude Code; the skill appears as `/dt-spend-eval`.

## Usage

```
/dt-spend-eval <tenant> [<tenant> ...] [format=md|html] [since=YYYY-MM-DD] [until=YYYY-MM-DD]
               [account="<account name>"] [out=<dir>] [-clean]
```

| Arg | Default | Notes |
|---|---|---|
| `<tenant>` | required | `https://abc12345.apps.dynatrace.com`, `abc12345`, or a dtctl context name. Repeat for a multi-tenant roll-up. |
| `format=` | `md` | `md` or `html` (self-contained, light/dark) |
| `since=` / `until=` | ~4 months back / yesterday | Billing window. Billing lags ~1 day, so `until` should be ≥ 24h ago. |
| `account=` | — | Turns on the optional PowerBI step |
| `out=` | current directory | Where the report is written |
| `-clean` | off | Replaces hostnames, emails, tenant IDs and entity IDs with placeholders |

### Examples

```
/dt-spend-eval https://abc12345.apps.dynatrace.com
/dt-spend-eval abc12345 format=html since=2026-05-01
/dt-spend-eval abc12345 def67890 format=html account="Example Corp" -clean
```

If the tenant isn't authenticated yet, the skill runs `dtctl auth login` (OAuth, browser SSO) for you.

### Running the engine without Claude

The data collection and math are a plain Python script, so you can run or audit them yourself:

```bash
S=scripts/spend_eval.py
dtctl auth login --context abc12345 --environment https://abc12345.apps.dynatrace.com
python3 $S collect --context abc12345 --out ./work          # ~20 read-only queries, run one at a time
python3 $S analyze --out ./work                             # -> ./work/analysis.json + console summary
python3 $S render  --md report.md --html report.html        # Markdown -> styled HTML
```

## How it works

```
tenant ──dtctl (OAuth)──► collect ──► analyze ──► Claude interprets ──► adversarial QA ──► report (.md/.html)
            one query       billing events     list pricing,        new cost lines,        a Sonnet agent
            at a time       spans, processes,  outliers, Full-Stack spikes, roles,         re-runs the queries
                            vulns, problems    host groups          recommendations        to disprove claims
```

**DPS list rates used** (verify at [dynatrace.com/pricing](https://www.dynatrace.com/pricing/)):

| Capability | Rate |
|---|---|
| Full-Stack Monitoring | $0.01 / GiB-hour |
| Infrastructure Monitoring | $0.04 / host-hour |
| Runtime Vulnerability Analytics / Application Protection | $0.00225 / GiB-hour |
| Real User Monitoring / with Session Replay | $0.00225 / $0.0045 per session |
| Browser Monitor or Clickpath | $0.0045 / action |
| Logs / Traces / Events: Ingest & Process | $0.20 / GiB |
| Logs: Retain | $0.0007 / GiB-day |
| Query | $0.0035 / GiB scanned |
| Metrics: Ingest & Process | $0.15 / 100k data points |

All figures are **list price**. Contracted rates are lower, but the relative savings are the same.

## Guardrails built in

- **`dtctl` runs one query at a time.** Running dtctl in parallel can corrupt the OAuth token file.
- **Read-only.** The skill never changes anything in the tenant.
- **Span checks use 1-day windows.** Longer windows can hit Grail's scan limit and silently return partial results. Partial scans are flagged.
- **Missing process-technology data isn't treated as "no app runtime".** Those hosts go to group B for manual checking.
- **Metric costs by key follow the documented billability rules.** Most `dt.*` metrics aren't billed, and histograms count ×10.
- **Log Retain usage is recorded hourly and divided by 24.**

See [`references/queries.md`](references/queries.md) for the full query library and gotchas.

## Repo layout

```
SKILL.md                  skill definition (phases, rules, report structure)
scripts/spend_eval.py     collect | analyze | render   (stdlib only)
references/queries.md     DQL library, unit fields, rates, gotchas
```

## Disclaimer

Community tool, not an official Dynatrace product. Estimates use list pricing and telemetry heuristics. Validate recommendations with the customer before changing monitoring modes.
