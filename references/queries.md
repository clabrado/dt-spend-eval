# dt-spend-eval — Query library & gotchas

All queries below are what `scripts/spend_eval.py collect` runs (placeholders: `<S>` billing start,
`<U>` settled end, `<HS>` host-window start, `<IDS>` quoted `HOST-…` list). Use them for ad-hoc
drill-downs and QA.

## Billing meter (source of truth for $)

```dql
fetch dt.system.events, from:"<S>", to:"<U>"
| filter event.kind == "BILLING_USAGE_EVENT"
| summarize n = count(), first = min(timestamp), last = max(timestamp), by:{event.type}
```

Unit fields by `event.type`:

| event.type | Field | List rate |
|---|---|---|
| Full-Stack Monitoring | billed_gibibyte_hours | $0.01 / GiB-h |
| Infrastructure Monitoring | billed_host_hours | $0.04 / host-h |
| Runtime Vulnerability Analytics / Runtime Application Protection | billed_gibibyte_hours | $0.00225 / GiB-h |
| Real User Monitoring | billed_sessions | $0.00225 / session |
| Real User Monitoring with Session Replay | billed_replay_sessions | $0.0045 / session |
| Browser Monitor or Clickpath | billed_synthetic_action_count | $0.0045 / action |
| Log/Traces/Events - Ingest & Process | billed_bytes | $0.20 / GiB |
| Log - Retain | billed_bytes (hourly samples, ÷24) | $0.0007 / GiB-day |
| * - Query | billed_bytes (+ user.email, client.source) | $0.0035 / GiB |
| Metrics - Ingest & Process | data_points | $0.15 / 100k |

Verify rates at dynatrace.com/pricing before delivery. Useful dimensions on billing events:
`dt.smartscape.host`, `dt.smartscape.browser_monitor`, `dt.entity.application`, `usage.bucket`,
`user.email`, `client.application_context`, `client.source`, `usage.start`.

## Drill-downs

Host (Full-Stack / Infra):
```dql
fetch dt.system.events, from:"<HS>", to:"<U>"
| filter event.kind == "BILLING_USAGE_EVENT" and event.type == "Full-Stack Monitoring"
| summarize u = sum(toDouble(billed_gibibyte_hours)), by:{h = dt.smartscape.host}
| lookup [smartscapeNodes HOST | fields id, name, os.type, cloud.provider], sourceField:h, lookupField:id, fields:{name, os.type, cloud.provider}
| sort u desc
```

Metric keys (billing meter has no key dimension → SFM + billability rules; reconciles ≈0.5%):
```dql
timeseries dp = sum(dt.sfm.metrics.ingest.datapoints, scalar:true), by:{grail.metric.source, grail.metric.key, grail.metric.type}, from:"<HS>", to:"<U>"
| filter not startsWith(grail.metric.key, "dt.") or startsWith(grail.metric.key, "dt.service.") or startsWith(grail.metric.key, "dt.osservice.") or startsWith(grail.metric.key, "dt.cloud.")
| fieldsAdd billed = if(grail.metric.type == "histogram" and not startsWith(grail.metric.key, "dt.service."), dp * 10, else: dp)
| sort billed desc | limit 60
```
`grail.metric.source == null` is usually cloud integrations (`cloud.azure.*`) — classify by key prefix.

## Full-Stack value signals

| Signal | Query |
|---|---|
| Spans (per 1-day window) | `fetch spans, from:"<D>", to:"<D+1>" \| filter in(dt.entity.host, {<IDS>}) \| summarize spans=count(), exes=collectDistinct(process.executable.name, maxLength:10), by:{dt.entity.host}` |
| Runtimes | `smartscapeNodes PROCESS \| filter in(dt.smartscape.host, {toSmartscapeId("HOST-…")}) \| fieldsAdd tech = iCollectArray(process.software_technologies[][type]) \| expand tech \| summarize procs=collectDistinct(name, maxLength:10), by:{h=toString(dt.smartscape.host), host.name, tech}` |
| Vulns 7d | `fetch security.events, from:now()-7d \| filter event.provider=="Dynatrace" and event.type=="VULNERABILITY_STATE_REPORT_EVENT" \| expand h = related_entities.hosts.ids \| filter in(h, {<IDS>}) \| summarize vulns=countDistinct(vulnerability.id), by:{h}` |
| Attacks 30d | `fetch security.events, from:now()-30d \| filter event.type == "DETECTION_FINDING" \| summarize n=count(), by:{dt.entity.host}` |
| Problems 90d | `fetch dt.davis.problems, from:now()-90d \| expand e = affected_entity_ids \| filter in(e, {<IDS>}) \| summarize svc_app=countDistinct(if(in(event.category,{"ERROR","SLOWDOWN"}), display_id)), by:{e}` |
| Utilization 30d | `timeseries {cpu=avg(dt.host.cpu.usage, scalar:true), mem=avg(dt.host.memory.usage, scalar:true)}, by:{dt.entity.host}, from:now()-30d, filter: in(dt.entity.host, {<IDS>})` |

Process-by-name check (when roles are unclear):
```dql
smartscapeNodes PROCESS | filter matchesValue(host.name, "<HOSTPREFIX>*")
| summarize hosts = countDistinct(host.name), by:{name}
| sort hosts desc
```

## Gotchas

| Trap | Fix |
|---|---|
| Parallel dtctl deletes the OAuth token file | Serial only, including subagents |
| `fetch spans` > ~1 day → 500 GB scan cap, silent partial | 1-day windows; check stderr "stopped after" |
| Log Retain events are hourly samples | ÷24 |
| `timeseries count(metric)` = cardinality | Use SFM datapoints |
| Trailing window reads 4–10% high | `until` ≥ 24h ago |
| `dtctl -o json` may be agent-wrapped | pass `--no-agent`; rows under `records` |
| Some tenants have no `process.software_technologies` | Treat runtime as unknown (script puts zero-span hosts in group B) |
| smartscape vs entity IDs | Billing uses `dt.smartscape.host`; wrap with `toSmartscapeId()` in `smartscapeNodes` filters |
| PowerBI `account_filter` substring match | Confirm exact account row |
