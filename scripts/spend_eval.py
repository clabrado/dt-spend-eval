#!/usr/bin/env python3
"""dt-spend-eval mechanical core: collect (serial dtctl), analyze (price + value buckets), render (md -> html).

Usage:
  spend_eval.py collect --context CTX --out DIR [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--host-days 14] [--span-days 7]
  spend_eval.py analyze --out DIR
  spend_eval.py render  --md FILE --html FILE [--title TITLE]

Stdlib only. dtctl queries run strictly serially (parallel dtctl races OAuth refresh and can delete the token file).
"""
import argparse, collections, datetime as dt, html, json, os, re, statistics, subprocess, sys

GiB = 1024 ** 3
# DPS list rates (USD per billed unit). Verify at dynatrace.com/pricing before customer delivery.
RATES = {
    "Full-Stack Monitoring": 0.01,                                  # GiB-hour
    "Infrastructure Monitoring": 0.04,                              # host-hour
    "Foundation & Discovery": 0.01,                                 # host-hour (verify)
    "Runtime Vulnerability Analytics": 0.00225,                     # GiB-hour
    "Runtime Application Protection": 0.00225,                      # GiB-hour
    "Real User Monitoring": 0.00225,                                # session
    "Real User Monitoring with Session Replay": 0.0045,             # replay session
    "Browser Monitor or Clickpath": 0.0045,                         # synthetic action
    "HTTP Monitor": 0.001,                                          # request (verify)
    "Log Management & Analytics - Ingest & Process": 0.20 / GiB,
    "Log Management & Analytics - Retain": 0.0007 / GiB / 24,       # hourly samples of retained bytes
    "Log Management & Analytics - Query": 0.0035 / GiB,
    "Traces - Ingest & Process": 0.20 / GiB,
    "Events - Ingest & Process": 0.20 / GiB,
    "Metrics - Ingest & Process": 0.15 / 1e5,                       # data point
    "Traces - Query": 0.0035 / GiB,
    "Events - Query": 0.0035 / GiB,
    "Traces - Retain": 0.0007 / GiB / 24,
    "Events - Retain": 0.0007 / GiB / 24,
}
INFRA_HOST_YEAR = 0.04 * 24 * 365
APP_TECH = {"JAVA", "DOTNET", "CLR", "DOTNET_CORE", "IIS", "NODE_JS", "PHP", "GO", "APACHE_HTTPD", "NGINX",
            "TOMCAT", "PYTHON", "RUBY", "JBOSS", "WEBSPHERE", "WEBLOGIC", "ASP_DOTNET", "ASP_DOTNET_CORE"}
NONPROD = [("DR", re.compile(r"_DR|DR\d|-DR\b", re.I)), ("test/dev", re.compile(r"TEST|\bDEV|UAT|QA\d|SANDBOX|TMMACHINE", re.I)),
           ("personal VM", re.compile(r"^[A-Z0-9]*VM(\.|$|\d)", re.I))]


# ---------------------------------------------------------------- collect
def q(ctx, name, dql, out, max_records=10000):
    path = os.path.join(out, f"{name}.json")
    p = subprocess.run(["dtctl", "query", dql, "--context", ctx, "--plain", "--no-agent", "-o", "json",
                        "--max-result-records", str(max_records)], capture_output=True, text=True)
    err = p.stderr.strip()
    try:
        d = json.loads(p.stdout)
        recs = d.get("records") if isinstance(d, dict) else d
        if recs is None and isinstance(d, dict):
            r = d.get("result", {})
            recs = r.get("records", r) if isinstance(r, dict) else r
        ok = isinstance(recs, list)
    except Exception:
        recs, ok = [], False
    partial = bool(re.search(r"stopped after|sampled|partial", err, re.I))
    json.dump({"records": recs or [], "ok": ok, "partial": partial, "stderr": err[:2000], "dql": dql}, open(path, "w"), indent=1)
    print(f"  {name:28} {'OK ' if ok else 'ERR'} rows={len(recs or []):<6}{' PARTIAL' if partial else ''}{'' if ok else '  ' + (err or p.stdout)[:300]}")
    return recs or [], ok, partial


def iso(d):
    return f'"{d.isoformat()}T00:00:00Z"'


def collect(a):
    os.makedirs(a.out, exist_ok=True)
    today = dt.date.today()
    until = dt.date.fromisoformat(a.until) if a.until else today - dt.timedelta(days=1)   # settled window
    since = dt.date.fromisoformat(a.since) if a.since else (until.replace(day=1) - dt.timedelta(days=100)).replace(day=1)
    hs = until - dt.timedelta(days=a.host_days)
    S, U, HS = iso(since), iso(until), iso(hs)
    BU = 'fetch dt.system.events, from:{f}, to:{t} | filter event.kind == "BILLING_USAGE_EVENT"'
    meta = dict(context=a.context, since=since.isoformat(), until=until.isoformat(), host_since=hs.isoformat(),
                host_days=a.host_days, span_days=a.span_days, collected=dt.datetime.now().isoformat(timespec="seconds"))
    json.dump(meta, open(os.path.join(a.out, "meta.json"), "w"), indent=1)
    print(f"[{a.context}] billing window {since}..{until}, host window {hs}..{until}")

    _, ok, _ = q(a.context, "probe", 'fetch dt.system.events | limit 1 | fields timestamp', a.out, 1)
    if not ok:
        sys.exit("dtctl probe failed — authenticate first: dtctl auth login --context <ctx> --environment <url>")

    q(a.context, "billing_types", BU.format(f=S, t=U) + " | summarize n = count(), first = min(timestamp), last = max(timestamp), by:{event.type} | sort n desc", a.out)
    q(a.context, "daily", BU.format(f=S, t=U) + """
| fieldsAdd day = bin(coalesce(usage.start, timestamp), 1d)
| fieldsAdd qty = coalesce(toDouble(billed_gibibyte_hours), toDouble(billed_host_hours), toDouble(billed_bytes), toDouble(data_points),
    toDouble(billed_sessions), toDouble(billed_replay_sessions), toDouble(billed_synthetic_action_count), toDouble(billed_request_count), toDouble(ingested_bytes))
| summarize qty = sum(qty), n = count(), by:{day, event.type}
| sort day asc""", a.out, 50000)
    q(a.context, "fs_hosts", BU.format(f=HS, t=U) + """ and event.type == "Full-Stack Monitoring"
| summarize u = sum(toDouble(billed_gibibyte_hours)), by:{h = dt.smartscape.host}
| lookup [smartscapeNodes HOST | fields id, name, os.type, cloud.provider], sourceField:h, lookupField:id, fields:{name, os.type, cloud.provider}
| sort u desc""", a.out)
    q(a.context, "infra_hosts", BU.format(f=HS, t=U) + """ and event.type == "Infrastructure Monitoring"
| summarize u = sum(toDouble(billed_host_hours)), by:{h = dt.smartscape.host}
| lookup [smartscapeNodes HOST | fields id, name], sourceField:h, lookupField:id, fields:{name}
| sort u desc""", a.out)
    q(a.context, "synth", BU.format(f=HS, t=U) + """ and event.type == "Browser Monitor or Clickpath"
| summarize a = sum(toDouble(billed_synthetic_action_count)), by:{m = dt.smartscape.browser_monitor}
| lookup [smartscapeNodes BROWSER_MONITOR | fields id, name], sourceField:m, lookupField:id, fields:{name}
| sort a desc""", a.out)
    q(a.context, "metrics_keys", f"""timeseries dp = sum(dt.sfm.metrics.ingest.datapoints, scalar:true), by:{{grail.metric.source, grail.metric.key, grail.metric.type}}, from:{HS}, to:{U}
| filter not startsWith(grail.metric.key, "dt.") or startsWith(grail.metric.key, "dt.service.") or startsWith(grail.metric.key, "dt.osservice.") or startsWith(grail.metric.key, "dt.cloud.")
| filter not startsWith(grail.metric.key, "legacy.containers.") and not startsWith(grail.metric.key, "legacy.dotnet.perform.") and not startsWith(grail.metric.key, "legacy.tomcat.")
| fieldsAdd billed = if(grail.metric.type == "histogram" and not startsWith(grail.metric.key, "dt.service."), dp * 10, else: dp)
| sort billed desc | limit 60""", a.out)
    q(a.context, "query_users", BU.format(f=HS, t=U) + """ and endsWith(event.type, " - Query")
| summarize gib = sum(toDouble(billed_bytes)) / 1073741824, n = count(), by:{event.type, user.email, client.application_context, src = client.source}
| sort gib desc | limit 25""", a.out)
    q(a.context, "rum_apps", BU.format(f=S, t=U) + """ and in(event.type, {"Real User Monitoring", "Real User Monitoring with Session Replay"})
| fieldsAdd mon = formatTimestamp(usage.start, format:"yyyy-MM")
| summarize s = sum(toDouble(coalesce(billed_sessions, billed_replay_sessions))), by:{event.type, app = dt.entity.application, mon}
| fieldsAdd appname = entityName(app, type:"dt.entity.application")""", a.out)
    q(a.context, "logs_bucket", BU.format(f=S, t=U) + """ and event.type == "Log Management & Analytics - Ingest & Process"
| fieldsAdd mon = formatTimestamp(usage.start, format:"yyyy-MM")
| summarize gib = sum(toDouble(billed_bytes)) / 1073741824, by:{usage.bucket, mon}""", a.out)
    q(a.context, "dow", BU.format(f=HS, t=U) + """ and in(event.type, {"Full-Stack Monitoring", "Runtime Vulnerability Analytics", "Runtime Application Protection", "Infrastructure Monitoring"})
| fieldsAdd dow = getDayOfWeek(usage.start), day = bin(usage.start, 1d)
| summarize u = sum(toDouble(coalesce(billed_gibibyte_hours, billed_host_hours))), days = countDistinct(day), by:{event.type, dow}""", a.out)

    # ---- Full-Stack value signals
    fs = json.load(open(os.path.join(a.out, "fs_hosts.json")))["records"]
    ids = [x["h"] for x in fs if x.get("h")]
    if not ids:
        print("  no Full-Stack hosts billed in host window — skipping value test")
        return
    IDS = ",".join(f'"{i}"' for i in ids)
    SIDS = ",".join(f'toSmartscapeId("{i}")' for i in ids)
    for i in range(a.span_days):   # 1-day windows: spans >~1d hit the 500 GB scan cap and go silently partial
        t0, t1 = until - dt.timedelta(days=i + 1), until - dt.timedelta(days=i)
        q(a.context, f"fs_spans_day{i}", f"""fetch spans, from:{iso(t0)}, to:{iso(t1)} | filter in(dt.entity.host, {{{IDS}}})
| summarize spans = count(), svc_names = collectDistinct(service.name, maxLength:10), exes = collectDistinct(process.executable.name, maxLength:10), by:{{dt.entity.host}}""", a.out)
    q(a.context, "fs_procs", f"""smartscapeNodes PROCESS | filter in(dt.smartscape.host, {{{SIDS}}})
| fieldsAdd tech = iCollectArray(process.software_technologies[][type]) | expand tech | filter isNotNull(tech)
| summarize procs = collectDistinct(name, maxLength:10), by:{{h = toString(dt.smartscape.host), host.name, tech}}""", a.out)
    q(a.context, "fs_vulns", f"""fetch security.events, from:now()-7d | filter event.provider == "Dynatrace" and event.type == "VULNERABILITY_STATE_REPORT_EVENT"
| expand h = related_entities.hosts.ids | filter in(h, {{{IDS}}})
| summarize vulns = countDistinct(vulnerability.id), crit_high = countDistinct(if(in(vulnerability.risk.level, {{"CRITICAL","HIGH"}}), vulnerability.id)), by:{{h}}""", a.out)
    q(a.context, "fs_attacks", 'fetch security.events, from:now()-30d | filter event.type == "DETECTION_FINDING" | summarize n = count(), by:{dt.entity.host}', a.out)
    q(a.context, "fs_probs", f"""fetch dt.davis.problems, from:now()-90d | expand e = affected_entity_ids | filter in(e, {{{IDS}}})
| summarize svc_app_probs = countDistinct(if(in(event.category, {{"ERROR","SLOWDOWN"}}), display_id)), host_probs = countDistinct(if(not in(event.category, {{"ERROR","SLOWDOWN"}}), display_id)), by:{{e}}""", a.out)
    q(a.context, "fs_util", f"""timeseries {{cpu = avg(dt.host.cpu.usage, scalar:true), mem = avg(dt.host.memory.usage, scalar:true)}}, by:{{dt.entity.host}}, from:now()-30d, filter: in(dt.entity.host, {{{IDS}}})""", a.out)


# ---------------------------------------------------------------- analyze
def L(out, name):
    p = os.path.join(out, f"{name}.json")
    if not os.path.exists(p):
        return [], False
    d = json.load(open(p))
    return d.get("records", []), d.get("partial", False)


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def analyze(a):
    out = a.out
    meta = json.load(open(os.path.join(out, "meta.json")))
    since, until = meta["since"], meta["until"]
    hd = meta["host_days"]
    res = {"meta": meta, "unpriced_types": set()}

    # monthly $ by capability
    mon = collections.defaultdict(lambda: collections.defaultdict(float))
    daily = collections.defaultdict(lambda: collections.defaultdict(float))
    days = collections.defaultdict(set)
    for x in L(out, "daily")[0]:
        d = (x.get("day") or "")[:10]
        if not d or d < since or d >= until:
            continue
        t = x["event.type"]
        if t not in RATES:
            res["unpriced_types"].add(t)
            continue
        c = num(x.get("qty")) * RATES[t]
        mon[t][d[:7]] += c; daily[t][d] += c; days[d[:7]].add(d)
    months = sorted(days)
    total = {m: sum(mon[t][m] for t in mon) for m in months}
    last_full = [m for m in months if len(days[m]) >= 28]
    all_days = sorted({d for t in daily for d in daily[t]})
    tail = all_days[-30:]
    run_rate_day = sum(daily[t][d] for t in daily for d in tail) / max(len(tail), 1)
    caps = []
    for t in sorted(mon, key=lambda t: -sum(mon[t].values())):
        nz = [d for d in all_days if daily[t].get(d, 0) > 0]
        first_nz = nz[0] if nz else None
        live = [d for d in all_days if first_nz and d >= first_nz]   # ignore pre-launch zero days
        vals = [daily[t].get(d, 0.0) for d in live]
        med = statistics.median(vals) if vals else 0
        mad = statistics.median([abs(v - med) for v in vals]) if vals else 0
        outliers = [(d, round(daily[t].get(d, 0.0))) for d in live
                    if abs(daily[t].get(d, 0.0) - med) > max(6 * mad, 0.25 * med, 1)]
        new_line = bool(first_nz and first_nz > all_days[0] and
                        all(daily[t].get(d, 0) == 0 for d in all_days[:7]))
        caps.append(dict(capability=t, monthly={m: round(mon[t][m]) for m in months},
                         last30_per_day=round(sum(daily[t].get(d, 0) for d in tail) / max(len(tail), 1), 2),
                         first_nonzero_day=first_nz, new_cost_line=new_line, median_day=round(med, 2),
                         outlier_days=outliers[:40], outlier_count=len(outliers)))
    last_share = last_full[-1] if last_full else (months[-1] if months else None)
    for c in caps:
        c["share_last_full_month"] = round(c["monthly"].get(last_share, 0) / total[last_share], 4) if last_share and total.get(last_share) else None
    res.update(months=months, days_per_month={m: len(days[m]) for m in months}, monthly_total={m: round(total[m]) for m in months},
               run_rate_per_day=round(run_rate_day, 2), run_rate_annual=round(run_rate_day * 365), capabilities=caps)

    # weekly trend of query spend (fast growers)
    # day-of-week skew
    dow = collections.defaultdict(dict)
    for x in L(out, "dow")[0]:
        dd = max(int(num(x.get("days"))), 1)
        dow[x["event.type"]][int(num(x.get("dow")))] = num(x.get("u")) / dd
    skew = []
    for t, m in dow.items():
        if len(m) < 5:
            continue
        med = statistics.median(m.values())
        for k, v in m.items():
            if med and v > 1.3 * med:
                skew.append(dict(capability=t, dow=k, per_day=round(v, 1), median=round(med, 1), ratio=round(v / med, 2)))
    res["dow_skew"] = skew

    # infra hygiene
    infra = []
    for x in L(out, "infra_hosts")[0]:
        n = x.get("name") or x.get("h") or "?"
        cls = next((c for c, rx in NONPROD if rx.search(n.split(".")[0])), None)
        per_year = num(x.get("u")) / hd * 365 * RATES["Infrastructure Monitoring"]
        infra.append(dict(name=n, id=x.get("h"), cls=cls, per_year=round(per_year)))
    np_ = [h for h in infra if h["cls"]]
    res["infra"] = dict(hosts=len(infra), annual=round(sum(h["per_year"] for h in infra)),
                        nonprod=np_, nonprod_annual=round(sum(h["per_year"] for h in np_)),
                        nonprod_by_class=dict(collections.Counter(h["cls"] for h in np_)))

    # synthetic
    syn = L(out, "synth")[0]
    st = sum(num(x.get("a")) for x in syn) or 1
    res["synthetic"] = [dict(name=x.get("name") or x.get("m"), actions_per_day=round(num(x.get("a")) / hd),
                             share=round(num(x.get("a")) / st, 4),
                             annual=round(num(x.get("a")) / hd * 365 * RATES["Browser Monitor or Clickpath"])) for x in syn]

    # metrics by key
    mk = L(out, "metrics_keys")[0]
    res["metric_keys"] = [dict(key=x.get("grail.metric.key"), source=x.get("grail.metric.source"), type=x.get("grail.metric.type"),
                               billed_dp_per_day=round(num(x.get("billed")) / hd),
                               annual=round(num(x.get("billed")) / hd * 365 * RATES["Metrics - Ingest & Process"])) for x in mk[:25]]
    # query spend
    res["query_spend"] = [dict(type=x.get("event.type"), user=x.get("user.email"), app=x.get("client.application_context"),
                               source=x.get("src"), gib=round(num(x.get("gib")), 1), queries=int(num(x.get("n"))),
                               cost=round(num(x.get("gib")) * GiB * RATES["Log Management & Analytics - Query"], 2))
                          for x in L(out, "query_users")[0]]
    # RUM by app/month
    rum = collections.defaultdict(dict)
    for x in L(out, "rum_apps")[0]:
        rum[(x.get("event.type"), x.get("appname") or x.get("app"))][x.get("mon")] = round(num(x.get("s")))
    res["rum_apps"] = [dict(type=k[0], app=k[1], monthly=v) for k, v in sorted(rum.items(), key=lambda kv: -sum(kv[1].values()))[:20]]

    # Full-Stack value buckets
    fsh = L(out, "fs_hosts")[0]
    sp = collections.defaultdict(lambda: dict(spans=0, days=0, svc=set(), exe=set()))
    span_partial = False
    span_days_ok = 0
    for i in range(meta["span_days"]):
        recs, partial = L(out, f"fs_spans_day{i}")
        if os.path.exists(os.path.join(out, f"fs_spans_day{i}.json")):
            span_days_ok += 1
        span_partial |= partial
        for x in recs:
            d = sp[x["dt.entity.host"]]; d["spans"] += int(num(x.get("spans"))); d["days"] += 1
            d["svc"].update(s for s in (x.get("svc_names") or []) if s); d["exe"].update(s for s in (x.get("exes") or []) if s)
    tech = collections.defaultdict(dict)
    procs_recs = L(out, "fs_procs")[0]
    tech_known = len(procs_recs) > 0   # some tenants expose no process.software_technologies at all
    for x in procs_recs:
        tech[x.get("h")][x.get("tech")] = x.get("procs") or []
    vul = {x["h"]: (int(num(x.get("vulns"))), int(num(x.get("crit_high")))) for x in L(out, "fs_vulns")[0]}
    att = {x.get("dt.entity.host"): int(num(x.get("n"))) for x in L(out, "fs_attacks")[0]}
    pr = {x["e"]: (int(num(x.get("svc_app_probs"))), int(num(x.get("host_probs")))) for x in L(out, "fs_probs")[0]}
    ut = {x.get("dt.entity.host"): x for x in L(out, "fs_util")[0]}
    rows = []
    for h in fsh:
        hid = h.get("h")
        if not hid:
            continue
        per_day = num(h.get("u")) / hd
        fs_year = per_day * 365 * RATES["Full-Stack Monitoring"]
        s = sp.get(hid); t = tech.get(hid, {}); v = vul.get(hid, (0, 0)); p = pr.get(hid, (0, 0)); u = ut.get(hid, {})
        app = sorted(k for k in t if k in APP_TECH)
        spans = s["spans"] if s else 0
        grp = ("A" if tech_known and not app else "B") if spans == 0 else "C" if spans < 5000 else "D"
        rows.append(dict(name=h.get("name") or hid, id=hid, gib=round(per_day / 24), fs_year=round(fs_year),
                         save_year=round(max(fs_year - INFRA_HOST_YEAR, 0)) if grp != "D" else 0, group=grp,
                         spans=spans, span_days=s["days"] if s else 0, services=sorted(s["svc"])[:5] if s else [],
                         exes=sorted(s["exe"])[:5] if s else [], app_tech=app, other_tech=sorted(k for k in t if k not in APP_TECH)[:6],
                         vulns=v[0], crit_high=v[1], attacks30d=att.get(hid, 0), svc_app_probs90d=p[0], host_probs90d=p[1],
                         cpu=round(num(u.get("cpu"))), mem=round(num(u.get("mem")))))
    groups = {g: dict(hosts=len([r for r in rows if r["group"] == g]), save_year=sum(r["save_year"] for r in rows if r["group"] == g),
                      fs_year=sum(r["fs_year"] for r in rows if r["group"] == g)) for g in "ABCD"}
    res["fullstack"] = dict(hosts=len(rows), rows=rows, groups=groups, span_scan_partial=span_partial, span_days_scanned=span_days_ok, tech_data_available=tech_known,
                            attacks_total=sum(att.values()))
    res["unpriced_types"] = sorted(res["unpriced_types"])
    json.dump(res, open(os.path.join(out, "analysis.json"), "w"), indent=1, default=list)

    # console summary
    print(f"Window {since}..{until} | run-rate ${res['run_rate_per_day']:,.0f}/day ≈ ${res['run_rate_annual']:,}/yr (DPS list)")
    print("Monthly $ by capability: " + " ".join(f"{m}={res['monthly_total'][m]:,}" for m in months))
    for c in caps[:12]:
        flag = " NEW" if c["new_cost_line"] else ""
        print(f"  {c['capability'][:46]:46} ${c['last30_per_day']:>8,.0f}/day  outliers={c['outlier_count']}{flag}")
    g = groups
    print(f"Full-Stack {len(rows)} hosts: A={g['A']['hosts']} (${g['A']['save_year']:,}) B={g['B']['hosts']} (${g['B']['save_year']:,}) "
          f"C={g['C']['hosts']} (${g['C']['save_year']:,}) D={g['D']['hosts']}{'  ⚠ SPAN SCAN PARTIAL' if span_partial else ''}{'' if tech_known else '  ⚠ no process-technology data: zero-span hosts put in B (validate)'}")
    print(f"Infra {res['infra']['hosts']} hosts, non-prod-by-name {len(np_)} (${res['infra']['nonprod_annual']:,}/yr)")
    if res["unpriced_types"]:
        print("Unpriced capability types (add rate or call out): " + ", ".join(res["unpriced_types"]))


# ---------------------------------------------------------------- render
CSS = """:root{--bg:#fff;--fg:#1b1f2a;--mut:#5b6475;--line:#e3e6ee;--acc:#1866FE;--head:#00092F;--zebra:#f6f8fc}
@media (prefers-color-scheme:dark){:root{--bg:#0b0f1a;--fg:#e6e9f2;--mut:#9aa3b5;--line:#252b3a;--acc:#5b93ff;--head:#e6e9f2;--zebra:#121828}}
body{background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,Segoe UI,Arial,sans-serif;margin:0}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}h1,h2,h3{color:var(--head);line-height:1.25}
h1{font-size:28px;border-bottom:3px solid var(--acc);padding-bottom:8px}h2{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}th{background:var(--zebra)}
tr:nth-child(even) td{background:var(--zebra)}code{background:var(--zebra);padding:1px 4px;border-radius:3px;font-size:13px}
pre{background:var(--zebra);padding:12px;overflow-x:auto;border-radius:6px}blockquote{border-left:4px solid var(--acc);margin:12px 0;padding:4px 14px;color:var(--mut)}
hr{border:0;border-top:1px solid var(--line);margin:28px 0}"""


def inline(s):
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<em>\1</em>", s)
    return s


def render(a):
    lines = open(a.md).read().splitlines()
    o, i, title = [], 0, a.title
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            j = i + 1; buf = []
            while j < len(lines) and not lines[j].startswith("```"):
                buf.append(lines[j]); j += 1
            o.append("<pre><code>" + html.escape("\n".join(buf)) + "</code></pre>"); i = j + 1; continue
        m = re.match(r"^(#{1,4})\s+(.*)", ln)
        if m:
            lvl = len(m.group(1)); title = title or (m.group(2) if lvl == 1 else None)
            o.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>"); i += 1; continue
        if ln.strip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]
            o.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells(ln)) + "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                o.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells(lines[i])) + "</tr>"); i += 1
            o.append("</tbody></table>"); continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", ln):
            tag = "ol" if re.match(r"^\s*\d+\.", ln) else "ul"; o.append(f"<{tag}>")
            while i < len(lines) and re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                o.append("<li>" + inline(re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i])) + "</li>"); i += 1
            o.append(f"</{tag}>"); continue
        if ln.startswith(">"):
            o.append("<blockquote>" + inline(ln.lstrip("> ")) + "</blockquote>"); i += 1; continue
        if re.match(r"^\s*(---|\*\*\*)\s*$", ln):
            o.append("<hr>"); i += 1; continue
        if ln.strip():
            buf = [ln]; i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||```|>|\s*([-*]|\d+\.)\s)", lines[i]):
                buf.append(lines[i]); i += 1
            o.append("<p>" + inline(" ".join(buf)) + "</p>"); continue
        i += 1
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f"<title>{html.escape(title or 'DPS Spend Evaluation')}</title><style>{CSS}</style></head><body><main>" + "\n".join(o) + "</main></body></html>")
    open(a.html, "w").write(doc)
    print(f"wrote {a.html}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect"); c.add_argument("--context", required=True); c.add_argument("--out", required=True)
    c.add_argument("--since"); c.add_argument("--until"); c.add_argument("--host-days", type=int, default=14); c.add_argument("--span-days", type=int, default=7)
    n = sub.add_parser("analyze"); n.add_argument("--out", required=True)
    r = sub.add_parser("render"); r.add_argument("--md", required=True); r.add_argument("--html", required=True); r.add_argument("--title")
    a = ap.parse_args()
    {"collect": collect, "analyze": analyze, "render": render}[a.cmd](a)
