#!/usr/bin/env python3
"""
generate_report.py - automated Threat Intelligence report from Elasticsearch.

Queries the last N hours (default 24) of enriched honeypot events, summarises the top
Indicators of Compromise (IPs, malware hashes, URLs, credentials, commands, ATT&CK
techniques) and writes an executive summary as Markdown, HTML and PDF plus machine-readable
IOC exports (CSV + plain IP blocklist).

Layers (each testable on its own):
    build_*           Elasticsearch DSL  (query layer)
    ElasticsearchSource.fetch()  ->  report dict  (parse layer, pure function `parse_report`)
    render_markdown / render_html / render_pdf   (presentation layer)
    export_iocs       CSV + blocklist
    run_once / run_daily_loop    (automation layer)

Credentials come from the environment (ES_URL, ES_USER, ES_PASSWORD [, ES_CA_CERT,
ES_VERIFY_CERTS]) - never from the command line, so they do not end up in shell history.

Examples
    python generate_report.py --hours 24 --out ./reports
    python generate_report.py --hours 168 --formats md,html
    python generate_report.py --daily-at 07:00          # long-running scheduler (used by the `reporter` container)
    python generate_report.py --print-query             # show the Elasticsearch DSL and exit
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape as xml_escape

INDEX = "honeypot-cowrie-*"
HIGH_RISK = 70
VERDICT_ORDER = ["malicious", "suspicious", "unknown", "clean", "benign", "not_applicable"]


# =============================================================================
# 1. QUERY LAYER
# =============================================================================
def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_query(start: datetime, end: datetime, exclude_simulated: bool = False) -> dict:
    q: dict = {"bool": {"filter": [{"range": {"@timestamp": {"gte": iso(start), "lt": iso(end)}}}]}}
    if exclude_simulated:
        q["bool"]["must_not"] = [{"term": {"tags": "simulated"}}]
    return q


def _ip_sub_aggs() -> dict:
    return {
        "sessions": {"cardinality": {"field": "cowrie.session"}},
        "max_risk": {"max": {"field": "event.risk_score"}},
        "ti_score": {"max": {"field": "ti.score"}},
        "country": {"terms": {"field": "source.geo.country_name", "size": 1}},
        "asn_org": {"terms": {"field": "source.as.organization.name", "size": 1}},
        "verdict": {"terms": {"field": "ti.verdict", "size": 1}},
        "latest": {"top_hits": {
            "size": 1, "sort": [{"@timestamp": "desc"}],
            "_source": {"includes": ["ti.abuseipdb.confidence_score", "ti.otx.pulse_count", "ti.otx.tags",
                                     "ti.virustotal.malicious", "source.as.number"]}}},
    }


def build_aggs(start: datetime, end: datetime, interval: str = "1h") -> dict:
    ms = lambda d: int(d.timestamp() * 1000)  # noqa: E731
    return {
        "actions": {"terms": {"field": "event.action", "size": 30}},
        "unique_ips": {"cardinality": {"field": "source.ip"}},
        "sessions": {"cardinality": {"field": "cowrie.session"}},
        "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0,
                                        "extended_bounds": {"min": ms(start), "max": ms(end)}}},
        "risk_levels": {"terms": {"field": "event.risk_level", "size": 5}},
        "top_ips_risk": {"terms": {"field": "source.ip", "size": 15, "order": {"max_risk": "desc"}},
                         "aggs": _ip_sub_aggs()},
        "top_ips_volume": {"terms": {"field": "source.ip", "size": 10}, "aggs": _ip_sub_aggs()},
        "countries": {"terms": {"field": "source.geo.country_name", "size": 10},
                      "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
        "asns": {"terms": {"field": "source.as.organization.name", "size": 10},
                 "aggs": {"ips": {"cardinality": {"field": "source.ip"}},
                          "max_risk": {"max": {"field": "event.risk_score"}}}},
        "ports": {"filter": {"term": {"event.action": "cowrie.session.connect"}},
                  "aggs": {"t": {"terms": {"field": "destination.port", "size": 10}}}},
        "protocols": {"filter": {"term": {"event.action": "cowrie.session.connect"}},
                      "aggs": {"t": {"terms": {"field": "network.protocol", "size": 5}}}},
        "usernames": {"terms": {"field": "cowrie.username", "size": 10}},
        "passwords": {"terms": {"field": "cowrie.password", "size": 10}},
        "credentials": {"terms": {"field": "cowrie.credential", "size": 10}},
        "commands": {"terms": {"field": "cowrie.input", "size": 15}},
        "techniques": {"terms": {"field": "threat.technique.id", "size": 12},
                       "aggs": {"name": {"terms": {"field": "threat.technique.name", "size": 1}}}},
        "malware": {"terms": {"field": "cowrie.shasum", "size": 10},
                    "aggs": {"urls": {"terms": {"field": "cowrie.url", "size": 3}},
                             "vt": {"max": {"field": "ti.file.malicious"}},
                             "family": {"terms": {"field": "ti.file.threat_label", "size": 1}},
                             "ips": {"cardinality": {"field": "source.ip"}}}},
        "urls": {"terms": {"field": "cowrie.url", "size": 10}},
        "hassh": {"terms": {"field": "cowrie.hassh", "size": 8},
                  "aggs": {"client": {"terms": {"field": "cowrie.client_version", "size": 1}},
                           "ips": {"cardinality": {"field": "source.ip"}}}},
        "verdicts": {"terms": {"field": "ti.verdict", "size": 8},
                     "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
        "otx_tags": {"terms": {"field": "ti.otx.tags", "size": 12}},
        "malicious_ips": {"filter": {"term": {"ti.verdict": "malicious"}},
                          "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
        "high_risk": {"filter": {"range": {"event.risk_score": {"gte": HIGH_RISK}}},
                      "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
        "simulated": {"filter": {"term": {"tags": "simulated"}}},
    }


def build_prev_aggs() -> dict:
    return {
        "unique_ips": {"cardinality": {"field": "source.ip"}},
        "high_risk": {"filter": {"range": {"event.risk_score": {"gte": HIGH_RISK}}}},
        "malicious_ips": {"filter": {"term": {"ti.verdict": "malicious"}},
                          "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}},
    }


# =============================================================================
# 2. PARSE LAYER
# =============================================================================
def _buckets(agg):
    return (agg or {}).get("buckets", [])


def _val(node, name):
    v = (node.get(name) or {}).get("value")
    return 0 if v is None else v


def _top(node, name):
    b = _buckets(node.get(name))
    return b[0]["key"] if b else None


def _kv(agg, size=None):
    out = [{"key": b["key"], "count": b["doc_count"]} for b in _buckets(agg)]
    return out[:size] if size else out


def _total(resp) -> int:
    t = resp.get("hits", {}).get("total", 0)
    return t.get("value", 0) if isinstance(t, dict) else int(t)


def _ip_row(b: dict) -> dict:
    hits = ((b.get("latest") or {}).get("hits") or {}).get("hits") or []
    src = hits[0].get("_source", {}) if hits else {}
    ti = src.get("ti", {}) or {}
    return {
        "ip": b["key"], "events": b["doc_count"], "sessions": int(_val(b, "sessions")),
        "max_risk": int(_val(b, "max_risk")), "ti_score": int(_val(b, "ti_score")),
        "country": _top(b, "country") or "Unknown", "asn_org": _top(b, "asn_org") or "Unknown",
        "asn": (src.get("source", {}).get("as", {}) or {}).get("number"),
        "verdict": _top(b, "verdict") or "unknown",
        "abuse_score": (ti.get("abuseipdb") or {}).get("confidence_score"),
        "otx_pulses": (ti.get("otx") or {}).get("pulse_count"),
        "vt_malicious": (ti.get("virustotal") or {}).get("malicious"),
        "tags": ((ti.get("otx") or {}).get("tags") or [])[:4],
    }


def threat_level(t: dict) -> str:
    if t["critical_events"] > 0:
        return "CRITICAL"
    if t["high_risk_events"] > 0:
        return "HIGH"
    if t["login_success"] > 0:
        return "MEDIUM"
    return "LOW"


def pct_change(cur, prev):
    if not prev:
        return None
    return round((cur - prev) * 100.0 / prev, 1)


def parse_report(resp: dict, prev: dict, start: datetime, end: datetime, hours: float, exclude_simulated: bool) -> dict:
    a = resp.get("aggregations", {})
    actions = {b["key"]: b["doc_count"] for b in _buckets(a.get("actions"))}
    risk_levels = {b["key"]: b["doc_count"] for b in _buckets(a.get("risk_levels"))}
    pa = prev.get("aggregations", {})
    totals = {
        "events": _total(resp),
        "unique_ips": int(_val(a, "unique_ips")),
        "sessions": int(_val(a, "sessions")),
        "login_failed": actions.get("cowrie.login.failed", 0),
        "login_success": actions.get("cowrie.login.success", 0),
        "commands": actions.get("cowrie.command.input", 0),
        "downloads": actions.get("cowrie.session.file_download", 0),
        "uploads": actions.get("cowrie.session.file_upload", 0),
        "high_risk_events": (a.get("high_risk") or {}).get("doc_count", 0),
        "high_risk_ips": int(_val((a.get("high_risk") or {}), "ips")),
        "critical_events": risk_levels.get("critical", 0),
        "malicious_ips": int(_val((a.get("malicious_ips") or {}), "ips")),
    }
    totals["login_attempts"] = totals["login_failed"] + totals["login_success"]
    previous = {
        "events": _total(prev), "unique_ips": int(_val(pa, "unique_ips")),
        "high_risk_events": (pa.get("high_risk") or {}).get("doc_count", 0),
        "malicious_ips": int(_val((pa.get("malicious_ips") or {}), "ips")),
    }
    timeline = [{"ts": b["key"], "label": b.get("key_as_string", ""), "count": b["doc_count"]}
                for b in _buckets(a.get("timeline"))]

    report = {
        "meta": {
            "generated_at": iso(datetime.now(timezone.utc)), "start": iso(start), "end": iso(end),
            "hours": hours, "index": INDEX, "exclude_simulated": exclude_simulated,
            "simulated_events": (a.get("simulated") or {}).get("doc_count", 0),
        },
        "totals": totals, "previous": previous,
        "deltas": {k: pct_change(totals[k], previous[k]) for k in previous},
        "timeline": timeline,
        "top_ips_risk": [_ip_row(b) for b in _buckets(a.get("top_ips_risk"))],
        "top_ips_volume": [_ip_row(b) for b in _buckets(a.get("top_ips_volume"))],
        "countries": [{"key": b["key"], "count": b["doc_count"], "ips": int(_val(b, "ips"))} for b in _buckets(a.get("countries"))],
        "asns": [{"key": b["key"], "count": b["doc_count"], "ips": int(_val(b, "ips")), "max_risk": int(_val(b, "max_risk"))}
                 for b in _buckets(a.get("asns"))],
        "ports": _kv((a.get("ports") or {}).get("t")),
        "protocols": _kv((a.get("protocols") or {}).get("t")),
        "usernames": _kv(a.get("usernames")), "passwords": _kv(a.get("passwords")),
        "credentials": _kv(a.get("credentials")), "commands": _kv(a.get("commands")),
        "techniques": [{"id": b["key"], "name": _top(b, "name") or "", "count": b["doc_count"]} for b in _buckets(a.get("techniques"))],
        "malware": [{"sha256": b["key"], "events": b["doc_count"], "ips": int(_val(b, "ips")),
                     "vt_malicious": int(_val(b, "vt")), "family": _top(b, "family") or "",
                     "urls": [u["key"] for u in _buckets(b.get("urls"))]} for b in _buckets(a.get("malware"))],
        "urls": _kv(a.get("urls")),
        "hassh": [{"hash": b["key"], "count": b["doc_count"], "ips": int(_val(b, "ips")), "client": _top(b, "client") or ""}
                  for b in _buckets(a.get("hassh"))],
        "verdicts": [{"key": b["key"], "count": b["doc_count"], "ips": int(_val(b, "ips"))} for b in _buckets(a.get("verdicts"))],
        "otx_tags": _kv(a.get("otx_tags")),
        "risk_levels": risk_levels,
    }
    report["threat_level"] = threat_level(totals)
    report["summary"] = executive_summary(report)
    report["recommendations"] = recommendations(report)
    return report


def executive_summary(r: dict) -> list:
    t, d, lines = r["totals"], r["deltas"], []

    def delta(k):
        v = d.get(k)
        return "" if v is None else f" ({v:+.1f}% vs previous period)"

    lines.append(f"The honeypot recorded {t['events']:,} events from {t['unique_ips']:,} unique source IPs in the last "
                 f"{r['meta']['hours']:g} hours{delta('unique_ips')}.")
    if r["countries"]:
        top = ", ".join(f"{c['key']} ({c['count']:,})" for c in r["countries"][:3])
        lines.append(f"Top origin countries by event volume: {top}.")
    if r["timeline"]:
        peak = max(r["timeline"], key=lambda x: x["count"])
        if peak["count"]:
            lines.append(f"Attack volume peaked at {peak['count']:,} events in the hour starting {peak['label'] or peak['ts']}.")
    if r["top_ips_risk"]:
        x = r["top_ips_risk"][0]
        lines.append(f"Highest-risk source: {x['ip']} ({x['country']}, {x['asn_org']}) - max risk {x['max_risk']}/100, "
                     f"{x['events']:,} events, TI verdict '{x['verdict']}'.")
    lines.append(f"{t['malicious_ips']:,} source IPs were rated 'malicious' by threat intelligence and {t['high_risk_events']:,} "
                 f"events scored >= {HIGH_RISK} risk ({t['critical_events']:,} critical){delta('high_risk_events')}.")
    if t["login_attempts"]:
        lines.append(f"{t['login_attempts']:,} login attempts were made; {t['login_success']:,} succeeded against the "
                     f"honeypot's deliberately weak accounts, after which attackers ran {t['commands']:,} shell commands.")
    if t["downloads"]:
        lines.append(f"{t['downloads']:,} malware download attempts were captured: {len(r['malware'])} distinct sample hash(es) "
                     f"and {len(r['urls'])} distinct payload URL(s).")
    if r["credentials"]:
        c = r["credentials"][0]
        lines.append(f"Most common credential pair: '{c['key']}' ({c['count']:,} attempts).")
    if r["meta"]["simulated_events"]:
        lines.append(f"NOTE: {r['meta']['simulated_events']:,} of these events are SIMULATED demo traffic (tag 'simulated'); "
                     f"their threat-intel enrichment is synthetic.")
    return lines


def recommendations(r: dict) -> list:
    recs = []
    block = [x for x in r["top_ips_risk"] if x["verdict"] in ("malicious", "suspicious") or x["max_risk"] >= HIGH_RISK]
    if block:
        recs.append(f"Block or rate-limit the {len(block)} high-risk source IPs listed in the IOC export "
                    f"(blocklist file). IPs with verdict 'benign' (CDNs, search engines, whitelisted scanners) are excluded "
                    f"to avoid false positives.")
    if r["totals"]["login_success"]:
        recs.append("Audit production SSH/Telnet for the credential pairs seen here; disable password authentication, "
                    "enforce keys/MFA and remove default accounts (root, admin, pi, ubuntu).")
    if r["malware"]:
        recs.append("Search EDR/SIEM for the listed SHA-256 hashes and download URLs; add the URLs to egress/web-proxy deny lists.")
    if r["hassh"]:
        recs.append("Alert on the listed HASSH client fingerprints in production SSH logs - they identify attacker tooling "
                    "independent of source IP.")
    if any(t["id"] in ("T1098.004", "T1053.003") for t in r["techniques"]):
        recs.append("Attackers attempted persistence (SSH authorized_keys / cron): monitor those paths with file-integrity monitoring.")
    if not recs:
        recs.append("No high-risk activity in this period. Keep monitoring and review the top sources for early indicators.")
    return recs


class ElasticsearchSource:
    def __init__(self, client, index: str = INDEX):
        self.client, self.index = client, index

    def fetch(self, hours: float, exclude_simulated: bool = False, now: datetime | None = None) -> dict:
        end = now or datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        interval = "1h" if hours <= 72 else "1d"
        cur = self.client.search(index=self.index, size=0, track_total_hits=True,
                                 query=build_query(start, end, exclude_simulated), aggs=build_aggs(start, end, interval))
        pstart = start - timedelta(hours=hours)
        prev = self.client.search(index=self.index, size=0, track_total_hits=True,
                                  query=build_query(pstart, start, exclude_simulated), aggs=build_prev_aggs())
        return parse_report(cur, prev, start, end, hours, exclude_simulated)


def make_client():
    from elasticsearch import Elasticsearch

    url = os.environ.get("ES_URL", "http://localhost:9200")
    kw = {"request_timeout": 60}
    user, pwd = os.environ.get("ES_USER"), os.environ.get("ES_PASSWORD")
    if user and pwd:
        kw["basic_auth"] = (user, pwd)
    if url.startswith("https"):
        if os.environ.get("ES_CA_CERT"):
            kw["ca_certs"] = os.environ["ES_CA_CERT"]
        kw["verify_certs"] = os.environ.get("ES_VERIFY_CERTS", "true").lower() != "false"
    return Elasticsearch(url, **kw)


# =============================================================================
# 3. PRESENTATION LAYER
# =============================================================================
def fmt_ts(s: str) -> str:
    return s.replace("T", " ").replace(".000Z", " UTC")


def short(s, n=70) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def md_cell(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def md_table(headers, rows) -> str:
    if not rows:
        return "_No data in this period._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(out) + "\n"


def _ip_table_rows(rows):
    return [[x["ip"], x["country"], short(x["asn_org"], 28), x["events"], x["max_risk"], x["verdict"],
             "-" if x["abuse_score"] is None else x["abuse_score"], ", ".join(x["tags"]) or "-"] for x in rows]


IP_HEADERS = ["IP", "Country", "ASN org", "Events", "Max risk", "TI verdict", "AbuseIPDB", "Tags"]


def sections(r: dict):
    """Single definition of the report body, shared by the Markdown/HTML/PDF renderers."""
    t = r["totals"]
    yield "Key metrics", ("kv", [
        ("Total events", f"{t['events']:,}"), ("Unique attacker IPs", f"{t['unique_ips']:,}"),
        ("Attack sessions", f"{t['sessions']:,}"), ("Login attempts (success)", f"{t['login_attempts']:,} ({t['login_success']:,})"),
        ("Shell commands", f"{t['commands']:,}"), ("Malware downloads", f"{t['downloads']:,}"),
        ("High-risk events (>=70)", f"{t['high_risk_events']:,}"), ("Malicious IPs (TI)", f"{t['malicious_ips']:,}")])
    yield "Top 10 IOC source IPs (ranked by risk)", ("table", IP_HEADERS, _ip_table_rows(r["top_ips_risk"][:10]))
    yield "Top attackers by volume", ("table", IP_HEADERS, _ip_table_rows(r["top_ips_volume"][:10]))
    yield "Attack origin - countries", ("table", ["Country", "Events", "Unique IPs"],
                                        [[c["key"], c["count"], c["ips"]] for c in r["countries"]])
    yield "Top ASNs", ("table", ["ASN organisation", "Events", "Unique IPs", "Max risk"],
                       [[short(a["key"], 45), a["count"], a["ips"], a["max_risk"]] for a in r["asns"]])
    yield "Targeted ports and protocols", ("table", ["Port", "Connections"], [[p["key"], p["count"]] for p in r["ports"]])
    yield "Protocols", ("table", ["Protocol", "Connections"], [[p["key"], p["count"]] for p in r["protocols"]])
    yield "Credentials attempted", ("table", ["Username/password pair", "Attempts"],
                                    [[c["key"], c["count"]] for c in r["credentials"]])
    yield "Top usernames", ("table", ["Username", "Attempts"], [[c["key"], c["count"]] for c in r["usernames"]])
    yield "Top passwords", ("table", ["Password", "Attempts"], [[c["key"], c["count"]] for c in r["passwords"]])
    yield "Commands executed in the honeypot shell", ("table", ["Command", "Count"],
                                                      [[short(c["key"], 90), c["count"]] for c in r["commands"]])
    yield "Malware IOCs (SHA-256)", ("table", ["SHA-256", "Events", "IPs", "VT detections", "Family", "Source URL"],
                                     [[m["sha256"], m["events"], m["ips"], m["vt_malicious"], m["family"] or "-",
                                       short(m["urls"][0], 40) if m["urls"] else "-"] for m in r["malware"]])
    yield "Payload URLs", ("table", ["URL", "Downloads"], [[short(u["key"], 80), u["count"]] for u in r["urls"]])
    yield "MITRE ATT&CK techniques", ("table", ["ID", "Technique", "Events"],
                                      [[x["id"], x["name"], x["count"]] for x in r["techniques"]])
    yield "SSH client fingerprints (HASSH)", ("table", ["HASSH", "Client", "Events", "IPs"],
                                              [[h["hash"], h["client"] or "-", h["count"], h["ips"]] for h in r["hassh"]])
    yield "Threat-intel verdict distribution", ("table", ["Verdict", "Events", "Unique IPs"],
                                                [[v["key"], v["count"], v["ips"]] for v in r["verdicts"]])
    yield "OTX threat tags", ("table", ["Tag", "Events"], [[x["key"], x["count"]] for x in r["otx_tags"]])


def render_markdown(r: dict) -> str:
    m = r["meta"]
    out = [f"# Threat Intelligence Report", "",
           f"**Period:** {fmt_ts(m['start'])} -> {fmt_ts(m['end'])} ({m['hours']:g} h)  ",
           f"**Generated:** {fmt_ts(m['generated_at'])}  ", f"**Overall threat level:** **{r['threat_level']}**", "",
           "## Executive summary", ""]
    out += [f"- {s}" for s in r["summary"]]
    out += ["", "## Recommended actions", ""]
    out += [f"{i}. {s}" for i, s in enumerate(r["recommendations"], 1)]
    for title, body in sections(r):
        out += ["", f"## {title}", ""]
        if body[0] == "kv":
            out.append(md_table(["Metric", "Value"], body[1]))
        else:
            out.append(md_table(body[1], body[2]))
    out += ["", "---", "Risk score = round(0.6 x event severity + 0.4 x threat-intel score); "
            "TI score = max(AbuseIPDB confidence, 10 x VirusTotal detections, 10 x OTX pulses). "
            "Verdict: malicious >= 75, suspicious >= 25; CDN/whitelisted sources are 'benign'.", ""]
    return "\n".join(out)


def svg_bars(timeline, width=900, height=160) -> str:
    if not timeline:
        return ""
    vals = [p["count"] for p in timeline]
    mx = max(vals) or 1
    n = len(vals)
    bw = width / n
    bars = []
    for i, p in enumerate(timeline):
        h = (p["count"] / mx) * (height - 24)
        bars.append(f'<rect x="{i * bw + 1:.1f}" y="{height - 16 - h:.1f}" width="{max(bw - 2, 1):.1f}" height="{h:.1f}" '
                    f'fill="#2f6fed"><title>{html.escape(p["label"] or str(p["ts"]))}: {p["count"]}</title></rect>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Attack events per hour">'
            f'{"".join(bars)}<text x="0" y="{height - 2}" font-size="10" fill="#666">{html.escape(fmt_ts(timeline[0]["label"]))}</text>'
            f'<text x="{width}" y="{height - 2}" font-size="10" text-anchor="end" fill="#666">peak {mx:,}/interval</text></svg>')


HTML_CSS = """
:root{--bg:#fff;--fg:#1b2430;--muted:#5b6675;--line:#dfe4ea;--accent:#2f6fed;--card:#f6f8fb}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--fg:#e6ebf2;--muted:#9aa6b6;--line:#26303c;--accent:#6ea0ff;--card:#171e27}}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px}
main{max-width:1000px;margin:0 auto}h1{margin:0 0 4px}h2{margin:28px 0 8px;font-size:17px;border-bottom:1px solid var(--line);padding-bottom:4px}
.meta{color:var(--muted)}.level{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-weight:600}
.CRITICAL{background:#c62828}.HIGH{background:#e65100}.MEDIUM{background:#b58900}.LOW{background:#2e7d32}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}
.kpi b{display:block;font-size:20px}.kpi span{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--card)}td.n{font-variant-numeric:tabular-nums}.box{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px}
.warn{border-left:4px solid #e65100}
"""


def render_html(r: dict) -> str:
    m, e = r["meta"], html.escape
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Threat Intelligence Report</title><style>{HTML_CSS}</style></head><body><main>",
             "<h1>Threat Intelligence Report</h1>",
             f"<p class='meta'>Period {e(fmt_ts(m['start']))} &rarr; {e(fmt_ts(m['end']))} ({m['hours']:g} h) &middot; generated "
             f"{e(fmt_ts(m['generated_at']))} &middot; threat level <span class='level {r['threat_level']}'>{r['threat_level']}</span></p>"]
    if m["simulated_events"]:
        parts.append(f"<div class='box warn'><b>Demo data:</b> {m['simulated_events']:,} events in this period are simulated; "
                     f"their threat-intel enrichment is synthetic.</div>")
    parts.append("<h2>Executive summary</h2><ul>" + "".join(f"<li>{e(s)}</li>" for s in r["summary"]) + "</ul>")
    parts.append("<h2>Recommended actions</h2><ol>" + "".join(f"<li>{e(s)}</li>" for s in r["recommendations"]) + "</ol>")
    parts.append("<h2>Attack timeline</h2>" + svg_bars(r["timeline"]))
    for title, body in sections(r):
        parts.append(f"<h2>{e(title)}</h2>")
        if body[0] == "kv":
            parts.append("<div class='kpis'>" + "".join(f"<div class='kpi'><b>{e(v)}</b><span>{e(k)}</span></div>" for k, v in body[1]) + "</div>")
        elif not body[2]:
            parts.append("<p class='meta'>No data in this period.</p>")
        else:
            parts.append("<table><thead><tr>" + "".join(f"<th>{e(h)}</th>" for h in body[1]) + "</tr></thead><tbody>"
                         + "".join("<tr>" + "".join(f"<td{' class=n' if isinstance(c, int) else ''}>{e(str(c))}</td>" for c in row) + "</tr>"
                                   for row in body[2]) + "</tbody></table>")
    parts.append("<p class='meta'>Risk score = round(0.6 &times; event severity + 0.4 &times; TI score). Verdict: malicious &ge; 75, "
                 "suspicious &ge; 25; CDN/whitelisted sources are 'benign'.</p></main></body></html>")
    return "".join(parts)


def render_pdf(r: dict, path: str) -> None:
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    def clean(s):  # core PDF fonts are Latin-1 only
        return xml_escape(str(s).encode("latin-1", "replace").decode("latin-1"))

    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    cell = ParagraphStyle("c", parent=body, fontSize=7.5, leading=9.5)
    head = ParagraphStyle("h", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, spaceBefore=12, spaceAfter=4, textColor=colors.HexColor("#1b2430"))
    level_colors = {"CRITICAL": "#c62828", "HIGH": "#e65100", "MEDIUM": "#b58900", "LOW": "#2e7d32"}
    m = r["meta"]

    def tbl(headers, rows, widths=None):
        data = [[Paragraph(clean(h), head) for h in headers]] + [[Paragraph(clean(c), cell) for c in row] for row in rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2f6fed")),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5fa")]),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd6df")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        return t

    story = [Paragraph("Threat Intelligence Report", ss["Title"]),
             Paragraph(clean(f"Period {fmt_ts(m['start'])} -> {fmt_ts(m['end'])} ({m['hours']:g} h) | generated {fmt_ts(m['generated_at'])}"), body),
             Paragraph(f"Overall threat level: <font color='{level_colors[r['threat_level']]}'><b>{r['threat_level']}</b></font>", body)]
    if m["simulated_events"]:
        story.append(Paragraph(clean(f"Demo data: {m['simulated_events']:,} events are simulated; their threat-intel enrichment is synthetic."), body))
    story += [Paragraph("Executive summary", h2)] + [Paragraph("&bull; " + clean(s), body) for s in r["summary"]]
    story += [Paragraph("Recommended actions", h2)] + [Paragraph(f"{i}. " + clean(s), body) for i, s in enumerate(r["recommendations"], 1)]

    if r["timeline"]:
        story.append(Paragraph("Attack timeline (events per interval)", h2))
        d = Drawing(500, 130)
        ch = VerticalBarChart()
        ch.x, ch.y, ch.width, ch.height = 30, 20, 455, 100
        ch.data = [[p["count"] for p in r["timeline"]]]
        ch.bars[0].fillColor = colors.HexColor("#2f6fed")
        ch.bars.strokeColor = None
        ch.categoryAxis.labels.boxAnchor = "n"
        ch.categoryAxis.labels.fontSize = 6
        step = max(1, len(r["timeline"]) // 8)
        ch.categoryAxis.categoryNames = [(p["label"][11:16] if i % step == 0 and p["label"] else "") for i, p in enumerate(r["timeline"])]
        ch.valueAxis.labels.fontSize = 6
        ch.valueAxis.valueMin = 0
        d.add(ch)
        story.append(d)

    for title, b in sections(r):
        story.append(Paragraph(clean(title), h2))
        if b[0] == "kv":
            rows = b[1]
            data = [[Paragraph(f"<b>{clean(v)}</b><br/><font size=7 color='#5b6675'>{clean(k)}</font>", body) for k, v in rows[i:i + 4]]
                    for i in range(0, len(rows), 4)]
            t = Table(data, colWidths=[44 * mm] * 4)
            t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd6df")),
                                   ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd6df")),
                                   ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fb"))]))
            story.append(t)
        elif not b[2]:
            story.append(Paragraph("No data in this period.", body))
        else:
            story.append(tbl(b[1], b[2]))
        story.append(Spacer(1, 2))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5b6675"))
        canvas.drawString(15 * mm, 8 * mm, "Threat Intelligence Dashboard - automated report")
        canvas.drawRightString(195 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                      title="Threat Intelligence Report", author="Threat Intelligence Dashboard").build(story, onFirstPage=footer, onLaterPages=footer)


# =============================================================================
# 4. IOC EXPORT
# =============================================================================
def ioc_rows(r: dict) -> list:
    rows = []
    for x in r["top_ips_risk"]:
        rows.append({"type": "ipv6" if ":" in str(x["ip"]) else "ipv4", "indicator": x["ip"], "events": x["events"],
                     "max_risk": x["max_risk"], "verdict": x["verdict"], "abuse_score": x["abuse_score"] if x["abuse_score"] is not None else "",
                     "context": f"{x['country']} / {x['asn_org']}"})
    for m_ in r["malware"]:
        rows.append({"type": "sha256", "indicator": m_["sha256"], "events": m_["events"], "max_risk": "",
                     "verdict": "malicious" if m_["vt_malicious"] >= 5 else "unknown", "abuse_score": "",
                     "context": f"VT detections={m_['vt_malicious']} family={m_['family'] or '-'}"})
    for u in r["urls"]:
        rows.append({"type": "url", "indicator": u["key"], "events": u["count"], "max_risk": "", "verdict": "", "abuse_score": "", "context": "payload URL"})
    return rows


def blocklist(r: dict) -> list:
    """Only IPs that are risky AND not 'benign' (false-positive reduction)."""
    return sorted({x["ip"] for x in r["top_ips_risk"]
                   if x["verdict"] != "benign" and (x["verdict"] in ("malicious", "suspicious") or x["max_risk"] >= HIGH_RISK)})


def export_iocs(r: dict, out_dir: str, stamp: str) -> list:
    rows = ioc_rows(r)
    p_csv, p_txt = os.path.join(out_dir, f"iocs_{stamp}.csv"), os.path.join(out_dir, f"blocklist_ips_{stamp}.txt")
    with open(p_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type", "indicator", "events", "max_risk", "verdict", "abuse_score", "context"])
        w.writeheader()
        w.writerows(rows)
    with open(p_txt, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(blocklist(r)) + ("\n" if blocklist(r) else ""))
    return [p_csv, p_txt]


# =============================================================================
# 5. AUTOMATION LAYER
# =============================================================================
def write_reports(report: dict, out_dir: str, formats: list, stamp: str | None = None) -> list:
    os.makedirs(out_dir, exist_ok=True)
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    written = []
    def write_text(path, text):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    renderers = {"md": lambda p: write_text(p, render_markdown(report)),
                 "html": lambda p: write_text(p, render_html(report)),
                 "pdf": lambda p: render_pdf(report, p)}
    for f in formats:
        path = os.path.join(out_dir, f"threat_report_{stamp}.{f}")
        renderers[f](path)
        written.append(path)
        latest = os.path.join(out_dir, f"latest.{f}")
        try:
            with open(path, "rb") as s, open(latest, "wb") as d:
                d.write(s.read())
        except OSError:
            pass
    written += export_iocs(report, out_dir, stamp)
    with open(os.path.join(out_dir, f"threat_report_{stamp}.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2, default=str)
    return written


def run_once(args, client=None) -> list:
    client = client or make_client()
    report = ElasticsearchSource(client).fetch(args.hours, args.exclude_simulated)
    files = write_reports(report, args.out, args.formats)
    print(f"[report] threat level {report['threat_level']} - {report['totals']['events']:,} events, "
          f"{report['totals']['unique_ips']:,} IPs, {report['totals']['malicious_ips']:,} malicious", flush=True)
    for f in files:
        print(f"[report]   wrote {f}", flush=True)
    return files


def seconds_until(hhmm: str, tzname: str, now: datetime | None = None) -> float:
    from zoneinfo import ZoneInfo

    tz = ZoneInfo(tzname)
    now = (now or datetime.now(tz)).astimezone(tz)
    h, m = (int(x) for x in hhmm.split(":"))
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return (nxt - now).total_seconds()


def run_daily_loop(args) -> None:
    tzname = os.environ.get("REPORT_TZ", "UTC")
    print(f"[report] scheduler: daily at {args.daily_at} ({tzname}); output {args.out}", flush=True)
    while True:
        wait = seconds_until(args.daily_at, tzname)
        while wait > 0:
            time.sleep(min(wait, 60))
            wait -= 60
        try:
            run_once(args)
        except Exception:  # keep the scheduler alive across transient ES outages
            traceback.print_exc()
        time.sleep(61)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Generate the automated threat-intelligence report.")
    ap.add_argument("--hours", type=float, default=24, help="look-back window in hours (default 24)")
    ap.add_argument("--out", default=os.environ.get("REPORT_DIR", "./reports"), help="output directory")
    ap.add_argument("--formats", default="md,html,pdf", help="comma list of md,html,pdf")
    ap.add_argument("--exclude-simulated", action="store_true", help="ignore events tagged 'simulated'")
    ap.add_argument("--daily-at", metavar="HH:MM", help="run forever, generating a report daily at this local time (REPORT_TZ)")
    ap.add_argument("--print-query", action="store_true", help="print the Elasticsearch DSL and exit")
    a = ap.parse_args(argv)
    a.formats = [f.strip() for f in a.formats.split(",") if f.strip()]
    bad = [f for f in a.formats if f not in ("md", "html", "pdf")]
    if bad:
        ap.error(f"unknown format(s): {bad}")
    return a


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.print_query:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=args.hours)
        print(json.dumps({"index": INDEX, "size": 0, "query": build_query(start, end, args.exclude_simulated),
                          "aggs": build_aggs(start, end)}, indent=2))
        return 0
    if args.daily_at:
        run_daily_loop(args)
        return 0
    try:
        run_once(args)
    except Exception as exc:
        print(f"[report] FAILED: {exc}", file=sys.stderr)
        if os.environ.get("DEBUG"):
            traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
