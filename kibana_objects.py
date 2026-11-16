"""
kibana_objects.py - generates the Kibana saved objects (visualisations, saved searches,
dashboard) as NDJSON for the Saved Objects import API.

All panels use Kibana's classic "aggregation based" visualisations, which are stable
across 8.x.  The Coordinate/Maps panel is NOT auto-generated (Maps saved objects are far
more version-sensitive): the dashboard contains a Markdown panel with the 60-second recipe
and docs/ explain it step by step.
"""
import json

DATA_VIEW_ID = "honeypot-cowrie"
KIBANA_VERSION = "8.15.0"
IDX_REF = {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}


def _search_source(query="", language="kuery"):
    return json.dumps({
        "query": {"query": query, "language": language},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def _agg(i, type_, schema, params=None, enabled=True):
    return {"id": str(i), "enabled": enabled, "type": type_, "params": params or {}, "schema": schema}


def _terms(i, field, size=10, schema="segment", order_by="1", label=None):
    p = {"field": field, "orderBy": order_by, "order": "desc", "size": size,
         "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing"}
    if label:
        p["customLabel"] = label
    return _agg(i, "terms", schema, p)


def _count(i=1):
    return _agg(i, "count", "metric")


def _vis(vid, title, vis_type, aggs, params, query="", description=""):
    state = {"title": title, "type": vis_type, "aggs": aggs, "params": params}
    return {
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "description": description,
            "visState": json.dumps(state), "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
        },
        "references": [IDX_REF],
        "coreMigrationVersion": KIBANA_VERSION,
    }


def metric_vis(vid, title, aggs, query="", description=""):
    params = {"addTooltip": True, "addLegend": False, "type": "metric", "metric": {
        "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
        "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True}, "invertColors": False,
        "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48}}}
    return _vis(vid, title, "metric", aggs, params, query, description)


def table_vis(vid, title, aggs, query="", per_page=10):
    params = {"perPage": per_page, "showPartialRows": False, "showMetricsAtAllLevels": False,
              "showTotal": False, "totalFunc": "sum", "percentageCol": "",
              "sort": {"columnIndex": None, "direction": None}}
    return _vis(vid, title, "table", aggs, params, query)


def pie_vis(vid, title, aggs, query="", donut=True):
    params = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
              "isDonut": donut, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}
    return _vis(vid, title, "pie", aggs, params, query)


def tagcloud_vis(vid, title, aggs, query=""):
    params = {"scale": "linear", "orientation": "single", "minFontSize": 16, "maxFontSize": 60,
              "showLabel": True}
    return _vis(vid, title, "tagcloud", aggs, params, query)


def bar_vis(vid, title, aggs, query="", mode="stacked", chart="histogram"):
    params = {
        "type": chart, "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                          "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                       "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": "Events"}}],
        "seriesParams": [{"show": True, "type": chart, "mode": mode, "data": {"label": "Events", "id": "1"},
                          "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2,
                          "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
        "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }
    return _vis(vid, title, chart, aggs, params, query)


def markdown_vis(vid, title, text):
    params = {"fontSize": 12, "openLinksInNewTab": False, "markdown": text}
    return {
        "id": vid, "type": "visualization",
        "attributes": {"title": title, "description": "",
                       "visState": json.dumps({"title": title, "type": "markdown", "aggs": [], "params": params}),
                       "uiStateJSON": "{}",
                       "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source()}},
        "references": [], "coreMigrationVersion": KIBANA_VERSION,
    }


def saved_search(sid, title, query, columns):
    return {
        "id": sid, "type": "search",
        "attributes": {
            "title": title, "description": "", "columns": columns,
            "sort": [["@timestamp", "desc"]], "grid": {}, "hideChart": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
        },
        "references": [IDX_REF], "coreMigrationVersion": KIBANA_VERSION,
    }


MAP_HELP = """### Attack-origin map (60 seconds, one-off)
1. Open **Maps** -> *Create map* -> **Add layer** -> **Documents**.
2. Data view: **Honeypot - Cowrie**, geospatial field: `source.geo.location`.
3. Layer style: colour by `event.risk_score` (graduated), size by `event.risk_score`.
4. Save as *Attack origins* and add it to this dashboard (*Add from library*)."""


def visualizations():
    v = []
    # ---- KPI tiles
    v.append(metric_vis("ti-vis-kpi-events", "Total events", [_count()]))
    v.append(metric_vis("ti-vis-kpi-attackers", "Unique attacker IPs", [
        _agg(1, "cardinality", "metric", {"field": "source.ip", "customLabel": "Attacker IPs"})]))
    v.append(metric_vis("ti-vis-kpi-sessions", "Attack sessions", [
        _agg(1, "cardinality", "metric", {"field": "cowrie.session", "customLabel": "Sessions"})]))
    v.append(metric_vis("ti-vis-kpi-highrisk", "High-risk events (score >= 70)", [_count()],
                        query="event.risk_score >= 70"))
    v.append(metric_vis("ti-vis-kpi-malicious", "Malicious IPs (TI verdict)", [
        _agg(1, "cardinality", "metric", {"field": "source.ip", "customLabel": "Malicious IPs"})],
        query='ti.verdict : "malicious"'))
    v.append(metric_vis("ti-vis-kpi-malware", "Malware downloads", [_count()],
                        query='event.action : "cowrie.session.file_download"'))
    # ---- Timeline / velocity
    v.append(bar_vis("ti-vis-timeline", "Attack timeline (events by risk level)", [
        _count(),
        _agg(2, "date_histogram", "segment", {"field": "@timestamp", "useNormalizedEsInterval": True,
                                              "scaleMetricValues": False, "interval": "auto", "drop_partials": False,
                                              "min_doc_count": 1, "extended_bounds": {}}),
        _terms(3, "event.risk_level", 5, schema="group")]))
    v.append(bar_vis("ti-vis-velocity", "Login attempt velocity (brute-force)", [
        _count(),
        _agg(2, "date_histogram", "segment", {"field": "@timestamp", "useNormalizedEsInterval": True,
                                              "scaleMetricValues": False, "interval": "auto", "drop_partials": False,
                                              "min_doc_count": 1, "extended_bounds": {}}),
        _terms(3, "event.outcome", 3, schema="group")],
        query='event.action : "cowrie.login.failed" or event.action : "cowrie.login.success"', chart="line",
        mode="normal"))
    # ---- Who: IPs / ASNs / countries
    v.append(table_vis("ti-vis-top-ips", "Top 10 malicious IPs (by max risk)", [
        _agg(1, "max", "metric", {"field": "event.risk_score", "customLabel": "Max risk"}),
        _agg(2, "count", "metric", {"customLabel": "Events"}),
        _agg(3, "max", "metric", {"field": "ti.abuseipdb.confidence_score", "customLabel": "AbuseIPDB score"}),
        _terms(4, "source.ip", 10, schema="bucket", order_by="1"),
        _terms(5, "source.geo.country_name", 1, schema="bucket", order_by="2", label="Country"),
    ]))
    v.append(table_vis("ti-vis-top-asns", "Top 10 attacking ASNs", [
        _count(),
        _agg(2, "cardinality", "metric", {"field": "source.ip", "customLabel": "Unique IPs"}),
        _terms(3, "source.as.organization.name", 10, schema="bucket", label="ASN organisation"),
    ]))
    v.append(pie_vis("ti-vis-countries", "Attack origin by country", [
        _count(), _terms(2, "source.geo.country_name", 10)]))
    v.append(pie_vis("ti-vis-verdicts", "Threat-intel verdicts", [
        _count(), _terms(2, "ti.verdict", 6)]))
    # ---- What: ports / protocols
    v.append(pie_vis("ti-vis-ports", "Targeted ports", [
        _count(), _terms(2, "destination.port", 8)], query='event.action : "cowrie.session.connect"'))
    v.append(pie_vis("ti-vis-protocols", "Protocols", [
        _count(), _terms(2, "network.protocol", 5)], query='event.action : "cowrie.session.connect"', donut=False))
    # ---- Credentials / commands
    v.append(table_vis("ti-vis-usernames", "Top usernames attempted", [
        _count(), _terms(2, "cowrie.username", 10, schema="bucket", label="Username")],
        query='cowrie.username : *'))
    v.append(table_vis("ti-vis-passwords", "Top passwords attempted", [
        _count(), _terms(2, "cowrie.password", 10, schema="bucket", label="Password")],
        query='cowrie.password : *'))
    v.append(table_vis("ti-vis-credentials", "Top credential pairs (user:password)", [
        _count(), _terms(2, "cowrie.credential", 10, schema="bucket", label="Credential")]))
    v.append(table_vis("ti-vis-commands", "Top commands executed in the honeypot shell", [
        _count(), _terms(2, "cowrie.input", 15, schema="bucket", label="Command")],
        query='event.action : "cowrie.command.input"', per_page=15))
    # ---- IOCs / TTPs
    v.append(table_vis("ti-vis-malware", "Malware samples (SHA-256)", [
        _count(),
        _agg(2, "max", "metric", {"field": "ti.file.malicious", "customLabel": "VT detections"}),
        _terms(3, "cowrie.shasum", 10, schema="bucket", label="SHA-256"),
        _terms(4, "ti.file.threat_label", 1, schema="bucket", order_by="1", label="Family")],
        query='cowrie.shasum : *'))
    v.append(table_vis("ti-vis-mitre", "MITRE ATT&CK techniques observed", [
        _count(), _terms(2, "threat.technique.id", 10, schema="bucket", label="Technique"),
        _terms(3, "threat.technique.name", 1, schema="bucket", order_by="1", label="Name")]))
    v.append(table_vis("ti-vis-hassh", "SSH client fingerprints (HASSH)", [
        _count(), _terms(2, "cowrie.hassh", 10, schema="bucket", label="HASSH"),
        _terms(3, "cowrie.client_version", 1, schema="bucket", order_by="1", label="Client")],
        query='cowrie.hassh : *'))
    v.append(tagcloud_vis("ti-vis-otx-tags", "OTX threat tags", [
        _count(), _terms(2, "ti.otx.tags", 30)]))
    v.append(markdown_vis("ti-vis-map-help", "Attack origin map - setup", MAP_HELP))
    return v


def saved_searches():
    cols = ["source.ip", "source.geo.country_name", "event.action", "cowrie.username", "cowrie.input",
            "ti.verdict", "event.risk_score"]
    return [
        saved_search("ti-search-highsev", "High-severity events (risk >= 70)", "event.risk_score >= 70", cols),
        saved_search("ti-search-malware", "Malware downloads / uploads",
                     'event.action : ("cowrie.session.file_download" or "cowrie.session.file_upload")',
                     ["source.ip", "cowrie.url", "cowrie.shasum", "ti.file.threat_label", "ti.file.malicious"]),
        saved_search("ti-search-success", "Successful honeypot logins from malicious IPs",
                     'event.action : "cowrie.login.success" and ti.verdict : "malicious"',
                     ["source.ip", "source.geo.country_name", "cowrie.username", "cowrie.password", "ti.score"]),
    ]


# Layout: (visualization id, x, y, w, h) on Kibana's 48-column grid
LAYOUT = [
    ("ti-vis-kpi-events", 0, 0, 8, 6), ("ti-vis-kpi-attackers", 8, 0, 8, 6), ("ti-vis-kpi-sessions", 16, 0, 8, 6),
    ("ti-vis-kpi-highrisk", 24, 0, 8, 6), ("ti-vis-kpi-malicious", 32, 0, 8, 6), ("ti-vis-kpi-malware", 40, 0, 8, 6),
    ("ti-vis-timeline", 0, 6, 28, 14), ("ti-vis-verdicts", 28, 6, 20, 14),
    ("ti-vis-map-help", 0, 20, 14, 14), ("ti-vis-countries", 14, 20, 14, 14), ("ti-vis-top-asns", 28, 20, 20, 14),
    ("ti-vis-top-ips", 0, 34, 28, 14), ("ti-vis-velocity", 28, 34, 20, 14),
    ("ti-vis-ports", 0, 48, 12, 12), ("ti-vis-protocols", 12, 48, 12, 12), ("ti-vis-mitre", 24, 48, 24, 12),
    ("ti-vis-usernames", 0, 60, 16, 14), ("ti-vis-passwords", 16, 60, 16, 14), ("ti-vis-credentials", 32, 60, 16, 14),
    ("ti-vis-commands", 0, 74, 28, 14), ("ti-vis-malware", 28, 74, 20, 14),
    ("ti-vis-hassh", 0, 88, 24, 12), ("ti-vis-otx-tags", 24, 88, 24, 12),
]


def dashboard():
    panels, refs = [], []
    for n, (vid, x, y, w, h) in enumerate(LAYOUT, start=1):
        panels.append({"version": KIBANA_VERSION, "type": "visualization",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n)},
                       "panelIndex": str(n), "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
        refs.append({"name": f"panel_{n}", "type": "visualization", "id": vid})
    return {
        "id": "ti-dashboard-soc", "type": "dashboard",
        "attributes": {
            "title": "Threat Intelligence - SOC Overview",
            "description": "Honeypot attack telemetry enriched with GeoIP, AbuseIPDB, OTX and VirusTotal.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                       "syncTooltips": False, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 30000},
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs, "coreMigrationVersion": KIBANA_VERSION,
    }


def all_objects():
    return visualizations() + saved_searches() + [dashboard()]


def build_ndjson():
    return "\n".join(json.dumps(o, separators=(",", ":")) for o in all_objects()) + "\n"


if __name__ == "__main__":
    import sys
    out = build_ndjson()
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
