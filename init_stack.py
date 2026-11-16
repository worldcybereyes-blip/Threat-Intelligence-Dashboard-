#!/usr/bin/env python3
"""
init_stack.py - one-shot bootstrap for the Threat Intelligence Dashboard.

  python init_stack.py elasticsearch   users/roles (least privilege), ILM policy, index template
  python init_stack.py kibana          data view, saved searches, visualisations, dashboard

Idempotent: safe to run on every `start.bat`.  Secrets come only from environment variables.
"""
import json
import os
import sys
import time

import requests

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200").rstrip("/")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://kibana:5601").rstrip("/")
ELASTIC_AUTH = ("elastic", os.environ.get("ELASTIC_PASSWORD", ""))
CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")


def log(msg):
    print(f"[init] {msg}", flush=True)


def wait_for(url, auth=None, timeout=600, ok=lambda r: r.status_code == 200):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = requests.get(url, auth=auth, timeout=10)
            if ok(r):
                return r
            last = f"HTTP {r.status_code}"
        except requests.RequestException as exc:
            last = str(exc)
        time.sleep(5)
    raise SystemExit(f"[init] timed out waiting for {url}: {last}")


def es(method, path, body=None, expect=(200, 201)):
    r = requests.request(method, f"{ES_URL}{path}", auth=ELASTIC_AUTH, json=body, timeout=60)
    if r.status_code not in expect:
        raise SystemExit(f"[init] {method} {path} -> HTTP {r.status_code}: {r.text[:500]}")
    return r.json() if r.content else {}


# --------------------------------------------------------------------------- Elasticsearch
def init_elasticsearch():
    if not ELASTIC_AUTH[1]:
        raise SystemExit("[init] ELASTIC_PASSWORD is not set")
    wait_for(f"{ES_URL}/_cluster/health", auth=ELASTIC_AUTH)

    # Built-in kibana_system user needs its password set before Kibana can start.
    es("POST", "/_security/user/kibana_system/_password", {"password": os.environ["KIBANA_SYSTEM_PASSWORD"]})
    log("kibana_system password set")

    # Least-privilege roles: each component gets only what it needs.
    roles = {
        "ti_logstash_writer": {
            "cluster": ["monitor"],
            "indices": [{"names": ["honeypot-*"], "privileges": ["create_index", "create", "index", "auto_configure"]}],
        },
        "ti_reader": {
            "cluster": ["monitor"],
            "indices": [{"names": ["honeypot-*"], "privileges": ["read", "view_index_metadata"]}],
        },
        "ti_elastalert": {
            "cluster": ["monitor"],
            "indices": [
                {"names": ["honeypot-*"], "privileges": ["read", "view_index_metadata"]},
                {"names": ["elastalert*"], "privileges": ["all"]},
            ],
        },
    }
    for name, body in roles.items():
        es("PUT", f"/_security/role/{name}", body)
    users = {
        "ti_logstash": ("LOGSTASH_WRITER_PASSWORD", ["ti_logstash_writer"]),
        "ti_reader": ("TI_READER_PASSWORD", ["ti_reader"]),
        "ti_elastalert": ("ELASTALERT_PASSWORD", ["ti_elastalert"]),
    }
    for user, (env_name, user_roles) in users.items():
        es("PUT", f"/_security/user/{user}", {"password": os.environ[env_name], "roles": user_roles})
    log("roles and service users created: ti_logstash, ti_reader, ti_elastalert")

    retention = int(os.environ.get("RETENTION_DAYS", "30"))
    es("PUT", "/_ilm/policy/honeypot-retention", {
        "policy": {"phases": {
            "hot": {"actions": {"set_priority": {"priority": 100}}},
            "delete": {"min_age": f"{retention}d", "actions": {"delete": {}}},
        }}
    })
    log(f"ILM policy honeypot-retention: delete after {retention} days")

    with open(os.path.join(CONFIG_DIR, "index-template.json"), encoding="utf-8") as fh:
        template = json.load(fh)
    es("PUT", "/_index_template/honeypot-cowrie", template)
    log("index template honeypot-cowrie installed")
    log("Elasticsearch bootstrap complete")


# --------------------------------------------------------------------------------- Kibana
def kibana(method, path, **kw):
    headers = {"kbn-xsrf": "true"}
    headers.update(kw.pop("headers", {}))
    return requests.request(method, f"{KIBANA_URL}{path}", auth=ELASTIC_AUTH, headers=headers, timeout=120, **kw)


def init_kibana():
    import kibana_objects  # local module

    wait_for(f"{KIBANA_URL}/api/status", ok=lambda r: r.status_code == 200 and "available" in r.text)

    r = kibana("POST", "/api/data_views/data_view", json={
        "data_view": {"id": kibana_objects.DATA_VIEW_ID, "title": "honeypot-cowrie-*",
                      "name": "Honeypot - Cowrie", "timeFieldName": "@timestamp"},
        "override": True,
    })
    log(f"data view: HTTP {r.status_code}")

    ndjson = kibana_objects.build_ndjson()
    r = kibana("POST", "/api/saved_objects/_import?overwrite=true",
               files={"file": ("threat-intel-dashboard.ndjson", ndjson.encode("utf-8"), "application/ndjson")})
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code == 200 and body.get("success"):
        log(f"imported {body.get('successCount')} saved objects (dashboard: 'Threat Intelligence - SOC Overview')")
    else:
        # Non-fatal: the stack still works; build panels manually using the guide in HOW_TO_RUN.txt.
        log(f"WARNING: saved-object import problem (HTTP {r.status_code}): {json.dumps(body)[:800]}")
        log("The stack is running; create the panels manually (see docs: Kibana dashboard design).")
    log("Kibana bootstrap complete")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if target == "elasticsearch":
        init_elasticsearch()
    elif target == "kibana":
        init_kibana()
    else:
        raise SystemExit("usage: init_stack.py elasticsearch|kibana")
