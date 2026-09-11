#!/usr/bin/env python3
"""Generate signed egress-attestation artifacts for one scenario (see README.md).

Usage: python gen.py --scenario {baseline,sandbox_leak,proxy_escape,proxy_writeback} [--out runs/]

Output is deterministic: the same scenario always produces byte-identical files.
"""

import argparse
import base64
import hashlib
import json
import random
from datetime import datetime, timezone
from math import log10
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- fixed topology ---------------------------------------------------------
ACCOUNT = "123456789012"
SANDBOX, PROXY = "10.0.2.10", "10.0.1.5"
PYPI, NPM = "203.0.113.10", "203.0.113.20"
# 2026-07-09T02:28:00Z. The spec's parenthetical unix value (1783996080) is
# 2026-07-14, not 2026-07-09; the ISO date wins, since that is what every
# schema example in the spec shows and what the artifacts carry.
WINDOW_START = 1783564080
INSTALLS = 300
# Download size range per install, log-uniform. A 5 MB upper bound gives a mean
# of ~1.07 MB and a baseline in/out ratio near 50, high enough that the
# proxy_writeback ratio alert never fires. 300 KB gives a ~140 KB mean, matching
# the worked digest example this PoC is built against, and a writeback ratio
# of ~6 against a floor of 20.
DOWN_MIN, DOWN_MAX = 50_000, 300_000
SCENARIOS = ["baseline", "sandbox_leak", "proxy_escape", "proxy_writeback"]
ENI = {"sandbox": "eni-sandbox01", "proxy": "eni-proxy01"}
HOST = {"sandbox": SANDBOX, "proxy": PROXY}

REGISTRY_EXPECT = {"max_out_bytes": 1000000, "min_in_out_ratio": 50}
POLICY = {
    "sandbox": {
        "boundary": "sandbox",
        "monitored_host": SANDBOX,
        "allowed": [
            {"dst": f"{PROXY}:443", "label": "artifactory package proxy",
             "expect": {"max_out_bytes": 2000000, "min_in_out_ratio": 20}},
        ],
    },
    "proxy": {
        "boundary": "proxy",
        "monitored_host": PROXY,
        "allowed": [
            {"dst": f"{PYPI}:443", "label": "pypi", "expect": dict(REGISTRY_EXPECT)},
            {"dst": f"{NPM}:443", "label": "npm", "expect": dict(REGISTRY_EXPECT)},
        ],
    },
}


# --- flow logs --------------------------------------------------------------
def line(boundary, src, dst, sport, dport, nbytes, start, end):
    """One AWS VPC Flow Logs v2 record, as (sort key, text).

    The sort key carries a direction rank so that a connection's forward line
    (monitored host -> dst) always precedes its reverse line at the same
    timestamp, instead of the two landing in srcaddr order.
    """
    packets = max(1, nbytes // 1400)
    rank = 0 if src == HOST[boundary] else 1
    text = (
        f"2 {ACCOUNT} {ENI[boundary]} {src} {dst} {sport} {dport} 6 "
        f"{packets} {nbytes} {start} {end} ACCEPT OK"
    )
    return (start, rank, src, text)


def connection(flows, boundary, dst, sport, dport, up, down, start, dur):
    """Forward (monitored host -> dst) and reverse (dst -> monitored host)."""
    host = HOST[boundary]
    flows.append(line(boundary, host, dst, sport, dport, up, start, start + dur))
    flows.append(line(boundary, dst, host, dport, sport, down, start, start + dur))


def base_traffic(sandbox, proxy):
    """300 package installs, identical recipe for every scenario."""
    t = WINDOW_START
    for _ in range(INSTALLS):
        t += random.randint(5, 60)
        sport = random.randint(32768, 60999)
        dur = random.randint(1, 5)
        up = 2000 + random.randint(-300, 300)
        down = int(10 ** random.uniform(log10(DOWN_MIN), log10(DOWN_MAX)))
        connection(sandbox, "sandbox", PROXY, sport, 443, up, down, t, dur)
        registry = PYPI if random.random() < 0.85 else NPM
        pup = 1000 + random.randint(-200, 200)
        psport = random.randint(32768, 60999)
        connection(proxy, "proxy", registry, psport, 443, pup, down, t, dur)
    return t


def spread(n, span):
    """n timestamps evenly spread across the base-traffic window."""
    return [WINDOW_START + (span * (i + 1)) // (n + 1) for i in range(n)]


def inject(scenario, sandbox, proxy, span):
    def burst(flows, boundary, dst, dport, n, up_fn, down_fn):
        for start in spread(n, span):
            sport = random.randint(32768, 60999)
            connection(flows, boundary, dst, sport, dport, up_fn(), down_fn(), start, 1)

    if scenario == "sandbox_leak":
        burst(sandbox, "sandbox", "10.0.5.7", 22, 3, lambda: 900, lambda: 1200)
    elif scenario == "proxy_escape":
        burst(proxy, "proxy", "198.51.100.8", 443, 400,
              lambda: random.randint(1500, 6000), lambda: random.randint(200, 3000))
        burst(proxy, "proxy", "198.51.100.44", 443, 60,
              lambda: random.randint(800, 4000), lambda: random.randint(100, 500))
    elif scenario == "proxy_writeback":
        burst(sandbox, "sandbox", PROXY, 443, 1500,
              lambda: 4000 + random.randint(-500, 500),
              lambda: 200 + random.randint(-50, 50))


def write_log(path, flows):
    """Sorted by start, then forward before reverse, then srcaddr."""
    flows.sort(key=lambda f: (f[0], f[1], f[2]))
    path.write_text("\n".join(f[3] for f in flows) + "\n")


# --- digests, manifest, signing ---------------------------------------------
def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_digest(path, boundary):
    """Read the written log back and summarise it. Never uses in-memory flows."""
    raw = path.read_bytes()
    host = HOST[boundary]
    conns, out, inn = {}, {}, {}
    end = WINDOW_START
    for record in raw.decode().splitlines():
        f = record.split()
        src, dst, sport, dport = f[3], f[4], f[5], f[6]
        nbytes, flow_end = int(f[9]), int(f[11])
        end = max(end, flow_end)
        if src == host:  # forward
            key = f"{dst}:{dport}"
            conns[key] = conns.get(key, 0) + 1
            out[key] = out.get(key, 0) + nbytes
        else:  # reverse
            key = f"{src}:{sport}"
            inn[key] = inn.get(key, 0) + nbytes
    seen = [
        {"dst": k, "connections": conns.get(k, 0),
         "bytes_out": out.get(k, 0), "bytes_in": inn.get(k, 0)}
        for k in sorted(set(conns) | set(inn))
    ]
    digest = {
        "boundary": boundary,
        "monitored_host": host,
        "window": {"start": iso(WINDOW_START), "end": iso(end)},
        "raw_log_sha256": hashlib.sha256(raw).hexdigest(),
        "seen": seen,
    }
    return digest, end


def write_json(path, obj):
    with path.open("w", newline="\n") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def load_key(keys_dir):
    """Load the demo signing key, generating it once if keys/ is absent.

    WARNING: keys/lab.key is a throwaway demo key that is deliberately committed
    to git so anyone can reproduce these artifacts. It signs nothing real. Never
    reuse it, and never commit a key you care about. Existing keys are never
    regenerated -- that would invalidate every committed manifest.sig.
    """
    priv_path, pub_path = keys_dir / "lab.key", keys_dir / "lab.pub"
    if not keys_dir.exists():
        keys_dir.mkdir(parents=True)
        key = ed25519.Ed25519PrivateKey.generate()
        priv_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return key
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Generate egress attestation artifacts.")
    ap.add_argument("--scenario", required=True, choices=SCENARIOS)
    ap.add_argument("--out", default="runs/")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent
    out_dir = (root / args.out) / args.scenario
    out_dir.mkdir(parents=True, exist_ok=True)
    key = load_key(root / "keys")

    random.seed(args.scenario)
    sandbox, proxy = [], []
    last = base_traffic(sandbox, proxy)
    inject(args.scenario, sandbox, proxy, last - WINDOW_START)

    write_log(out_dir / "flows_sandbox.log", sandbox)
    write_log(out_dir / "flows_proxy.log", proxy)

    ends = []
    for boundary in ("sandbox", "proxy"):
        write_json(out_dir / f"policy_{boundary}.json", POLICY[boundary])
        digest, end = build_digest(out_dir / f"flows_{boundary}.log", boundary)
        write_json(out_dir / f"digest_{boundary}.json", digest)
        ends.append(end)

    names = [
        "policy_sandbox.json",
        "policy_proxy.json",
        "digest_sandbox.json",
        "digest_proxy.json",
    ]
    manifest = {
        "spec_version": "0.1",
        "run_id": "exploitgym-run-0001",
        "window": {"start": iso(WINDOW_START), "end": iso(max(ends))},
        "nonce": hashlib.sha256(args.scenario.encode()).hexdigest(),
        "proxy": {
            "product": "artifactory",
            "version": "7.98.1",
            "image_sha256": hashlib.sha256(b"demo-proxy-image").hexdigest(),
        },
        "files": {n: sha256_file(out_dir / n) for n in names},
    }
    manifest_path = out_dir / "manifest.json"
    write_json(manifest_path, manifest)
    sig = key.sign(manifest_path.read_bytes())
    (out_dir / "manifest.sig").write_text(base64.b64encode(sig).decode())

    print(f"wrote {out_dir}")


if __name__ == "__main__":
    main()
