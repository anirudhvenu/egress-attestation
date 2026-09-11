#!/usr/bin/env python3
"""Generate signed egress-attestation artifacts for one scenario.

Models a sandbox that reaches the internet only through a package proxy, and
attests what each hop actually talked to:

    sandbox 10.0.2.10 --> proxy 10.0.1.5:443 --> registries 203.0.113.0/24

Flow:
    1. Synthesise VPC flow logs at both boundaries. 300 package installs,
       identical in every scenario.
    2. Inject the traffic that makes this scenario distinct.
    3. Write both logs, read them back, reduce each to a per-destination digest.
    4. Hash the two policies and two digests into a manifest, and sign it.

Digests are built from the written files, so a digest and its raw_log_sha256
always cover the same bytes. Output is deterministic: one scenario, one set of
bytes, every time. The scenario name reaches the artifacts only as a random seed
and a nonce hash, never as plaintext.

Usage: python gen.py --scenario {baseline,sandbox_leak,proxy_escape,proxy_writeback} [--out runs/]
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

# A flow log record awaiting output: (start, direction rank, srcaddr, text).
# The first three fields are the sort key; only the text is written.
FlowRecord = tuple[int, int, str, str]

# --- fixed topology ---------------------------------------------------------
ACCOUNT = "123456789012"
SANDBOX, PROXY = "10.0.2.10", "10.0.1.5"
PYPI, NPM = "203.0.113.10", "203.0.113.20"
WINDOW_START = 1783564080  # 2026-07-09T02:28:00Z
INSTALLS = 300
# Per-install download size, drawn log-uniformly between these bounds (mean ~140 KB).
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
def line(boundary: str, src: str, dst: str, sport: int, dport: int,
         nbytes: int, start: int, end: int) -> FlowRecord:
    """Build one AWS VPC Flow Logs v2 record, paired with its sort key.

    Direction rank is 0 when the monitored host is the source, 1 otherwise,
    which keeps a connection's two lines adjacent and forward-first.
    """
    packets = max(1, nbytes // 1400)
    rank = 0 if src == HOST[boundary] else 1
    text = (
        f"2 {ACCOUNT} {ENI[boundary]} {src} {dst} {sport} {dport} 6 "
        f"{packets} {nbytes} {start} {end} ACCEPT OK"
    )
    return (start, rank, src, text)


def connection(flows: list[FlowRecord], boundary: str, dst: str, sport: int,
               dport: int, up: int, down: int, start: int, dur: int) -> None:
    """Append both directions of one TCP connection to `flows`.

    `up` bytes leave the monitored host, `down` come back.
    """
    host = HOST[boundary]
    flows.append(line(boundary, host, dst, sport, dport, up, start, start + dur))
    flows.append(line(boundary, dst, host, dport, sport, down, start, start + dur))


def base_traffic(sandbox: list[FlowRecord], proxy: list[FlowRecord]) -> int:
    """Generate the 300 package installs common to every scenario.

    Each install pairs a sandbox-to-proxy connection with the proxy-to-registry
    fetch it causes, sharing a start time and duration. Registries split 85/15
    between pypi and npm.

    Returns the last install's start time, which bounds the traffic window.
    """
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


def spread(n: int, span: int) -> list[int]:
    """Return n start times spaced evenly across a window of `span` seconds.

    Ascending, and never coinciding with the window edges.
    """
    return [WINDOW_START + (span * (i + 1)) // (n + 1) for i in range(n)]


def inject(scenario: str, sandbox: list[FlowRecord], proxy: list[FlowRecord],
           span: int) -> None:
    """Add the traffic that distinguishes this scenario from the baseline.

    baseline:        nothing.
    sandbox_leak:    SSH to an undeclared internal host.
    proxy_escape:    proxy traffic to two undeclared external services.
    proxy_writeback: bulk uploads to the declared proxy, inverting its shape.
    """
    def burst(flows, boundary, dst, dport, n, up_fn, down_fn):
        """Add n connections to one destination, spread across the window."""
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


def write_log(path: Path, flows: list[FlowRecord]) -> None:
    """Write flow records sorted by start, forward before reverse, then srcaddr."""
    flows.sort(key=lambda f: (f[0], f[1], f[2]))
    path.write_text("\n".join(f[3] for f in flows) + "\n")


# --- digests, manifest, signing ---------------------------------------------
def iso(ts: int) -> str:
    """Format a unix timestamp as a UTC ISO 8601 string, e.g. 2026-07-09T02:28:00Z."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_digest(path: Path, boundary: str) -> tuple[dict, int]:
    """Reduce a written flow log to a per-destination digest.

    Reads the file from disk, so the digest and its raw_log_sha256 cover the same
    bytes. Lines from the monitored host give connections and bytes_out keyed by
    destination; lines back to it give bytes_in.

    Returns the digest and the log's latest flow end.
    """
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


def write_json(path: Path, obj: dict) -> None:
    """Write JSON with sorted keys and fixed indent, so the bytes are hashable."""
    with path.open("w", newline="\n") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def load_key(keys_dir: Path) -> ed25519.Ed25519PrivateKey:
    """Load the ed25519 signing key, creating the keypair on first use.

    keys/lab.key is a throwaway demo key, committed with the artifacts so anyone
    can reproduce the signatures. It protects nothing. An existing key is always
    reused, since replacing it would invalidate every committed manifest.sig.
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


def sha256_file(path: Path) -> str:
    """Return the SHA-256 of a file's contents as a hex string."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    """Write one scenario's run folder.

    Two flow logs, two policies, two digests, a manifest, and a detached
    signature over the manifest bytes.
    """
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
