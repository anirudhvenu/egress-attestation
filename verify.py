#!/usr/bin/env python3
"""Verify an egress attestation run.

Checks, in this order: manifest signature, file hashes, sandbox boundary, proxy
boundary. Has no knowledge of which scenario produced the run, and reads only
manifest.json, manifest.sig and the four files named in manifest.files. It never
reads flows_*.log.

Usage: python verify.py runs/<scenario> [--pubkey keys/lab.pub] [--verbose] [--no-color]
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

BOUNDARIES = ("sandbox", "proxy")
GREEN, YELLOW, RED, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[0m"
STATUS_COLOR = {"ok": GREEN, "alert": YELLOW, "not in policy": RED}
USE_COLOR = False


def paint(text, color):
    return f"{color}{text}{RESET}" if USE_COLOR else str(text)


def mb(n):
    return f"{n / 1_000_000:.1f}"


def render(verdict, offenders, tables, status):
    """verdict, blank line, offender lines, optional tables, blank line, status row."""
    print()
    print(verdict)
    if offenders:
        print()
        w1 = max([7] + [len(o[0]) for o in offenders])
        w2 = max([len(o[1]) for o in offenders])
        wc = max([0] + [len(str(o[3][0])) for o in offenders if o[2] == "unknown"])
        for col1, col2, kind, payload in offenders:
            if kind == "unknown":
                conns, out = payload
                detail = f"{paint('not in policy', RED)}   {conns:>{wc}} conns   {mb(out)} MB out"
            else:
                detail = payload
            if col2:
                print(f"  {col1.ljust(w1)}  {col2.ljust(w2)}  {detail}")
            else:
                print(f"  {col1} {detail}")
    for boundary, rows in tables:
        print()
        print(f"  {boundary}")
        head = ["dst", "label", "conns", "MB out", "MB in", "status"]
        body = [[r[0], r[1], str(r[2]), mb(r[3]), mb(r[4]), r[5]] for r in rows]
        w = [max([len(h)] + [len(row[i]) for row in body]) for i, h in enumerate(head)]
        cells = [head[0].ljust(w[0]), head[1].ljust(w[1]), head[2].rjust(w[2]),
                 head[3].rjust(w[3]), head[4].rjust(w[4]), head[5]]
        print("    " + "   ".join(cells))
        for row in body:
            cells = [row[0].ljust(w[0]), row[1].ljust(w[1]), row[2].rjust(w[2]),
                     row[3].rjust(w[3]), row[4].rjust(w[4]),
                     paint(row[5], STATUS_COLOR[row[5]])]
            print("    " + "   ".join(cells))
    print()
    print("  " + "    ".join(f"{name} {value}" for name, value in status.items()))


def check_boundary(run, boundary, offenders, tables):
    """Returns 'ok', 'alert' or 'fail' for one boundary; appends offenders/rows."""
    try:
        policy = json.loads((run / f"policy_{boundary}.json").read_text())
        digest = json.loads((run / f"digest_{boundary}.json").read_text())
    except (OSError, ValueError, UnicodeDecodeError):
        offenders.append((boundary, f"policy/digest_{boundary}.json", "text",
                          paint("unreadable", RED)))
        return "fail"

    allowed = {entry["dst"]: entry for entry in policy.get("allowed", [])}
    seen = digest.get("seen", [])
    verdict, rows = "ok", []
    # Undeclared destinations are reported loudest-first (most connections), not
    # in the digest's dst order; alerts follow, in the order they were checked.
    unknown, alerts = [], []

    for s in seen:
        dst, conns = s["dst"], s["connections"]
        out, into = s["bytes_out"], s["bytes_in"]
        entry = allowed.get(dst)
        if entry is None:
            unknown.append((boundary, dst, "unknown", (conns, out)))
            rows.append((dst, "-", conns, out, into, "not in policy"))
            verdict = "fail"
            continue
        state = "ok"
        expect = entry.get("expect") or {}
        limit = expect.get("max_out_bytes")
        if limit is not None and out > limit:
            alerts.append((boundary, dst, "text", f"out {mb(out)} MB, limit {mb(limit)} MB"))
            state = "alert"
        floor = expect.get("min_in_out_ratio")
        if floor is not None:
            ratio = into / max(out, 1)
            if ratio < floor:
                alerts.append((boundary, dst, "text",
                               f"in/out {ratio:.1f}, expected >= {floor}"))
                state = "alert"
        if state == "alert" and verdict == "ok":
            verdict = "alert"
        rows.append((dst, entry.get("label", "-"), conns, out, into, state))

    unknown.sort(key=lambda o: (-o[3][0], o[1]))
    offenders.extend(unknown)
    offenders.extend(alerts)
    for dst, entry in allowed.items():
        if dst not in {s["dst"] for s in seen}:
            rows.append((dst, entry.get("label", "-"), 0, 0, 0, "ok"))
    tables.append((boundary, sorted(rows)))
    return verdict


def main():
    ap = argparse.ArgumentParser(description="Verify an egress attestation run.")
    ap.add_argument("run", help="run folder, e.g. runs/baseline")
    ap.add_argument("--pubkey", default="keys/lab.pub")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and not args.no_color
    run = Path(args.run)
    offenders, tables = [], []
    status = {"signature": "-", "files": "-", "sandbox": "-", "proxy": "-"}

    # 1. signature over the exact bytes of manifest.json
    try:
        manifest_bytes = (run / "manifest.json").read_bytes()
        signature = base64.b64decode((run / "manifest.sig").read_text().strip())
        pubkey = load_pem_public_key(Path(args.pubkey).read_bytes())
        pubkey.verify(signature, manifest_bytes)
    except Exception:
        offenders.append(("signature", "", "text", paint("invalid", RED)))
        status["signature"] = paint("FAIL", RED)
        render(paint("FAIL", RED), offenders, [], status)
        return 2
    status["signature"] = paint("ok", GREEN)

    # 2. hashes of the files the manifest names
    failed = False
    try:
        files = json.loads(manifest_bytes)["files"]
    except (ValueError, KeyError, TypeError):
        offenders.append(("files", "manifest.json", "text", paint("unreadable", RED)))
        files, failed = {}, True
    good = 0
    for name in sorted(files):
        try:
            digest = hashlib.sha256((run / name).read_bytes()).hexdigest()
        except OSError:
            offenders.append(("files", name, "text", paint("missing", RED)))
            failed = True
            continue
        if digest != files[name]:
            offenders.append(("files", name, "text", paint("hash mismatch", RED)))
            failed = True
        else:
            good += 1
    if files or not failed:
        status["files"] = paint(f"{good}/{len(files)}", RED if failed else GREEN)

    # 3. boundary checks
    alerted = False
    for boundary in BOUNDARIES:
        result = check_boundary(run, boundary, offenders, tables)
        failed = failed or result == "fail"
        alerted = alerted or result == "alert"
        status[boundary] = {"ok": paint("ok", GREEN), "alert": paint("ALERT", YELLOW),
                            "fail": paint("FAIL", RED)}[result]

    # 4. verdict
    if failed:
        verdict, code = paint("FAIL", RED), 1
    elif alerted:
        verdict, code = paint("PASS with ALERTS", YELLOW), 0
    else:
        verdict, code = paint("PASS", GREEN), 0
    render(verdict, offenders, tables if args.verbose else [], status)
    return code


if __name__ == "__main__":
    sys.exit(main())
