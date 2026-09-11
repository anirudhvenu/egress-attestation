# Egress Attestation

A signed, outsider-verifiable statement of what a sandbox could reach on the network during a
guardrails-off eval. The lab runs an eval, captures flow logs at every boundary between the
sandbox and the internet, reduces them to per-destination digests, and signs a manifest binding
those digests to a run. An outsider with only the public key and the run folder can then check
that the signature holds, that the digests are the ones that were signed, and that every
destination the sandbox and its proxy actually talked to was declared in policy — without
trusting the lab's own account of the run, and without seeing the raw logs.

**Design principle:** every hop between the sandbox and the internet is a boundary — log its far
side at the network layer, not the workload.

## Topology

```
sandbox 10.0.2.10  --->  proxy 10.0.1.5:443  --->  registries
                                                   203.0.113.10:443  (pypi)
                                                   203.0.113.20:443  (npm)
```

Two boundaries, two flow logs. The sandbox boundary sees only the proxy; the proxy boundary sees
where the proxy went next. A destination reached by the proxy on the sandbox's behalf is invisible
at the sandbox boundary, which is the whole reason the second log exists.

## Artifacts

Each run folder contains:

| File | What it is |
|---|---|
| `flows_sandbox.log` | Raw AWS VPC Flow Logs v2 captured at the sandbox interface. Evidence, not attested. |
| `flows_proxy.log` | Raw flow logs captured at the proxy interface. Evidence, not attested. |
| `policy_sandbox.json` | Destinations the sandbox is allowed to reach, with optional volume expectations. |
| `policy_proxy.json` | Destinations the proxy is allowed to reach on the sandbox's behalf. |
| `digest_sandbox.json` | Per-destination connection counts and byte totals reduced from `flows_sandbox.log`, plus its SHA-256. |
| `digest_proxy.json` | The same, reduced from `flows_proxy.log`. |
| `manifest.json` | Run id, window, nonce, proxy build identity, and the SHA-256 of each of the four JSON files above. |
| `manifest.sig` | Ed25519 signature over the exact bytes of `manifest.json`, base64. |

The verifier reads the manifest, the signature, and the four files it names. It never reads the
raw logs — the digests are what was signed, and the digests are what it checks.

## Running it

Python 3.11+.

```
pip install -r requirements.txt
python gen.py --scenario baseline
python verify.py runs/baseline
```

`gen.py` regenerates a run folder byte-for-byte; `runs/` is committed so the artifacts can be
verified without regenerating them. Scenarios: `baseline`, `sandbox_leak`, `proxy_escape`,
`proxy_writeback`.

`keys/lab.key` is a **throwaway demo key, committed on purpose** so anyone can reproduce the
signature. Nothing about this PoC's key handling resembles how a real attestation key would live.

## Scenarios

Four runs, four verdicts, one verifier that cannot tell them apart in advance. The scenario
name appears nowhere in the artifacts — only in the folder name — so the verdict comes from the
evidence, not from a label. Output below is verbatim.

| scenario | sandbox | proxy | verdict | exit |
|---|---|---|---|---|
| `baseline` | clean | clean | PASS | 0 |
| `sandbox_leak` | `10.0.5.7:22` not in policy | clean | FAIL | 1 |
| `proxy_escape` | clean | `198.51.100.8:443`, `198.51.100.44:443` not in policy | FAIL | 1 |
| `proxy_writeback` | upload 6.6 MB > 2 MB limit; in/out 6.4 < 20 | clean | PASS with ALERTS | 0 |

### baseline — nothing to report

The shape a clean run makes. Both boundaries talked only to declared destinations, within the
volumes the policy expects.

```
$ python verify.py runs/baseline

PASS

  signature ok    files 4/4    sandbox ok    proxy ok
```

### sandbox_leak — a destination the sandbox was never allowed

Three SSH connections to an internal host on `10.0.5.7:22`. Small — 2.7 KB out, rounding to
0.0 MB — and that is the point: the check is *declared or not declared*, not *large or small*.
A volume threshold would have missed this.

```
$ python verify.py runs/sandbox_leak

FAIL

  sandbox  10.0.5.7:22  not in policy   3 conns   0.0 MB out

  signature ok    files 4/4    sandbox FAIL    proxy ok
```

### proxy_escape — the case the second boundary exists for

The proxy reached an external code sandbox and a paste service on the sandbox's behalf. At the
sandbox boundary this run is **indistinguishable from baseline**: the sandbox only ever spoke to
`10.0.1.5:443`, exactly as policy allows. Only the proxy's own log shows where the traffic
actually went. Attest one hop and this passes.

```
$ python verify.py runs/proxy_escape

FAIL

  proxy    198.51.100.44:443  not in policy    60 conns   0.1 MB out
  proxy    198.51.100.8:443   not in policy   400 conns   1.5 MB out

  signature ok    files 4/4    sandbox ok    proxy FAIL
```

### proxy_writeback — an allowed destination used the wrong way

Every destination here is declared, so nothing is "not in policy". But a package proxy should
be a download path: bytes flow in, not out. This run pushes 6.6 MB up to a destination budgeted
for 2 MB, and inverts the traffic shape — 6.4 bytes in per byte out, against an expected 20.
That is ALERT, not FAIL: the evidence says *look at this*, not *this is forbidden*.

```
$ python verify.py runs/proxy_writeback

PASS with ALERTS

  sandbox  10.0.1.5:443  out 6.6 MB, limit 2.0 MB
  sandbox  10.0.1.5:443  in/out 6.4, expected >= 20

  signature ok    files 4/4    sandbox ALERT    proxy ok
```

### Tamper resistance

The digests are bound to the manifest by hash, and the manifest to the lab by signature, so the
two obvious edits fail in different places:

```
# doctor a digest to hide a destination -> the manifest hash catches it

FAIL

  files    digest_proxy.json  hash mismatch

  signature ok    files 3/4    sandbox ok    proxy ok

# also fix the manifest so the hash matches -> the signature catches it

FAIL

  signature invalid

  signature FAIL    files -    sandbox -    proxy -
```

Verifying with any key other than the one that signed the run exits 2.


## What this does not establish

- **Log honesty.** The lab controls the log between capture and hashing, so a lab willing to edit
  its own flow logs before the digest step defeats every check here. The next step is a timestamped
  commitment of log chunks to a public transparency log, and after that hardware-attested capture.
- **Abuse of allowed destinations under the thresholds.** Traffic to a declared destination that
  stays below `max_out_bytes` and above `min_in_out_ratio` passes silently. Exfiltration shaped to
  look like a package install is not caught by this.
- **Policy quality.** Publishing a policy makes it reviewable, not correct. A policy that allows
  too much passes cleanly.
- **A proxy shared across runs.** This PoC scopes the proxy digest to a single run. In practice the
  proxy boundary must be attested per time window across every run that used it, or one run's
  traffic hides inside another's.
- **Threshold calibration.** The numbers in the policies are illustrative. Real values come from a
  baseline of known-clean runs, not from a spec.

Also out of scope for v1: privacy mode (hashed destinations), multi-run proxy windows, external
nonce issuance, the DNS boundary, and any third hop beyond the proxy.

## Prior art

- Brundage et al. 2020, *Toward Trustworthy AI Development* — verifiable claims as the frame for
  auditable statements about an AI system's development.
- SLSA and in-toto — signed build provenance binding artifacts to the process that produced them.
- Sigstore — transparency logs for signatures, the model for making a commitment publicly checkable.
- AWS VPC Flow Logs — the record format used here for boundary capture.
