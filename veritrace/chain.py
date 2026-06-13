"""Tamper-evident hash chain for the reasoning ledger.

The whole point of Veritrace is that you do not have to trust the agent, you can
verify it. The ledger already writes every step into Splunk. This module makes
that ledger tamper-evident: each step carries the hash of the step before it, so
the entries form a chain anchored to the investigation. Change, drop, reorder or
insert a single step and the chain no longer recomputes, which is exactly the
property a chain of custody needs.

The digest covers the stable, human-meaningful fields of a step (its sequence,
kind, title, the reasoning text, the SPL it ran, the technique it mapped to, its
confidence and timestamp). It deliberately excludes raw evidence samples, which
can be large and are already addressable in Splunk, so the same digest recomputes
identically whether the step is in memory or read back out of Splunk.
"""

from __future__ import annotations

import hashlib

# Fields included in the digest, in a fixed order. All are present both on the
# in-memory Step and on the event read back from Splunk.
_FIELDS = ("seq", "kind", "title", "detail", "spl", "technique_id", "technique_name")
_SEP = "␟"  # a separator that will not appear in field values


def genesis(investigation_id: str) -> str:
    """The anchor the first step chains from, derived from the investigation id."""
    return hashlib.sha256(f"veritrace-genesis:{investigation_id}".encode()).hexdigest()


def _canonical(payload: dict) -> str:
    parts = [f"{k}={payload.get(k, '')}" for k in _FIELDS]
    conf = payload.get("confidence")
    parts.append("confidence=" + (f"{float(conf):.4f}" if conf not in (None, "") else ""))
    rc = payload.get("result_count")
    parts.append("result_count=" + ("" if rc in (None, "") else str(int(float(rc)))))
    parts.append(f"ts={payload.get('ts', '')}")
    return _SEP.join(parts)


def digest(prev_hash: str, payload: dict) -> str:
    """Hash of (previous hash + this step's canonical content)."""
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(b"\n")
    h.update(_canonical(payload).encode())
    return h.hexdigest()


def verify(investigation_id: str, steps: list[dict], expected_root: str | None = None) -> dict:
    """Recompute the chain over ``steps`` (ordered by seq) and report integrity.

    Returns a dict with: ok (bool), step_count, computed_root, expected_root,
    broken_at (the seq where the recomputation first diverged, or None), and a
    human-readable detail string. A genuine, untampered ledger returns ok=True
    with computed_root equal to the recorded root.
    """
    ordered = sorted(steps, key=lambda s: int(float(s.get("seq", 0))))
    prev = genesis(investigation_id)
    broken_at: int | None = None
    for step in ordered:
        stored_prev = step.get("prev_hash", "")
        if stored_prev and stored_prev != prev:
            broken_at = int(float(step.get("seq", 0)))
            break
        recomputed = digest(prev, step)
        stored_entry = step.get("entry_hash", "")
        if stored_entry and stored_entry != recomputed:
            broken_at = int(float(step.get("seq", 0)))
            break
        prev = recomputed
    computed_root = prev
    ok = broken_at is None and (expected_root is None or computed_root == expected_root)
    if broken_at is not None:
        detail = f"Chain broken at step {broken_at}: a ledger entry was altered, removed or reordered."
    elif expected_root is not None and computed_root != expected_root:
        ok = False
        detail = "Recomputed root does not match the sealed root: the ledger was tampered with."
    else:
        detail = f"Verified {len(ordered)} sealed steps. Chain of custody is intact."
    return {
        "ok": ok,
        "step_count": len(ordered),
        "computed_root": computed_root,
        "expected_root": expected_root,
        "broken_at": broken_at,
        "detail": detail,
    }
