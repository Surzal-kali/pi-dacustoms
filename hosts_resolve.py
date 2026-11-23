"""hosts_resolve - /etc/hosts-aware forward resolution for LAB names.

Wraps the shipped `resolve_host` (`auxiliaries/dns_lookup.py`) with the step
that module lacks: an /etc/hosts lookup BEFORE public DNS. Why this exists:

The shipped `resolve_host` resolves through dnspython (its `_resolve_one`
always prefers `_dnspython_query`; `socket.getaddrinfo` — the path that
reads /etc/hosts — runs only on ImportError). Consequences on a lab box:

- a hostname that exists ONLY in kali's /etc/hosts (every HTB target:
  `connected.htb`, `box.htb`, ...) reads as "no records" — dnspython asks
  public resolvers, which legitimately have nothing for `.htb`;
- single-label service names (`kali`, `jupyter`, `open-webui`) are rejected
  outright by the shipped `_validate_hostname` regex.

Traffic tools don't have this blindness: `probe_web` resolves through libc
(reads /etc/hosts), as do the nmap CLI and `web_probe`'s dns-unresolved
message. Only the helper whose whole purpose is deciding WHAT TO BLESS
(`scope add-ip`) couldn't see /etc/hosts. This module closes that gap
without touching shipped code.

Order of resolution per hostname:
1. /etc/hosts (getent-style scan of the hosts file, both A and AAAA).
2. Shipped `resolve_host` (dnspython A/AAAA/CNAME, CNAME chain chased).

Every response is passive — /etc/hosts is a local file read, and the
wrapped public-DNS call never contacts the target. Same scope posture as
the shipped tool: deliberately NOT scope-gated, exists to feed the scope
workflow; never writes scope state itself.

Tools:
- :func:`hosts_resolve` — /etc/hosts-first A/AAAA for lab + public names
  (single-label names ARE accepted here).
- :func:`hosts_lookup_ip` — what /etc/hosts says about one name alone
  (no DNS call at all). Fastest way to answer "is this a hosts-file
  alias?"
"""

from __future__ import annotations

import logging
import re
import socket
from pathlib import Path
from typing import Any

from constants import framework_tool, resolve_framework_root

logger = logging.getLogger(__name__)

_MAX_HOSTS = 32
# Single-label + FQDN hostnames (lab service names like `kali` ARE legal).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _hosts_file() -> Path:
    """Path to the hosts file the Brain lane reads (kali's own)."""
    return Path("/etc/hosts")


def _parse_hosts() -> dict[str, list[dict[str, Any]]]:
    """Scan /etc/hosts into name -> [{value, source}] (first hit wins later).

    Returns a lowercase-name map with both A (IPv4) and AAAA (IPv6) entries.
    Comment lines and the hostname-local nonsense record are ignored.
    """
    entries: dict[str, list[dict[str, Any]]] = {}
    hosts = _hosts_file()
    try:
        text = hosts.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("swallowed exception reading /etc/hosts", exc_info=True)
        return {}

    for line in text.splitlines():
        # strip comments
        hash_idx = line.find("#")
        effective = line[:hash_idx].strip() if hash_idx != -1 else line.strip()
        if not effective:
            continue
        parts = effective.split()
        if len(parts) < 2:
            continue
        addr, names = parts[0], parts[1:]
        for name in names:
            low = name.lower().rstrip(".")
            if not low:
                continue
            bucket = entries.setdefault(low, [])
            bucket.append(
                {"value": addr, "ttl": None, "source": "/etc/hosts"}
            )
    return entries


def _hosts_lookup(name: str) -> list[dict[str, Any]]:
    return _parse_hosts().get(name.lower(), [])


def _validate_lab_hostname(h: str) -> str:
    """Like the shipped validator but single-label names ARE allowed."""
    h = (h or "").strip().rstrip(".")
    if not h or any(c in h for c in " :/?#*@\\") or "://" in h:
        raise ValueError(
            f"{h!r} is not a bare hostname (no scheme/path/wildcard/spaces)"
        )
    if _IPV4_RE.match(h):
        raise ValueError(
            f"{h!r} looks like an IP — hosts_resolve takes hostnames; use "
            "ptr_lookup for IP -> name"
        )
    if not _HOSTNAME_RE.match(h.lower()):
        raise ValueError(f"{h!r} does not parse as a hostname")
    return h.lower()


def _resolve_one_lab(hostname: str, timeout: float) -> dict[str, Any]:
    """"/etc/hosts first; FQDN misses chase public DNS; single-label
    names stop clean (public DNS does not serve them — they are compose
    service or hosts-alias names, answered by `getent hosts` in-lane).
    """
    name = _validate_lab_hostname(hostname)
    hosts_hits = _hosts_lookup(name)
    records: dict[str, list[dict[str, Any]]] = {}
    engine = "hosts-file"
    single_label = "." not in name

    if hosts_hits:
        # Split by address family for a shape identical to shipped output.
        records["A"] = [r for r in hosts_hits if ":" not in r["value"]]
        records["AAAA"] = [r for r in hosts_hits if ":" in r["value"]]
        resolved = [r["value"] for r in records["A"]] + [
            r["value"] for r in records["AAAA"]
        ]
    elif single_label:
        # Single-label names have no public-DNS life: the shipped
        # resolver would REJECT them (its regex demands a TLD dot) and
        # dnspython would NXDOMAIN/timeout. Defer to the container lane:
        # `getent hosts <name>` over the bridge service names is the
        # honest check for these.
        return {
            "hostname": name,
            "records": {},
            "resolved_ips": [],
            "engine": "none",
            "hosts_file_hit": False,
            "note": (
                "single-label name: not in /etc/hosts; public DNS does "
                "not serve bare labels. If it is a compose service name, "
                "resolve it in-lane: `getent hosts " + name + "`."
            ),
        }
    else:
        # FQDN miss -> the shipped resolver (dnspython, public DNS).
        from auxiliaries.dns_lookup import _resolve_one as _shipped_resolve

        shipped = _shipped_resolve(name, timeout)
        records = shipped["records"]
        resolved = shipped["resolved_ips"]
        engine = shipped.get("engine", "dnspython")

    return {
        "hostname": name,
        "records": records,
        "resolved_ips": resolved,
        "engine": engine,
        "hosts_file_hit": bool(hosts_hits),
    }


@framework_tool(
    "Resolve bare hostnames to IP addresses checking /etc/hosts FIRST, "
    "then public DNS — the lab-aware version of resolve_host. Built for "
    "lab targets that exist only in kali's /etc/hosts (connected.htb, "
    "*.htb) and single-label service names (kali, jupyter, open-webui) "
    "that public DNS will never answer: those resolve here instead of "
    "reading as 'no records'. Returns the same A/AAAA/CNAME record shape "
    "as resolve_host plus an engine field (hosts-file|dnspython) and "
    "hosts_file_hit. Operator-side next step is the same: bless the "
    "resolved IPs with 'scope add-ip' in the Tool REPL. Passive — the "
    "target is never contacted; never writes scope state itself.",
    next_hints=["probe_web", "run_nmap", "check_scope"],
)
def hosts_resolve(
    hostnames: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Resolve ``hostnames`` (/etc/hosts first, public DNS fallback).

    Args:
        hostnames: One or more bare hostnames — FQDN or single-label,
            e.g. ``"connected.htb kali jupyter"`` (comma or whitespace
            separated, max 32).
        timeout: Per-query public-DNS timeout in seconds (hosts-file hits
            never wait on the network).
    """
    import time

    raw = (hostnames or "").strip()
    if not raw:
        return {"status": "Failed", "error": "no hostnames provided"}
    parts = [p for p in re.split(r"[\s,]+", raw) if p.strip()]
    if len(parts) > _MAX_HOSTS:
        return {
            "status": "Failed",
            "error": f"too many hostnames ({len(parts)} > {_MAX_HOSTS})",
        }

    started = time.time()
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for h in parts:
        try:
            results.append(_resolve_one_lab(h, timeout))
        except ValueError as e:
            errors.append({"input": h, "error": str(e)})
        except Exception as e:  # noqa: BLE001 - never crash the batch
            errors.append({"input": h, "error": f"{type(e).__name__}: {e}"})

    all_ips = sorted({ip for r in results for ip in r["resolved_ips"]})
    hosts_hits = sum(1 for r in results if r.get("hosts_file_hit"))
    return {
        "status": "Success",
        "results": results,
        "errors": errors,
        "unique_ips": all_ips,
        "hosts_file_hits": hosts_hits,
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "engine='hosts-file' rows resolved from kali /etc/hosts — "
            "bless those IPs with 'scope add-ip <ip> <hostname>' in the "
            "Tool REPL; public-DNS rows carry the shipped resolve_host "
            "shape; engine='none' single-label rows are compose service "
            "names (getent hosts <name> in-lane) or hosts-file aliases "
            "that don't exist yet. This tool never writes scope state "
            "itself. Verify with check_scope before firing scans."
        ),
    }


@framework_tool(
    "Answer 'is this name ONLY an /etc/hosts alias?' — read kali's "
    "/etc/hosts for one hostname and return its A/AAAA entries with no "
    "network call at all. Useful before blessing a lab target: a "
    "hosts-file-only name has no public DNS life, so scope validation "
    "and any downstream tooling should expect a lab-local IP.",
    next_hints=["check_scope"],
)
def hosts_lookup_ip(hostname: str) -> dict[str, Any]:
    """Read /etc/hosts alone for ``hostname`` (single label accepted)."""
    try:
        name = _validate_lab_hostname(hostname)
    except ValueError as e:
        return {"status": "Failed", "error": str(e)}
    hits = _hosts_lookup(name)
    return {
        "status": "Success",
        "hostname": name,
        "entries": hits,
        "hosts_file_hit": bool(hits),
        "note": (
            "hosts_file_hit=false means the name is absent from kali's "
            "/etc/hosts — it may still resolve through public DNS (use "
            "resolve_host) or be a container service name (use "
            "'getent hosts <name>' in-lane)."
        ),
    }


__all__ = ["hosts_resolve", "hosts_lookup_ip"]
