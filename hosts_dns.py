"""dacustoms.hosts_dns — /etc/hosts-aware name resolution.

Etched 2026-11-23 after the KB doc-drift pass. The shipped helper
``auxiliaries/dns_lookup.py`` resolves through dnspython
(``_resolve_one`` l.95-128), which reads ``/etc/resolv.conf`` and **never**
consults ``/etc/hosts``; its ``getaddrinfo`` path (``_socket_resolve``,
l.80-82) is reached only on ``ImportError`` (l.105), and ``_dnspython_query``
swallows ``NXDOMAIN/NoAnswer/NoNameservers`` into ``[]`` (l.68-71). On this
box dnspython is installed, so the fallback never fires and a name that lives
*only* in kali's ``/etc/hosts`` — which is the single source of truth for lab
names, per ``lab-dns.md`` — reports back as "no records". That is the helper
you'd use to decide what to ``scope add-ip``, so the blind spot sits directly
in front of a blessing decision.

Traffic-sending lanes (nmap CLI, ``web_probe`` via libc) DO honour
``/etc/hosts``; this module gives the recon lane the same view, additively,
without touching the shipped code.

Posture: stdlib only at import (dnspython is an *optional* runtime import),
no file writes, no raw target sockets, no DNS beyond ordinary resolver
queries — same ungated-by-design standing as ``auxiliaries.dns_lookup``
(it is not in the gate's ``check_scan``/``check_send`` coverage). Executed
host-side by the Brain, ``/etc/hosts`` here means kali's, not a container's.
Precedence is hosts-file first, then dnspython, then libc ``getaddrinfo``, and
each answer carries the ``source`` that produced it — an empty result is never
ambiguous.
"""

import ipaddress
import re
import socket

try:
    from constants import framework_tool
except ImportError:  # pragma: no cover - lets the module be used standalone
    def framework_tool(_capability):
        def _wrap(fn):
            return fn
        return _wrap


_HOSTS_COMMENT = re.compile(r"(?:^|\s)#.*$")
_WHITESPACE = re.compile(r"\s+")


def _parse_hosts_text(text):
    """Parse hosts-file text into ``{name: [ip, ...]}``, family-tagged.

    Mirrors glibc's reader closely enough for lab use: ``#`` starts a comment
    anywhere, fields are whitespace-separated, ``ip name [alias ...]``, and
    malformed lines are counted rather than raised (a hand-edited lab file
    churns between HTB sessions and a typo must not kill resolution).
    """
    table = {}
    skipped = []
    for lineno, raw in enumerate((text or "").splitlines(), 1):
        line = _HOSTS_COMMENT.sub("", raw).strip()
        if not line:
            continue
        fields = _WHITESPACE.split(line)
        if len(fields) < 2:
            skipped.append({"line": lineno, "reason": "no names", "text": line})
            continue
        try:
            addr = ipaddress.ip_address(fields[0])
        except ValueError:
            skipped.append({"line": lineno, "reason": "bad address", "text": line})
            continue
        for name in fields[1:]:
            table.setdefault(name.lower(), []).append(
                {"ip": str(addr), "family": "AAAA" if addr.version == 6 else "A"}
            )
    return table, skipped


def _read_hosts(hosts_file):
    """Read a hosts file; returns (table, skipped, error)."""
    try:
        with open(hosts_file, "r", encoding="utf-8", errors="replace") as fh:
            table, skipped = _parse_hosts_text(fh.read())
        return table, skipped, None
    except OSError as exc:
        return {}, [], f"{type(exc).__name__}: {exc}"


def _dnspython_query(name, rdtype, timeout):
    """A/AAAA via dnspython if the library is importable; [] on any failure."""
    try:
        import dns.resolver
    except ImportError:
        return None  # library absent -> caller falls back to libc
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = timeout
        resolver.lifetime = (timeout or 5.0) * 2
        answers = resolver.resolve(name, rdtype)
    except Exception:  # noqa: BLE001 - mirrors shipped helper's swallow
        return []
    return [{"ip": str(getattr(r, "address", r)).rstrip("."),
             "family": rdtype} for r in answers]


def _libc_query(name):
    """getaddrinfo — the path that honours nsswitch/``/etc/hosts``."""
    out = []
    try:
        for info in socket.getaddrinfo(name, None):
            ip = info[4][0]
            family = "AAAA" if ":" in ip else "A"
            if not any(r["ip"] == ip for r in out):
                out.append({"ip": ip, "family": family})
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return out, None


def _split_hostnames(hostnames):
    if isinstance(hostnames, (list, tuple)):
        parts = [str(h).strip() for h in hostnames]
    else:
        parts = re.split(r"[,\s]+", str(hostnames or ""))
    seen, ordered = set(), []
    for p in parts:
        if p and p.lower() not in seen:
            seen.add(p.lower())
            ordered.append(p)
    return ordered


def _resolve_one(name, table, timeout, hosts_error):
    """Resolve one name with explicit precedence + provenance."""
    key = name.lower()
    trace = []
    if hosts_error:
        trace.append({"source": "hosts-file", "status": "unreadable",
                      "detail": hosts_error})
    hits = list(table.get(key, []))
    if hits:
        trace.append({"source": "hosts-file", "status": "hit",
                      "detail": f"{len(hits)} record(s)"})
        return {"hostname": name, "source": "hosts-file", "resolved_ips":
                [h["ip"] for h in hits], "records": hits, "trace": trace}
    trace.append({"source": "hosts-file", "status": "miss", "detail": "no entry"})

    dns_a = _dnspython_query(name, "A", timeout)
    dns_aaaa = _dnspython_query(name, "AAAA", timeout)
    if dns_a is None and dns_aaaa is None:
        trace.append({"source": "dnspython", "status": "absent",
                      "detail": "module not importable"})
    else:
        recs = (dns_a or []) + (dns_aaaa or [])
        trace.append({"source": "dnspython", "status": "hit" if recs else "empty",
                      "detail": f"{len(recs)} record(s)"})
        if recs:
            return {"hostname": name, "source": "dnspython", "resolved_ips":
                    [r["ip"] for r in recs], "records": recs, "trace": trace}

    libc, err = _libc_query(name)
    if libc:
        trace.append({"source": "getaddrinfo", "status": "hit",
                      "detail": f"{len(libc)} record(s)"})
        return {"hostname": name, "source": "getaddrinfo", "resolved_ips":
                [r["ip"] for r in libc], "records": libc, "trace": trace}
    trace.append({"source": "getaddrinfo", "status": "fail",
                  "detail": err or "no records"})
    return {"hostname": name, "source": None, "resolved_ips": [], "records": [],
            "trace": trace}


@framework_tool("Resolve hostnames the way the traffic tools see them: "
                "the /etc/hosts file first, then dnspython, then libc "
                "getaddrinfo, reporting which lane answered as 'source' "
                "with a per-lane 'trace'. Closes the blind spot where a "
                "lab name that exists only in /etc/hosts reads as 'no "
                "records'. PREFERRED over auxiliaries.dns_lookup.resolve_host "
                "when lab names may live in /etc/hosts — resolve_host ignores "
                "/etc/hosts entirely; keep resolve_host for CNAME-chased "
                "public names and ptr_lookup for reverse DNS (this tool does "
                "neither). Hosts-file hits mirror what libc honors; "
                "non-hosts names still go to unicast DNS (dnspython), not "
                "nsswitch/mDNS, so .local names resolve only via the hosts "
                "lane. Read-only, host-side (kali's /etc/hosts, not a "
                "container's). Ungated, passive.",
                next_hints=["check_scope", "probe_web", "run_nmap"])
def hosts_dns_lookup(hostnames, timeout=None, hosts_file="/etc/hosts"):
    """Resolve ``hostnames`` (comma/space-separated string or list).

    Args:
        hostnames: one or many names, e.g. ``"connected.htb,api.lab.local"``.
        timeout: per-query resolver timeout in seconds (default 5).
        hosts_file: hosts file to honour (default ``/etc/hosts``; host-side
            execution means this is kali's file, and it is the lab-name
            source of truth).

    Returns:
        ``{"status", "results": [{hostname, source, resolved_ips, records,
        trace}], "hosts_file", "hosts_entries", "hosts_skipped",
        "hosts_error", "unique_ips"}`` — ``source`` is the lane that answered
        (``hosts-file`` / ``dnspython`` / ``getaddrinfo`` / ``null``), and
        ``trace`` shows every lane it walked, so an empty answer is never
        ambiguous. Only a hosts-file hit is guaranteed to match what
        traffic tools see; dnspython/getaddrinfo answers are unicast-DNS
        views.
    """
    names = _split_hostnames(hostnames)
    if not names:
        return {"status": "rejected", "error": "no hostnames given"}
    table, skipped, hosts_error = _read_hosts(hosts_file)
    results = [_resolve_one(n, table, timeout, hosts_error) for n in names]
    ips = sorted({ip for r in results for ip in r["resolved_ips"]})
    return {
        "status": "success",
        "results": results,
        "hosts_file": hosts_file,
        "hosts_entries": len(table),
        "hosts_skipped": skipped,
        "hosts_error": hosts_error,
        "unique_ips": ips,
        "note": ("Bless a resolved IP with 'scope add-ip <ip> <hostname>' "
                 "(operator-side). This tool never writes scope state."),
    }


_FIXTURE_HOSTS = """\
# lab fixture — mimics a hand-edited kali /etc/hosts
10.10.10.50      connected.htb        connected
127.0.0.1        localhost            # inline comment
fd00::1          dual.lab.local
203.0.113.9      alias.lab.local   app.lab.local
notanip          broken.lab.local
"""


@framework_tool("Self-test for hosts_dns: parses an embedded hosts fixture "
                "with no file access or network, and asserts the "
                "hosts-file lane wins. Run before trusting lookups after a "
                "framework rebuild. This is a diagnostic, NOT a resolver.")
def hosts_dns_selftest():
    """Deterministic check of the parser and the precedence order.

    Returns ``{"status", "checks": [{name, ok, detail}], "passed", "failed"}``.
    """
    table, skipped = _parse_hosts_text(_FIXTURE_HOSTS)
    checks = [
        ("lab name parses", table.get("connected.htb", [{}])[0].get("ip")
         == "10.10.10.50", str(table.get("connected.htb"))),
        ("alias shared across names",
         table.get("app.lab.local", [{}])[0].get("ip") == "203.0.113.9",
         str(table.get("app.lab.local"))),
        ("ipv6 tagged AAAA",
         table.get("dual.lab.local", [{}])[0].get("family") == "AAAA",
         str(table.get("dual.lab.local"))),
        ("inline comment stripped",
         [r["ip"] for r in table.get("localhost", [])] == ["127.0.0.1"],
         str(table.get("localhost"))),
        ("malformed line skipped, not raised",
         any(s.get("reason") == "bad address" for s in skipped), str(skipped)),
        ("case-insensitive lookup",
         _resolve_one("CONNECTED.HTB", table, None, None)["resolved_ips"]
         == ["10.10.10.50"], "keys normalised on read, query lowercased"),
    ]
    probe = _resolve_one("connected.htb", table, None, None)
    checks.append(("hosts-file lane wins over resolver",
                   probe["source"] == "hosts-file"
                   and probe["resolved_ips"] == ["10.10.10.50"],
                   f"source={probe['source']}"))
    passed = sum(1 for _, ok, _ in checks if ok)
    return {
        "status": "success" if passed == len(checks) else "failed",
        "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks],
        "passed": passed,
        "failed": len(checks) - passed,
    }
