"""obs - obs-websocket 5.x client tools for the operator's OWN streaming rig.

LOCAL STUDIO CONTROL AND ENUMERATION, NOT A TARGET. This module talks to a
websocket server the operator runs on their own machine. It is deliberately
outside the scope gate: the gate wraps check_scan (nmap, masscan, ffuf, hydra,
ZAP open/spider/ajax/active-scan, send_raw) and check_send (packetcraft
send_packet) - a websocket to your own OBS is in neither set. Do not read
"no gate hit" here as evidence anything on a network was touched.

Connection parameters come ONLY from the environment (see obs_status), never
from arguments, so a password cannot leak into a tool call, a journal row, or
a report. obs_status performs NO network I/O at all.

Env sourcing - this module loads its OWN config files at import (see the
.env bootstrap block for the full rationale): <framework>/.env, then
<WORKSPACE_ROOT>/.env, then /etc/daharness/daharness.env (the deb conffile
the systemd units run with via EnvironmentFile, so a lane sourcing nothing
else still agrees with what the units see). First writer of a key wins:
shell exports beat the files, earlier files beat later ones (override/=
False, the "never clobber an already-set process env" rule documented in the
bootstrap block). obs_status.env_loaded reports which files were actually
consumed by THIS process; config edits need a fresh process, same as every
other .env consumer in the harness.

Verification ladder, in order - the whole point of this module is that each
rung is distinguishable, because "it didn't work" has four very different
causes on this box:

  config   -> are the env vars present and is the URL well-formed?
  routing  -> can THIS lane reach that host at all (the kernel is route-fenced:
              one link-local route, gateway 00000000, DNS = 127.0.0.11). A
              failure here means "wrong lane", NOT "OBS is down".
  transport-> TCP connect + WS upgrade succeeded
  identify -> Hello/opCode 0 -> Identified/opCode 5, plus rpcVersion negotiated
  auth     -> password challenge/salt math (only if OBS demanded it)
  rpc      -> GetVersion returned requestStatus.code == 0

Read and write are SPLIT (operator decision, 2026-11-21). obs_status,
obs_probe, obs_enumerate and obs_event_peek are read-only: they never send a
request that changes studio state. obs_request is the write path and is
default-deny twice over (see _write_allowed). Scene switches, source toggles
and start/stop-recording happen ONLY when the operator has opted in through
the environment.

Protocol constants below come from the obs-websocket 5.x spec. They are NOT
verified against a live OBS from inside this container (no route to one). The
tools report whatever the server actually says (raw responseData) instead of
reshaping it, so a version mismatch shows up as data rather than as a lie.
"""

import logging
from pathlib import Path

from constants import (
    framework_tool,
    resolve_framework_root,
    resolve_workspace_root,
)

# ---- .env bootstrap (module scope, BEFORE the first getenv) ----------------
# The config contract of this module is "everything comes from the process
# environment, never from tool arguments" (_cfg reads os.getenv only, so a
# password can never leak into a tool call). But a bare os.getenv() WITHOUT a
# loader is only half that contract - the authoring mistake this block fixes.
# Nothing in the harness arms OBS_WS_* for every lane; the env channels and
# what each one sees:
#
#   systemd units (deb lane) - EnvironmentFile=/etc/daharness/daharness.env,
#     the conffile OBS_WS_URL is authored in. Only unit-spawned processes
#     (Brain sidecar, API gateway) inherit it.
#   operator shells - /etc/profile.d/daharness.sh exports exactly
#     WORKSPACE_ROOT + BRAIN_SOCKET and nothing else, so a REPL, VS Code
#     session or notebook lane started from a shell sees no obs vars at all.
#   python-dotenv - bootstrap.py, api_gateway.py, daharness/__init__.py and
#     the in-tree auxiliaries (convention set by
#     auxiliaries/program_scope.py) each load a .env at module scope.
#     Dacustoms tools are imported like any other module and get NO env
#     arming from anywhere, so a dacustoms module that wants env-driven
#     config MUST load it here, itself, before its first getenv.
#
# Files consulted in order - FIRST writer of a key wins, so a shell export
# (the profile.d doctrine: "a user-profile lane wins by exporting first")
# beats the files, and among them the later files only FILL GAPS:
#   1. <framework checkout>/.env    dev-tree .env - the same file bootstrap.py
#      and api_gateway.py load; in bind-mounted container lanes this resolves
#      to the mounted checkout's copy.
#   2. <WORKSPACE_ROOT>/.env        state-lane .env (dev tree: same file as
#      1; deb lane: /var/lib/daharness; dacustoms itself lives under this
#      root).
#   3. /etc/daharness/daharness.env the deb conffile - the EXACT file the
#      systemd units run with via EnvironmentFile, so a lane that sources no
#      other channel still ends up agreeing with what the units see.
# override=False is deliberate here, NOT a softening of the repo's override/
# =True convention (see auxiliaries/program_scope.py): that convention exists
# because sudo strips shell exports, so .env must beat an INHERITED env. This
# module's vars are authored with shell exports as a legitimate, documented
# channel, so the rule needed is "never clobber an already-set process env";
# anything the lane genuinely inherits (including under sudo) stays
# authoritative. If you need a file value to beat an inherited one, that is
# what deleting the export in the shell profile is for.
# Missing python-dotenv or an unreadable file degrades to "env as the lane
# already armed it" and must never break import/discovery.
# File edits apply to the NEXT process (this runs once, at import) - the
# same restart-for-config rule as every other .env consumer in the harness.
# To check what THIS process actually consumed, call obs_status and read
# env_loaded.
_ENV_LOADED = []    # diagnostics surface for obs_status

try:
    from dotenv import load_dotenv

    _ENV_CANDIDATES = (
        resolve_framework_root() / ".env",
        resolve_workspace_root() / ".env",
        Path("/etc/daharness/daharness.env"),
    )
    for _p in _ENV_CANDIDATES:
        if not _p.is_file():
            continue
        if load_dotenv(_p, override=False):
            _ENV_LOADED.append(str(_p))
except Exception:
    # python-dotenv absent or a candidate path blew up - keep the env exactly
    # as the lane armed it; config loading must never break tool import.
    logging.getLogger(__name__).debug(
        "swallowed exception in obs.py .env bootstrap", exc_info=True)

# opCode table, obs-websocket 5.x - from docs/generated/protocol.md (fetched
# 2026-11-22). THE DIRECTION MATTERS: Hello is sent by the SERVER, first frame
# after the upgrade. The client answers with Identify and waits for Identified.
# This module used to send a Hello itself (4.x muscle memory); real OBS 33.0.2 /
# obs-websocket 5.7.6 answered that with a close, 4006 UnknownOpCode,
# "Your request is missing an `op`" - the spec's own text for "the specified
# `op` was invalid or missing". Numbers are no longer load-bearing anywhere in
# this file: frames are classified by STRUCTURE (_kind_of), requests correlate
# by requestId. The table exists to be SENT correctly and REPORTED honestly.
OP_HELLO = 0                    # server -> client, immediately on connect
OP_IDENTIFY = 1                 # client -> server, our reply to Hello
OP_IDENTIFIED = 2               # server -> client, handshake complete
OP_REIDENTIFY = 3               # client -> server, change subscriptions later
OP_EVENT = 5                    # server -> client
OP_REQUEST = 6                  # client -> server
OP_REQUEST_RESPONSE = 7         # server -> client
OP_REQUEST_BATCH = 8            # client -> server
OP_REQUEST_BATCH_RESPONSE = 9   # server -> client

# RequestStatus codes, 5.x. Success is 100, NOT 0 - code 10 is NoError (an
# internal field-check marker). Treating 0 as success silently marked every
# successful 5.x reply as a failure.
RS_SUCCESS = 100
RS_NO_ERROR = 10

# WebSocketCloseCode values we can actually be handed, so a bare "4006" in a
# report is self-explaining instead of a fresh round of guessing.
CLOSE_CODES = {
    4002: "MessageDecodeError", 4003: "MissingDataField",
    4004: "InvalidDataFieldType", 4005: "InvalidDataFieldValue",
    4006: "UnknownOpCode - the `op` was invalid or missing",
    4007: "NotIdentified - a message was sent before Identify/after no Identified",
    4008: "AlreadyIdentified - Identify sent twice; use Reidentify",
    4009: "AuthenticationFailed", 4010: "UnsupportedRpcVersion",
    4011: "SessionInvalidated (UI Kick button - do NOT auto-reconnect)",
    4012: "UnsupportedFeature",
}

# EventSubscription bitfield, 5.x (the 4.x one - General/Input/Scenes/Filters/
# Misc/Volumes/UI/LowLevel - is what this table used to hold, which is how a
# "confirmed outbound subs=103" came to mean nothing). High-volume intents are
# opt-in: they are listed but NOT part of ALL.
CATEGORIES = {
    "General": 1 << 0, "Config": 1 << 1, "Scenes": 1 << 2, "Inputs": 1 << 3,
    "Transitions": 1 << 4, "Filters": 1 << 5, "Outputs": 1 << 6,
    "SceneItems": 1 << 7, "MediaInputs": 1 << 8, "Vendors": 1 << 9,
    "Ui": 1 << 10, "Canvases": 1 << 11,
    "InputVolumeMeters": 1 << 16, "InputActiveStateChanged": 1 << 17,
    "InputShowStateChanged": 1 << 18, "SceneItemTransformChanged": 1 << 19,
}
EVENTS_ALL = (1 << 12) - 1      # General..Canvases, per the spec's All helper

ENV_VARS = (
    "OBS_WS_URL", "OBS_WS_HOST", "OBS_WS_PORT", "OBS_WS_TLS",
    "OBS_WS_PASSWORD", "OBS_WS_TIMEOUT_S", "OBS_WS_INSECURE_TLS",
    "OBS_WS_CA_FILE", "OBS_WS_PROXY", "OBS_WS_ORIGIN",
    "OBS_WS_EVENT_CATEGORIES", "OBS_WS_ALLOW_WRITE", "OBS_WS_ALLOW_REQUESTS",
)

# Read verbs, 5.x names first. The trailing block keeps the 4.x names this
# module used to call: obs_request must still REFUSE them (so nobody "gets
# around" the read/write split with a stale name) even though a 5.x server
# would only answer them with 204 UnknownRequestType.
READ_ONLY_REQUESTS = (
    "GetVersion", "GetStats", "GetHotkeyList",
    "GetSceneList", "GetGroupList", "GetCurrentProgramScene", "GetCurrentPreviewScene",
    "GetSceneSceneTransitionOverride", "GetSceneItemList", "GetGroupSceneItemList",
    "GetSceneItemId", "GetSceneItemSource", "GetSceneItemTransform",
    "GetSceneItemEnabled", "GetSceneItemLocked", "GetSceneItemIndex",
    "GetSceneItemBlendMode",
    "GetInputList", "GetInputKindList", "GetSpecialInputs", "GetInputDefaultSettings",
    "GetInputSettings", "GetInputMute", "GetInputVolume", "GetInputAudioBalance",
    "GetInputAudioSyncOffset", "GetInputAudioMonitorType", "GetInputAudioTracks",
    "GetInputDeinterlaceMode", "GetInputDeinterlaceFieldOrder",
    "GetInputPropertiesListPropertyItems",
    "GetSourceActive", "GetSourceScreenshot", "GetSourceFilterKindList",
    "GetSourceFilterList", "GetSourceFilterDefaultSettings", "GetSourceFilter",
    "GetTransitionKindList", "GetSceneTransitionList", "GetCurrentSceneTransition",
    "GetCurrentSceneTransitionCursor",
    "GetStreamStatus", "GetRecordStatus", "GetReplayBufferStatus",
    "GetLastReplayBufferReplay", "GetVirtualCamStatus", "GetOutputList",
    "GetOutputStatus", "GetOutputSettings", "GetMediaInputStatus",
    "GetStudioModeEnabled", "GetMonitorList",
    "GetPersistentData", "GetSceneCollectionList", "GetProfileList",
    "GetProfileParameter", "GetVideoSettings", "GetStreamServiceSettings",
    "GetRecordDirectory", "GetCanvasList",
    # ---- 4.x names: refused as reads, and NOT sent by this module ----
    "GetStudioModeState", "GetSourceList", "GetProfile", "GetCurrentSceneCollection",
    "GetSpecialDirectories", "GetRelativeTimestamp", "GetOutputActive",
    "GetAdvancedAudioProperties", "GetAudioTracks", "GetSourceAudioSettings",
    "GetMonitorType", "GetMonitorNameList", "GetTransitionList", "GetCurrentTransition",
    "GetSceneSelectionState", "GetInputActiveState",
)


# -------------------------------------------------------------------------- config
def _cfg():
    """Resolve connection config from the environment. Never from arguments.

    Returns (cfg, problems). problems is a list of human-readable reasons the
    config is unusable; cfg is still returned so obs_status can echo it.
    """
    import os
    problems = []
    url = os.getenv("OBS_WS_URL", "").strip()
    host = os.getenv("OBS_WS_HOST", "").strip()
    port = os.getenv("OBS_WS_PORT", "4455").strip() or "4455"
    tls = os.getenv("OBS_WS_TLS", "").strip().lower() in ("1", "true", "yes", "on")
    if not url:
        if not host:
            problems.append("no OBS_WS_URL and no OBS_WS_HOST set")
            host = "127.0.0.1"
        url = f"{'wss' if tls else 'ws'}://{host}:{port}"
    scheme = url.split("://", 1)[0]
    if scheme not in ("ws", "wss"):
        problems.append(f"OBS_WS_URL scheme {scheme!r} is not ws/wss")
    try:
        timeout = float(os.getenv("OBS_WS_TIMEOUT_S", "8") or 8)
    except ValueError:
        problems.append("OBS_WS_TIMEOUT_S is not a number")
        timeout = 8.0
    cfg = {
        "url": url,
        "host": host or url,
        "port": port,
        "password_set": bool(os.getenv("OBS_WS_PASSWORD", "")),
        "timeout_s": timeout,
        "insecure_tls": os.getenv("OBS_WS_INSECURE_TLS", "").strip().lower() in ("1", "true", "yes", "on"),
        "ca_file": os.getenv("OBS_WS_CA_FILE", "").strip() or None,
        "proxy": os.getenv("OBS_WS_PROXY", "").strip() or None,
        "origin": os.getenv("OBS_WS_ORIGIN", "").strip() or None,
        "event_categories": [c.strip() for c in os.getenv("OBS_WS_EVENT_CATEGORIES", "").split(",") if c.strip()],
    }
    return cfg, problems


def _route_view():
    """What this lane can see of the network, WITHOUT sending anything.

    Included in every failure so 'unreachable' is never mistaken for 'OBS is
    down': on the fenced kernel lane the answer is usually 'wrong lane'.

    MINIMIZED ON PURPOSE. This block landed in a tool result and leaked the
    operator's upstream resolvers (2026-11-21) - resolvers identify a network
    and a provider, and this output flows into reports. Addresses are therefore
    classified and counted, kept only when loopback/link-local/Docker-internal,
    and hidden otherwise. OBS_WS_VERBOSE_LANE=1 restores them for live
    debugging of this very lane.
    """
    import ipaddress, os
    out = {"resolver_scope": None, "resolver_count": 0, "resolvers": None,
           "routes": [], "note": None, "redacted": None}
    try:
        with open("/etc/resolv.conf") as fh:
            addrs = [ln.split()[1] for ln in fh if ln.startswith("nameserver")]
    except OSError as exc:
        addrs = []
        out["resolver_scope"] = f"unreadable: {exc}"
    if addrs:
        def _local(a):
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                return False
            return ip.is_loopback or ip.is_link_local or a.endswith(".11")
        keep = [a for a in addrs if _local(a)]
        external = [a for a in addrs if not _local(a)]
        out["resolver_count"] = len(addrs)
        out["resolvers"] = keep or None
        if external:
            out["resolver_scope"] = (f"{len(external)} upstream/external resolver(s) - this lane "
                                     "has real host DNS, so a failure here is NOT the fence")
            if os.getenv("OBS_WS_VERBOSE_LANE", "").strip().lower() in ("1", "true", "yes", "on"):
                out["redacted"] = external
            else:
                out["redacted"] = ("hidden - upstream resolvers identify your network; "
                                   "set OBS_WS_VERBOSE_LANE=1 to show them")
    try:
        with open("/proc/net/route") as fh:
            rows = [ln.split("\t") for ln in fh.read().splitlines()[1:]]
            out["routes"] = [{"dest": r[1], "gw": r[2], "iface": r[0]} for r in rows]
            if len(out["routes"]) == 1 and out["routes"][0]["gw"] == "00000000":
                out["note"] = ("single default route - this lane is route-fenced; a host outside "
                               "the container is unreachable from here regardless of OBS state")
            else:
                out["note"] = f"{len(out['routes'])} route(s) - not the fenced kernel profile"
    except OSError as exc:
        out["routes"] = f"unreadable: {exc}"
    return out


def _flag(v):
    """Truthiness that survives the bridge.

    Bridge/JSON-schema wrappers hand scalar parameters over as STRINGS, so
    types_only=False can arrive as "false" - which is truthy in Python and
    silently inverts the flag. Same trap as `if not capture`.
    """
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def _strlist(v):
    """List, comma-string, or None -> list of stripped names (bridge-safe)."""
    if v is None or v == "":
        return None
    if isinstance(v, str):
        return [c.strip() for c in v.split(",") if c.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(c).strip() for c in v if str(c).strip()]
    return [str(v)]


def _why(exc):
    """Exception -> one honest line, with an OBS close code NAMED not just numbered.

    A bare "received 4006" sent us into a guessing game; the spec says what 4006
    means, so the message carries it.
    """
    txt = f"{type(exc).__name__}: {exc}"
    code = getattr(exc, "code", None) or getattr(getattr(exc, "rcvd", None), "code", None)
    if code in CLOSE_CODES:
        txt += f" [OBS close {code} = {CLOSE_CODES[code]}]"
    return txt


def _fail(reason, **extra):
    r = {"status": "Failed", "reason": reason, "lane": _route_view()}
    r.update(extra)
    return r


# -------------------------------------------------------------------------- async
def _run_async(coro, timeout):
    """Drive a coroutine from a sync tool body.

    Jupyter/the kernel already runs an event loop, so asyncio.run() raises
    'asyncio.run() cannot be called from a running event loop' - the naive
    version of this tool therefore fails ONLY in the kernel lane, which is the
    lane the diary and most traffic use. Offload to one worker thread with its
    own loop instead; works from any lane.
    """
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(asyncio.wait_for(coro, timeout))
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
        def _go():
            return asyncio.run(asyncio.wait_for(coro, timeout))
        return ex.submit(_go).result(timeout + 5)


def _auth_response(password, salt, challenge):
    """obs-websocket auth: secret = b64(sha256(password + salt)),
    authentication = b64(secret + challenge)."""
    import base64, hashlib
    secret = base64.b64encode(hashlib.sha256((password + salt).encode("utf-8")).digest()).decode("ascii")
    return base64.b64encode((secret + challenge).encode("utf-8")).decode("ascii")


def _op_of(frame):
    """(opcode, key) under whichever envelope key this server uses.

    'opCode' is the 5.0-era key; real OBS 33.0.2 / obs-websocket 5.7.6 answered
    with 'op'. Treated as observed data, never assumed.
    """
    for k in ("opCode", "op", "opcode", "op_type"):
        if k in frame:
            try:
                return int(frame[k]), k
            except (TypeError, ValueError):
                return None, k
    return None, None


def _d_of(frame):
    d = frame.get("d")
    return d if isinstance(d, dict) else {}


HELLO_MARKERS = ("rpcVersion", "obsStudioVersion", "obsWebSocketVersion")
IDENT_MARKERS = ("negotiatedRpcVersion",)
# 4.x fingerprints. If these show up we are talking to an obs-websocket 4.x
# server, which handshakes the OTHER way round; that is reported, not patched
# over with a guess.
LEGACY_MARKERS = ("authRequired", "passwordProtected")


def _kind_of(frame):
    """Classify a frame by STRUCTURE, not by opcode number.

    Why this exists: an earlier version of this file read that structure once,
    concluded from {'op': 0, 'd': {'obsStudioVersion': '33.0.2', ...}} that
    "Identified arrives at op 0", and baked that in as a constant. That frame
    was the server's HELLO - in 5.x the server sends Hello at op 0 and
    Identified at op 2 carries only negotiatedRpcVersion. Structure-first
    classification survives; opcode constants rot. Once a server's framing is
    observed it is reported, not hidden.
    """
    d = _d_of(frame)
    op, _key = _op_of(frame)
    # requestId may live inside d (5.x puts it there) OR at the frame top level.
    # A frame carrying requestStatus is a response even if neither location
    # carries an id - correlation then falls back to requestType.
    if "requestStatus" in d:
        return "response"
    if "results" in d and ("requestId" in d or "requestId" in frame):
        return "batch_response"
    if "requestId" in d or "requestId" in frame:
        return "response"
    if "eventType" in d or "updateType" in d:
        return "event"
    if any(m in d for m in IDENT_MARKERS):
        return "identified"
    if any(m in d for m in LEGACY_MARKERS):
        return "legacy_welcome"
    if any(m in d for m in HELLO_MARKERS) and "requestType" not in d:
        return "hello"
    if isinstance(d.get("type"), str) and "Authentication" in d["type"]:
        return "legacy_error"
    if "requestType" in d:
        return "request"          # typically a copy of something we sent
    if op == OP_IDENTIFIED and not d:
        return "identified"       # opcode as tiebreaker only, and it is reported
    return "unknown"


def _seq_kind(direction, frame):
    """Frame kind AS REPORTED, direction-aware.

    _kind_of is direction-blind on purpose - it answers "what did the SERVER
    say". Our own outbound frames carry the same markers, so an Identify was
    labelled "hello" (it carries rpcVersion) and a Request "response" (it
    carries requestId): a diagnostic field saying something it isn't, and
    fields like that are how this module spent a day chasing a phantom. For tx
    frames the opcode IS authoritative, because we wrote it.
    """
    kind = _kind_of(frame)
    if direction != "tx":
        return kind
    op, _key = _op_of(frame)
    return {OP_IDENTIFY: "identify", OP_REIDENTIFY: "reidentify",
            OP_REQUEST: "request", OP_REQUEST_BATCH: "request_batch"}.get(op, kind)


async def _await_kinds(conn, timeout, kinds, tap=None, what="reply"):
    """Read frames until one is classified in `kinds`; events are skipped.

    Returns (data_dict, wire_meta). wire_meta carries the envelope key(s) and
    every opcode number actually seen, so one probe hands back the server's
    real framing. On timeout the message INCLUDES the frame sequence - the
    reader sees what arrived instead of being told nothing arrived.
    """
    import asyncio, json
    deadline = asyncio.get_running_loop().time() + max(1.0, float(timeout))
    seen, keys = [], set()
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise RuntimeError(f"no {what} within timeout (frames seen: {seen})")
        frame = json.loads(await asyncio.wait_for(conn.recv(), remaining))
        if tap is not None:
            tap.append({"dir": "rx", "frame": frame})
        op, key = _op_of(frame)
        if key:
            keys.add(key)
        kind = _kind_of(frame)
        seen.append({"op": op, "op_key": key, "kind": kind})
        if kind in kinds:
            return _d_of(frame), {"kind": kind, "op": op, "op_key": key,
                                  "op_keys": sorted(keys), "frames": seen}
        if kind == "event":
            continue


async def _request(conn, request_type, request_data=None, timeout=8.0,
                   op_key="op", tap=None):
    """One request, correlated by requestId - never by opcode number.

    A missing requestStatus is tolerated (success when responseData is there)
    and REPORTED, because 'no status key' and 'status code 0' must not be
    silently conflated in the record.
    """
    import asyncio, json, uuid
    rid = uuid.uuid4().hex[:12]
    payload = {op_key: OP_REQUEST, "d": {"requestType": request_type, "requestId": rid}}
    if request_data:
        payload["d"]["requestData"] = request_data
    await conn.send(json.dumps(payload))
    if tap is not None:
        tap.append({"dir": "tx", "frame": payload})
    deadline = asyncio.get_running_loop().time() + max(1.0, float(timeout))
    skipped = []
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise RuntimeError(
                f"{request_type}: no reply correlated to requestId {rid} within timeout. "
                f"Skipped {len(skipped)} frame(s): {skipped[:8]}. If the skipped list shows the "
                f"reply for this requestType, correlation failed (requestId placement), not OBS.")
        frame = json.loads(await asyncio.wait_for(conn.recv(), remaining))
        if tap is not None:
            tap.append({"dir": "rx", "frame": frame})
        d = _d_of(frame)
        kind = _kind_of(frame)
        frame_rid = frame.get("requestId")
        if kind == "response" and (d.get("requestId") == rid or frame_rid == rid \
                                   or d.get("requestType") == request_type):
            status = d.get("requestStatus")
            notes = []
            if status is None:
                code, result, comment = None, None, None
                notes.append("no requestStatus key in reply - treated as success")
            else:
                code, result, comment = (status.get("code"), status.get("result"),
                                         status.get("comment"))
            # 5.x status codes: 100 is Success, 10 is NoError (an internal
            # field-check marker), 0 is Unknown. Reading "code not in (0, None)"
            # as failure - which this line used to do - makes EVERY successful
            # 5.x reply an error. That is a false-negative generator, not a
            # cosmetic bug: it would have reported a working OBS as broken.
            if code is not None and code not in (RS_SUCCESS, RS_NO_ERROR) \
                    and result is not True:
                raise RuntimeError(f"{request_type} requestStatus.code={code} "
                                   f"result={result} comment={comment!r} "
                                   f"(5.x: 100 == Success)")
            if code is None and result is False:
                raise RuntimeError(f"{request_type} requestStatus.result=False, no code")
            out = d.get("responseData")
            if out is None:
                out = d.get("data") if isinstance(d.get("data"), dict) else {}
                notes.append("responseData absent, used d.data")
            if not isinstance(out, dict):
                out = {"_value": out}
            if notes:
                out = dict(out)
                out.setdefault("_wire_notes", []).extend(notes)
            return out
        if kind == "input_error":
            raise RuntimeError(f"input error for {request_type}: {d}")
        skipped.append({"op": _op_of(frame)[0], "kind": kind})


async def _connect(cfg, rpc_version=1, categories=(), tap=None):
    """5.x handshake: server Hello -> our single Identify -> server Identified.

    Returns (conn, handshake_dict, auth_state, wire_meta). handshake_dict
    merges the Hello body (versions, auth challenge) with the Identified body
    (negotiatedRpcVersion) because callers want one view of "what the server
    said"; wire_meta keeps the provenance split (hello_fields / identified_fields)
    so the merge can never quietly conflate the two. The envelope key used
    OUTBOUND mirrors the key the server used INBOUND.

    Order is load-bearing and documented by the spec: a client may send nothing
    but one Identify before it is Identified (4007 NotIdentified otherwise), and
    a second Identify is 4008 - so auth goes IN the single Identify, not in a
    re-Hello.
    """
    import asyncio, json, uuid
    try:
        from websockets.asyncio.client import connect as _connect_impl
    except ImportError:                       # older websockets layouts
        from websockets import connect as _connect_impl

    bits = 0
    for c in categories:
        bits |= CATEGORIES.get(c, 0)

    common = {"open_timeout": cfg["timeout_s"], "max_size": 2 ** 22}
    if cfg["origin"]:
        common["origin"] = cfg["origin"]

    if cfg["ca_file"] or cfg["insecure_tls"] or cfg["url"].startswith("wss"):
        import ssl
        if cfg["ca_file"]:
            ctx = ssl.create_default_context(cafile=cfg["ca_file"])
        elif cfg["insecure_tls"]:
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.create_default_context()
        common["ssl"] = ctx

    conn = None
    last_exc = None
    for compression in ("default", None):   # websocketpp's server has had
        kw = dict(common)                   # permessage-deflate quirks; if the
        if compression is None:             # upgrade dies oddly, retry bare.
            kw["compression"] = None
        if cfg["proxy"]:
            kw["proxy"] = cfg["proxy"]
        try:
            conn = await _connect_impl(cfg["url"], **kw)
            break
        except TypeError as exc:            # e.g. this build rejects proxy=
            last_exc = f"connect kwargs rejected: {exc}"
            break
        except Exception as exc:
            last_exc = f"{type(exc).__name__}: {exc}"
    if conn is None:
        raise OSError(last_exc or "connect failed")

    # The server speaks FIRST. Waiting for its Hello before sending anything is
    # the whole 5.x handshake; the previous version sent its own Hello here and
    # was closed with 4006 for lacking an `op`.
    hello_body, hw = await _await_kinds(conn, cfg["timeout_s"],
                                        ("hello", "legacy_welcome"), tap, "server Hello")
    if hw["kind"] == "legacy_welcome":
        await conn.close()
        raise RuntimeError("server handshakes as obs-websocket 4.x "
                           f"(its first frame carries {sorted(hello_body)}); this module "
                           "speaks 5.x Hello/Identify/Identified. Needs a 4.x path or "
                           "5.x enabled in OBS - not a silent fallback")
    op_key = hw.get("op_key") or "op"

    auth_state = "not_required"
    ident_out = {"rpcVersion": rpc_version}
    if bits:
        ident_out["eventSubscriptions"] = bits
    challenge = hello_body.get("authentication") or {}
    if challenge.get("salt") and challenge.get("challenge"):
        import os
        password = os.getenv("OBS_WS_PASSWORD", "")
        if not password:
            await conn.close()
            raise RuntimeError("server demands auth (Hello.authentication present) but "
                               "OBS_WS_PASSWORD is unset in this lane - and this module "
                               "will never take a password from a tool argument")
        ident_out["authentication"] = _auth_response(password, challenge["salt"],
                                                    challenge["challenge"])
        auth_state = "supplied_in_identify_unverified"

    identify = {op_key: OP_IDENTIFY, "d": ident_out}
    await conn.send(json.dumps(identify))
    if tap is not None:
        tap.append({"dir": "tx", "frame": identify})
    ident_body, iw = await _await_kinds(conn, cfg["timeout_s"], ("identified",),
                                        tap, "Identified")

    hand = dict(hello_body)
    hand.update(ident_body)
    wire = {"op_keys": sorted(set(hw["op_keys"]) | set(iw["op_keys"])),
            "op_key_outbound": op_key,
            "hello_op": hw["op"], "identified_op": iw["op"],
            "frames": hw["frames"] + iw["frames"],
            "hello_fields": sorted(hello_body),
            "identified_fields": sorted(ident_body),
            "auth_required_by_server": bool(challenge),
            "rpcVersion_offered_by_server": hello_body.get("rpcVersion"),
            "rpcVersion_requested": rpc_version,
            "rpcVersion_negotiated": ident_body.get("negotiatedRpcVersion"),
            "server_versions": {k: v for k, v in hello_body.items() if "ersion" in k},
            "event_subscriptions_sent": bits or None,
            "event_subscriptions_note": (None if bits else
                                         "none sent - server default is All (non-high-volume)")}
    return conn, hand, auth_state, wire



# -------------------------------------------------------------------------- tools
@framework_tool("Report obs-websocket configuration and lane reachability WITHOUT any network I/O: which OBS_WS_* variables are set (password masked, never echoed), the resolved URL, the protocol constants and event-subscription bitfield this module assumes, and what this lane's routing table says about whether it could reach that host at all. Use this FIRST, and use it to interpret every other obs_* failure - on the fenced kernel lane the answer is usually 'wrong lane', not 'OBS is down'. Does not connect, does not send, does not read the password value.")
def obs_status():
    cfg, problems = _cfg()
    return {"status": "ok",
            "config": {"url": cfg["url"], "host": cfg["host"], "port": cfg["port"],
                       "password_set": cfg["password_set"], "timeout_s": cfg["timeout_s"],
                       "insecure_tls": cfg["insecure_tls"], "ca_file": cfg["ca_file"],
                       "proxy": cfg["proxy"], "origin": cfg["origin"],
                       "event_categories": cfg["event_categories"]},
            "config_problems": problems,
            "env_seen": {k: ("set" if __import__("os").getenv(k) else "unset") for k in ENV_VARS},
            "env_loaded": _ENV_LOADED or None,
            "lane": _route_view(),
            "assumed_protocol": {"rpc_version": 1, "opCodes": {
                "Hello": OP_HELLO, "Identify": OP_IDENTIFY, "Identified": OP_IDENTIFIED,
                "Reidentify": OP_REIDENTIFY, "Event": OP_EVENT, "Request": OP_REQUEST,
                "RequestResponse": OP_REQUEST_RESPONSE, "RequestBatch": OP_REQUEST_BATCH,
                "RequestBatchResponse": OP_REQUEST_BATCH_RESPONSE},
                "sent_by_us": ["Identify", "Request"],
                "received_only": ["Hello", "Identified", "Event", "RequestResponse"],
                "envelope_keys": ["op", "d"],
                "requestStatus_success": RS_SUCCESS,
                "category_bits": dict(CATEGORIES),
                "note": "5.x handshake is SERVER-FIRST: the server sends Hello (op 0) the moment "
                        "the socket upgrades; we answer with exactly one Identify (op 1) and wait "
                        "for Identified (op 2). OBSERVED LIVE 2026-11-22 on OBS 33.0.2 / "
                        "obs-websocket 5.7.6: envelope key 'op', and a client-sent 'opCode'-keyed "
                        "Hello is closed with 4006 UnknownOpCode, 'Your request is missing an `op`'. "
                        "An earlier note here claimed 'Identified arrives at op 0' - that frame was "
                        "the server's Hello, misread by a version-field classifier. obs_probe returns "
                        "wire + frame_sequence + raw_frames so the mapping stays inspectable."},
            "write_path": "obs_request is default-deny; see OBS_WS_ALLOW_WRITE / OBS_WS_ALLOW_REQUESTS"}


@framework_tool("Walk the obs-websocket 5.x verification ladder against the operator's own OBS: TCP+WS upgrade, the server's Hello (op 0), our single Identify (op 1, auth string computed in-lane if the server demanded it), the server's Identified (op 2), then GetVersion. Returns a rung-by-rung result with the server's own raw version data, the observed wire framing (op keys, opcodes, field provenance) and, on failure, the lane routing view plus the named OBS close code - so an unreachable or misframed OBS is not misreported as a broken one. Read-only: sends Identify and GetVersion only. Requires OBS_WS_HOST or OBS_WS_URL in the environment.")
def obs_probe(rpc_version=1, capture=0):
    import asyncio
    cfg, problems = _cfg()
    if problems:
        return _fail("config incomplete", config_problems=problems, config=cfg["url"])

    tap = [] if int(capture or 0) > 0 else None
    async def _ladder():
        import json
        steps = {}
        conn, identified, auth_state, wire = await _connect(cfg, int(rpc_version), (), tap)
        steps["transport"] = "connected"
        steps["identified"] = True
        steps["server_says"] = {k: identified.get(k) for k in
                                ("obsStudioVersion", "obsWebSocketVersion", "rpcVersion",
                                 "negotiatedRpcVersion") if k in identified}
        steps["auth"] = auth_state
        try:
            steps["GetVersion"] = await _request(conn, "GetVersion", timeout=cfg["timeout_s"],
                                                 op_key=wire["op_key_outbound"], tap=tap)
        finally:
            await conn.close()
        steps["wire"] = {k: wire.get(k) for k in
                         ("op_keys", "op_key_outbound", "hello_op", "identified_op",
                          "hello_fields", "identified_fields", "auth_required_by_server",
                          "rpcVersion_offered_by_server", "rpcVersion_requested",
                          "rpcVersion_negotiated", "server_versions",
                          "event_subscriptions_sent")}
        steps["frame_sequence"] = [{"dir": f["dir"], "op": _op_of(f["frame"])[0],
                                    "op_key": _op_of(f["frame"])[1],
                                    "kind": _seq_kind(f["dir"], f["frame"])}
                                   for f in (tap or [])]
        if tap:
            steps["raw_frames"] = tap[:int(capture)]
        return steps

    try:
        steps = _run_async(_ladder(), cfg["timeout_s"] * 3)
    except Exception as exc:
        return _fail(_why(exc), attempted=cfg["url"])
    return {"status": "ok", "url": cfg["url"], "ladder": steps,
            "note": "server_says is OBS's own text, not reshaped"}


@framework_tool("Enumerate the operator's OBS studio state read-only over ONE websocket session, sequentially - one Request (op 6) and one RequestResponse per verb, NOT obs-websocket request batching (op 8 is defined by the protocol and deliberately not implemented here; batching is a known enhancement, not a current capability): version, scene list, program/preview scene, studio-mode state, inputs, stats, scene collections, profiles, recording/replay/virtualcam status, transitions, and per-scene item lists (bounded). Returns OBS's raw responseData per request plus one errors entry per failed request, so partial success is explicit rather than silent. Sends no state-changing request. Requires OBS_WS_HOST or OBS_WS_URL.")
def obs_enumerate(sources_limit=10, capture=0):
    cfg, problems = _cfg()
    if problems:
        return _fail("config incomplete", config_problems=problems, config=cfg["url"])

    # 5.x requestType names. The 4.x names this list used to carry
    # (GetStudioModeState, GetProfile, GetSpecialDirectories, GetTransitionList,
    # GetCurrentTransition) would each have come back 204 UnknownRequestType.
    base = ["GetVersion", "GetSceneList", "GetStudioModeEnabled", "GetCurrentProgramScene",
            "GetCurrentPreviewScene", "GetGroupList", "GetInputList", "GetStats",
            "GetSceneCollectionList", "GetProfileList", "GetRecordStatus",
            "GetReplayBufferStatus", "GetVirtualCamStatus", "GetSceneTransitionList",
            "GetCurrentSceneTransition", "GetOutputList"]

    _tap = [] if int(capture or 0) > 0 else None
    async def _walk():
        import json
        conn, identified, auth_state, wire = await _connect(cfg, 1, (), _tap)
        out = {"identified": {k: identified.get(k) for k in
                              ("obsStudioVersion", "obsWebSocketVersion", "rpcVersion",
                               "negotiatedRpcVersion") if k in identified},
               "wire": {k: wire.get(k) for k in ("op_keys", "op_key_outbound", "hello_op",
                                                 "identified_op", "hello_fields",
                                                 "identified_fields", "server_versions",
                                                 "rpcVersion_negotiated")},
               "auth": auth_state, "requests": {}, "errors": {}}
        try:
            for r in base:
                try:
                    out["requests"][r] = await _request(conn, r, timeout=cfg["timeout_s"],
                                                       op_key=wire["op_key_outbound"], tap=_tap)
                except Exception as exc:
                    out["errors"][r] = _why(exc)
            limit = max(0, int(sources_limit))
            scenes = (out["requests"].get("GetSceneList") or {}).get("scenes") or []
            out["scenes_seen"] = len(scenes)
            for sc in scenes[:limit]:
                name = sc.get("sceneName")
                if not name:
                    continue
                try:
                    out["requests"][f"GetSceneItemList:{name}"] = await _request(
                        conn, "GetSceneItemList", {"sceneName": name}, timeout=cfg["timeout_s"],
                        op_key=wire["op_key_outbound"], tap=_tap)
                except Exception as exc:
                    out["errors"][f"GetSceneItemList:{name}"] = _why(exc)
            if len(scenes) > limit:
                out["sources_truncated"] = {"limit": limit, "scenes": len(scenes),
                                            "note": "raise sources_limit to see the rest"}
        finally:
            await conn.close()
        return out

    try:
        data = _run_async(_walk(), cfg["timeout_s"] * 6)
    except Exception as exc:
        return _fail(_why(exc), attempted=cfg["url"])
    return {"status": "ok", "url": cfg["url"], **data}


@framework_tool("Sample the operator's OBS event stream for a bounded number of seconds (default 5) and return the observed eventType names (5.x calls it eventType; updateType is the 4.x spelling, still accepted on receive), counts, and up to N sample payloads with absolute wall-clock timestamps - the timestamps are what join to diary_log_event clip beats and to DaVinci Resolve marker times (stream.events.at_wall). Subscriptions are declared ONCE, in the Identify frame's eventSubscriptions bitfield, because obs-websocket 5 has no runtime subscribe request (Reidentify changes them mid-session, still unimplemented here); they come from OBS_WS_EVENT_CATEGORIES or the categories argument. Non-event frames are counted, never dropped silently. Read-only. Events are a firehose during a live stream: keep seconds short.")
def obs_event_peek(seconds=5, categories=None, max_samples=25, types_only=False):
    import time
    cfg, problems = _cfg()
    if problems:
        return _fail("config incomplete", config_problems=problems, config=cfg["url"])
    # categories arrives as a list from a notebook lane and as "General,Scenes"
    # from the bridge; the raw string used to be iterated CHARACTER BY CHARACTER
    # here, so every letter came back "unknown event categories".
    cats = _strlist(categories) or cfg["event_categories"] \
        or ["General", "Scenes", "Inputs", "Outputs", "Ui"]
    bad = [c for c in cats if c not in CATEGORIES]
    if bad:
        return _fail("unknown event categories", unknown=bad, known=sorted(CATEGORIES))
    secs = max(1, min(int(seconds), 120))

    async def _peek():
        import asyncio, json
        conn, identified, auth_state, wire = await _connect(cfg, 1, cats)
        counts, others = {}, {}
        ev_ops = set()   # opcode numbers this server uses for events - observed, not assumed
        samples = []   # ordered, not mapped: order IS the timeline
        deadline = asyncio.get_running_loop().time() + secs
        try:
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    frame = json.loads(await asyncio.wait_for(conn.recv(), remaining))
                except asyncio.TimeoutError:
                    break
                kind = _kind_of(frame)
                if kind != "event":
                    # nothing is dropped silently: non-event frames are counted
                    others[kind] = others.get(kind, 0) + 1
                    continue
                d = _d_of(frame)
                ev_ops.add(_op_of(frame)[0])
                ut = d.get("eventType") or d.get("updateType") or "?"  # 5.x says eventType
                counts[ut] = counts.get(ut, 0) + 1
                if not _flag(types_only) and len(samples) < max_samples:
                    samples.append({"at_wall": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                    "eventType": ut, "eventIntent": d.get("eventIntent"),
                                    "eventData": d.get("eventData")})
        finally:
            await conn.close()
        return {"requested_categories": cats, "requested_bits": sum(CATEGORIES[c] for c in cats),
                "wire": {k: wire.get(k) for k in ("op_keys", "op_key_outbound", "identified_op",
                                                  "server_versions")},
                "event_ops_observed": sorted(x for x in ev_ops if x is not None),
                # 5.x Identified carries ONLY negotiatedRpcVersion, so a None here
                # is the expected shape, not a gap in the tool.
                "server_supported_event_subscriptions": identified.get("supportedEventSubscriptions"),
                "event_subscriptions_sent": wire.get("event_subscriptions_sent"),
                "auth": auth_state, "seconds": secs, "eventTypes": counts, "other_frames": others,
                "samples": samples, "distinct_types": len(counts)}

    try:
        data = _run_async(_peek(), secs + cfg["timeout_s"] * 2)
    except Exception as exc:
        return _fail(_why(exc), attempted=cfg["url"])
    return {"status": "ok", "url": cfg["url"], **data}


def _write_allowed(request_type):
    """Double gate on the write path. Opt-in lives in the environment, not in a
    tool argument, so a stray call can never mutate a live stream."""
    import os
    if os.getenv("OBS_WS_ALLOW_WRITE", "").strip().lower() not in ("1", "true", "yes", "on"):
        return False, "OBS_WS_ALLOW_WRITE is not set - write path is closed"
    allowed = [r.strip() for r in os.getenv("OBS_WS_ALLOW_REQUESTS", "").split(",") if r.strip()]
    if not allowed:
        return False, "OBS_WS_ALLOW_REQUESTS is empty - no request type is permitted"
    if request_type not in allowed:
        return False, f"{request_type} is not in OBS_WS_ALLOW_REQUESTS"
    return True, "permitted"


@framework_tool("THE WRITE PATH - sends one state-changing obs-websocket request to the operator's own OBS (set a scene, toggle a source, rename, start/stop recording, adjust audio). Default-deny on THREE counts and there is no way to argue past them from the model side: OBS_WS_ALLOW_WRITE must be truthy in the environment, the exact requestType must appear in the OBS_WS_ALLOW_REQUESTS allowlist, and the confirm argument must repeat the requestType verbatim. Refuses anything in the read-only set so it cannot be used to re-read. This tool can interrupt a live stream - the operator opts in per request type.")
def obs_request(request_type, request_data=None, confirm=None):
    cfg, problems = _cfg()
    if problems:
        return _fail("config incomplete", config_problems=problems, config=cfg["url"])
    if request_type in READ_ONLY_REQUESTS:
        return _fail("use the read verbs for reads", requestType=request_type,
                     detail="obs_enumerate/obs_probe cover this; obs_request is write-only")
    ok, why = _write_allowed(request_type)
    if not ok:
        return _fail("write refused", detail=why, requestType=request_type)
    if confirm != request_type:
        return _fail("confirmation mismatch",
                     detail="confirm must equal requestType verbatim; nothing was sent")

    async def _do():
        conn, identified, auth_state, wire = await _connect(cfg, 1, ())
        try:
            return await _request(conn, request_type, request_data or {}, timeout=cfg["timeout_s"],
                                  op_key=wire["op_key_outbound"])
        finally:
            await conn.close()

    try:
        data = _run_async(_do(), cfg["timeout_s"] * 2)
    except Exception as exc:
        return _fail(_why(exc), requestType=request_type, sent=True)
    return {"status": "ok", "requestType": request_type, "response": data,
            "note": "response is OBS's own responseData"}
