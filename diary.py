"""Stream dev-diary tools - local Postgres DML only, never contacts a target.

Second-brain for HTB / local-lab streams: one row per stream session, one row
per timeline beat (cold_open, state, intent, grind, value, stuck, valve,
framework, later, wrap), plus clip-marker extraction for DaVinci Resolve and a
queryable box-by-box index for charts and the archive pipeline.

These tools deliberately do NOT log tool calls. The framework already keeps an
append-only dispatch spine in journal.entries across every lane - re-logging
dispatches here would duplicate it. What lives here is the narrative layer
(intent, stuck points, takeaways, next seeds, clip flags) and each event row
optionally carries a journal_ref pointing at the dispatch row that produced
it, so the two join on demand.

No DDL is executed by this module. The stream schema is operator authority: it
is created by postgres/init/005_stream_diary.sql. If that is missing,
diary_schema_status reports it rather than trying to self-create.
"""

from constants import framework_tool

# Beats are byte-stable: the archive pipeline and the Resolve marker list key
# on them, and the stream.events table enforces the same list with a CHECK.
BEATS = (
    "cold_open", "state", "intent", "grind", "value", "stuck",
    "valve", "framework", "later", "wrap",
)

# Beats the archive pipeline and the next session's STATE beat cannot work without.
REQUIRED_AT_WRAP = ("cold_open", "state", "intent", "wrap")


_STREAM_OK = None  # cached schema-presence probe; reset by diary_schema_status


def _conn():
    """Framework-owned Postgres connection (per-lane creds, endpoint ordering).

    Lazy import on purpose: the Brain startup scan imports this module, and
    touching the database at import time is a module-level side effect.
    """
    from utils.engagement import connect
    conn = connect()
    if conn is None:
        from utils.engagement import db_status
        raise RuntimeError(f"Postgres unavailable: {db_status()}")
    return conn


def _exec(sql, params=()):
    """One statement on the lane's SHARED connection.

    Never close it and always end the transaction: utils.engagement.connect()
    caches one connection per lane and hands the same object to the journal
    writer, so closing it or leaving a failed transaction open would break
    every other lane-facing store that asks for a connection next.
    """
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [d.name for d in cur.description] if cur.description else []
            rows = [dict(zip(cols, r)) for r in cur.fetchall()] if cols else []
        conn.commit()
        return rows
    except Exception:
        try:
            conn.rollback()          # clear aborted-transaction state
        except Exception:
            pass
        raise


_REMEDIATION = ("do not retry identically - check Postgres reachability and the lane's "
                "driver via dacustoms.diary.diary_schema_status, which reports "
                "db_status() reason and role")


def _failed(error, remediation, **extra):
    """Structured refusal, used ONLY where nothing was attempted.

    Follows the framework's own refusal envelope word ("Failed") instead of
    inventing a third vocabulary, so anything inspecting envelopes downstream
    reads one consistent status.
    """
    out = {"status": "Failed", "error": error, "remediation": remediation}
    out.update(extra)
    return {"status": "Failed", "result": out}


def _abort(exc):
    """Raise a genuine failure so the dispatcher journals status=error.

    Failure mode this replaces, verified live: a diary call that returned an
    error envelope was journaled status=ok / result_digest='Success', so a beat
    that never wrote was indistinguishable from one that did. Remediation travels
    inside the message so the model still gets guidance after the raise.
    """
    return RuntimeError(f"{type(exc).__name__}: {exc} | remediation: {_REMEDIATION}")


def _probe_failed(exc):
    """The status probe reports unavailability rather than raising: a probe that
    correctly diagnoses a broken connection is data, not a failed write."""
    detail = {"error": f"{type(exc).__name__}: {exc}"}
    try:
        from utils.engagement import db_status
        st = db_status()
        for k in ("role", "reason", "connected", "server"):
            detail[k] = st.get(k)
    except Exception as inner:
        detail["db_status_error"] = f"{type(inner).__name__}: {inner}"
    return {"status": "Failed", "result": detail}


def _fold(text, width=112):
    """Marker titles fold at a word boundary instead of truncating mid-word: a
    cut-off title is unusable as an edit point, and the summary is the only text
    the editor sees in the marker list."""
    text = (text or "").strip()
    if len(text) <= width:
        return text
    head = text[:width].rsplit(" ", 1)[0]
    tail = text[width:].strip().split(" ", 1)[0]
    return f"{head} ... {tail}"


@framework_tool(
    "Report whether the stream dev-diary schema exists and is usable: which of "
    "stream.sessions / stream.events are present, the current lane, the failure "
    "reason, and whether Postgres is reachable. Call this FIRST, before any other "
    "dacustoms.diary tool, and again after the operator re-runs 'sudo "
    "daharness-pg init'. It runs no DDL and writes nothing - if the schema is "
    "missing it only tells you, so the operator can create it."
)
def diary_schema_status() -> dict:
    global _STREAM_OK
    try:
        rows = _exec(
            "SELECT n.nspname AS schema, c.relname AS relation "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'stream' AND c.relkind IN ('r','v') "
            "ORDER BY c.relname"
        )
        found = sorted(r["relation"] for r in rows)
        _STREAM_OK = {"sessions" in found and "events" in found}
        return {"status": "ok", "result": {
            "ready": _STREAM_OK, "relations": found,
            "missing": [t for t in ("sessions", "events") if t not in found],
            "how_to_install": "operator re-runs 'sudo daharness-pg init' (idempotent; "
                             "005_stream_diary.sql is in the init bundle), then "
                             "re-embed + Brain restart if this module's text changed"}}
    except Exception as exc:
        _STREAM_OK = False
        return _probe_failed(exc)


@framework_tool(
    "Open (or idempotently refresh) one stream dev-diary session row: platform "
    "(htb|pg|lab), box name, difficulty, attempt number, start time, and the "
    "engagement slug that ties it to the scope registry. Returns the session_key "
    "that every other diary tool takes. Call once per stream at preheat, not per "
    "beat. Local database write only; never contacts a target."
)
def diary_open_session(platform: str, box: str, difficulty: str = "",
                       attempt_no: int = 1, slug: str = "",
                       started_at: str = "", note: str = "") -> dict:
    try:
        if slug == "":
            from utils.engagement import current_slug
            slug = current_slug() or ""
        rows = _exec(
            """
            INSERT INTO stream.sessions (slug, platform, box, difficulty,
                                         attempt_no, started_at, note)
            VALUES (%s, %s, %s, %s, %s, COALESCE(%s::timestamptz, now()), %s)
            ON CONFLICT (slug, box, attempt_no) DO UPDATE
               SET note = EXCLUDED.note
            RETURNING session_key, started_at
            """,
            (slug, platform, box, difficulty, attempt_no, started_at or None, note),
        )
        return {"status": "ok", "result": rows[0]}
    except Exception as exc:
        raise _abort(exc)


@framework_tool(
    "Append one dev-diary timeline event for a stream session: beat name "
    "(cold_open, state, intent, grind, value, stuck, valve, framework, later, "
    "wrap), a one-line summary, which screen it happened on, whether it is "
    "clip-worthy, an optional journal_ref pointing at the tool-dispatch row that "
    "produced it, and an optional suspected layer for framework beats. Call once "
    "per beat, during the stream, not retroactively in bulk. Does not log tool "
    "calls - journal.entries already does that. Append-only: never call this to "
    "rewrite an earlier event."
)
def diary_log_event(session_key: str, beat: str, summary: str, screen: int = 1,
                    clip: bool = False, at_wall: str = "",
                    journal_ref: int = 0, layer: str = "") -> dict:
    if beat not in BEATS:
        return _failed(f"unknown beat {beat!r}",
                       "beats are byte-stable because the archive pipeline keys on "
                       "them - pick one of allowed_beats",
                       allowed_beats=list(BEATS))
    try:
        rows = _exec(
            """
            INSERT INTO stream.events (session_key, beat, summary, screen, clip,
                                       at_wall, journal_ref, layer)
            VALUES (%s, %s, %s, %s, %s,
                    COALESCE(%s::timestamptz, now()),
                    NULLIF(%s, 0), NULLIF(%s, ''))
            RETURNING event_id, at_wall
            """,
            (session_key, beat, summary, screen, clip, at_wall or None,
             journal_ref, layer),
        )
        return {"status": "ok", "result": rows[0]}
    except Exception as exc:
        raise _abort(exc)


@framework_tool(
    "Close a stream dev-diary session with the wrap fields: the one-sentence cold open (written last), two or three takeaways, and two or three concrete "
    "next seeds that the next session's state beat reads back. Call once, at wrap, before the stream ends. Column-scoped update - it cannot change what "
    "the session was, only how it closed. IMPORTANT: this does NOT insert a 'wrap' timeline event. Timeline and session summary are independent on "
    "purpose - log the beat with dacustoms.diary.diary_log_event(beat='wrap'), then confirm the record with dacustoms.diary.diary_verify_session."
)
def diary_close_session(session_key: str, cold_open: str, takeaways: list,
                        seeds: list, ended_at: str = "") -> dict:
    try:
        import json
        rows = _exec(
            """
            UPDATE stream.sessions
               SET cold_open = %s, takeaways = %s::jsonb, seeds = %s::jsonb,
                   ended_at = COALESCE(%s::timestamptz, now())
             WHERE session_key = %s
            RETURNING session_key, ended_at
            """,
            (cold_open, json.dumps(takeaways or []), json.dumps(seeds or []),
             ended_at or None, session_key),
        )
        if not rows:
            return _failed(f"no session {session_key!r}",
                           "open the session first with dacustoms.diary."
                           "diary_open_session; nothing was written")
        return {"status": "ok", "result": rows[0]}
    except Exception as exc:
        raise _abort(exc)


@framework_tool(
    "Extract the clip-marker list for one stream session as absolute wall-clock "
    "timestamps plus titles, in the form an editor pastes into DaVinci Resolve or "
    "an archive pipeline consumes. Returns plain text markers and the matching "
    "rows. Call at wrap, and again on request while live - it is read-only."
)
def diary_markers(session_key: str) -> dict:
    try:
        rows = _exec(
            "SELECT at_wall, beat, summary, layer FROM stream.events "
            "WHERE session_key = %s AND clip ORDER BY at_wall",
            (session_key,),
        )
        lines = [f"{r['at_wall']:%H:%M:%S}  {_fold(r['summary'])}" for r in rows]
        return {"status": "ok", "result": {"count": len(rows),
                                          "markers": "\n".join(lines),
                                          "rows": rows}}
    except Exception as exc:
        raise _abort(exc)


@framework_tool(
    "Query the dev-diary index: one row per box with attempt count, rounded hours logged, a COUNT of stuck events, a COUNT of valve events, and the "
    "session cold_open. Optional box filter, newest first. Returns counts only - it does NOT rank stuck points and does NOT evaluate whether a break "
    "unblocked a box; that needs a timeline-aware query this tool deliberately does not pretend to be. Use it to decide what to box next and as the "
    "source rows for diary stat charts. Read-only; never call it to update anything."
)
def diary_index(box: str = "", limit: int = 50) -> dict:
    try:
        rows = _exec(
            """
            SELECT s.box, s.difficulty, COUNT(DISTINCT s.session_key) AS attempts,
                   ROUND(SUM(EXTRACT(EPOCH FROM (s.ended_at - s.started_at))) / 3600.0, 2)
                       AS hours,
                   COUNT(e.*) FILTER (WHERE e.beat = 'stuck')  AS stuck_events,
                   COUNT(e.*) FILTER (WHERE e.beat = 'valve')  AS valves,
                   MAX(s.cold_open) AS cold_open
              FROM stream.sessions s
              LEFT JOIN stream.events e ON e.session_key = s.session_key
             WHERE NULLIF(%s, '') IS NULL OR s.box = %s
             GROUP BY s.box, s.difficulty
             ORDER BY MAX(s.started_at) DESC
             LIMIT %s
            """,
            (box, box, limit),
        )
        return {"status": "ok", "result": {"count": len(rows), "rows": rows}}
    except Exception as exc:
        raise _abort(exc)


@framework_tool(
    "Verify a dev-diary session's record before the stream ends: which beats exist and how many times each, which required beats (cold_open, state, "
    "intent, wrap) are MISSING, whether the session row is closed, and how many clip markers would be exported. Call at wrap, after diary_log_event and "
    "diary_close_session. A missing required beat is a defect in the record - report it, do not paper over it - because the archive pipeline and the next "
    "session's recap both key on those beats. Read-only: it writes nothing and cannot repair anything."
)
def diary_verify_session(session_key: str) -> dict:
    try:
        beats = _exec("SELECT beat, COUNT(*) AS n FROM stream.events "
                      "WHERE session_key = %s GROUP BY beat", (session_key,))
        present = {r["beat"]: r["n"] for r in beats}
        missing = [b for b in REQUIRED_AT_WRAP if b not in present]
        sess = _exec("SELECT ended_at, cold_open, takeaways, seeds FROM stream.sessions "
                     "WHERE session_key = %s", (session_key,))
        closed = bool(sess) and sess[0]["ended_at"] is not None
        cold = bool(sess) and bool(sess[0]["cold_open"])
        clips = _exec("SELECT COUNT(*) AS n FROM stream.events "
                      "WHERE session_key = %s AND clip", (session_key,))
        complete = (not missing) and closed and cold
        return {"status": "ok", "result": {
            "session_key": session_key, "complete": complete,
            "missing_required_beats": missing, "beats": present,
            "session_closed": closed, "cold_open_written": cold,
            "clip_markers": clips[0]["n"] if clips else 0,
            "remediation": (None if complete else
                            "log the missing beats with dacustoms.diary.diary_log_event "
                            "and the close fields with diary_close_session before the "
                            "stream ends"),
        }}
    except Exception as exc:
        raise _abort(exc)
