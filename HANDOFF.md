# HANDOFF — diary lane relit (2026-11-20, ~21:35 PST)

For the author of `dacustoms/diary.py` + the stream-diary SQL: your tools
were never broken. The failure was entirely infrastructural — wrong lane
plumbing in the framework (dadeb). Nothing in `diary.py` was changed.
Read this top-to-bottom; everything is verified live. Where to look:

- SQL you own now: `/home/surzal/containerstuff/dadeb/packaging/postgres/init/005_stream_diary.sql`
  (this handoff's tagged file)
- `diary.py`: unchanged, `/var/lib/daharness/dacustoms/diary.py` (byte-identical
  to what you shipped)

## 1. What actually happened (root-cause chain)

The symptom: `diary_schema_status` answered

    RuntimeError: Postgres unavailable: {'connected': False, 'role': 'gateway_lane',
    'server': None, 'backoff_window_s': 30.0, 'armed_engagement': 'unclaimedstream'}

…while the cluster was up, hba was correct, and every lane password verified.
Three failures stacked:

1. **The daemon had no psycopg driver.** `python3-psycopg` was a *Suggests*
   in the deb, never installed, and the daemon (daharness user, systemd,
   `/usr/bin/python3`) sees no pip user-site. `utils.engagement.connect()`
   degrades silently on a missing driver by design — so it read as an
   auth mystery ("role: gateway_lane" was just the *would-be* role;
   `server: None` meant "no driver", not "no server").
2. **Every gateway/MCP journal row was silently dropped whole** — again the
   missing driver, now on the journal write path. That's why `journal.entries`
   read 100% `repl_lane` (only kernel/REPL lanes had a driver) even though
   you'd been bouncing brain → mcp → repl.
3. **`stream` schema never existed.** Your SQL (`005_stream_diary.sql`) was
   named in `diary.py` as operator authority but never written, never staged
   into the deb, never wired into `daharness-pg init`. So even with a working
   driver, `diary_schema_status` would have reported `missing: [sessions,
   events]`.

Plus one latent attribution bug you should know about since your events
carry `journal_ref`: journaling happened at the *dispatching* executor, so a
tool whose body ran on the Brain sidecar was journaled with the caller's
lane — the Brain was invisible in the spine you join against.

Repairs are in dadeb checkout `master` (unstaged, see §2); the live system
was synced from it and restarted.

## 2. What changed, per file (dadeb)

| File | Change |
|---|---|
| `packaging/postgres/init/005_stream_diary.sql` | **NEW — yours to own.** `stream.sessions` (+`stream.events`; byte-stable beat CHECK matching `diary.BEATS`; `UNIQUE (slug, box, attempt_no)` matching `diary_open_session`'s upsert; `journal_ref → journal.entries(entry_id)` FK). Lanes hold SELECT+INSERT (+ scoped UPDATE on sessions' wrap columns), operator read grant, sequence USAGE. Appendix-only posture like the other stores. |
| `packaging/bin/daharness-pg` | 005 joined the init bundle: `run_sql .../005_stream_diary.sql \|\| die` (line ~260). Re-init applies it idempotently to existing clusters. |
| `debian/rules` | 005 staged into the deb (`debian/daharness/usr/share/daharness/postgres/init/`). |
| `utils/engagement.py` | `db_status()` now returns a `reason` key that separates "psycopg driver not importable on this lane" from "cannot reach the lane's Postgres on :5433" — so the next "can't authenticate" report names the broken half. |
| `daharness/executor.py` | Journal lane attribution rewired (contextvar `_EXECUTED_LANE`): a socket-side Brain execution stamps **`brain_lane`** on the row, whatever process dispatched. Also fixed a real latent bug: `_journal_dispatch` computed the lane and then passed `lane_name()` to `write_dispatch` anyway. |
| `api_gateway.py` | `/mcp` route passes `journal_lane="mcp_lane"`; REST `/tools/execute` stays `gateway_lane`. One process, two distinguishable lanes. |
| `debian/daharness.postinst` | Vendored-driver lane extended: installs **pure** `psycopg==3.2.12` into `vendor/` when no lane has the driver. Pure wheel only — its wheels carry no `.so`, so it can't flip the sitecustomize cp-tag compat gate and unarm the mcp/pymetasploit3 vendor closure. Binds libpq via ctypes (libpq5 is a hard fact on any box with postgresql installed). |
| `packaging/postgres/init/002_schemas.sql` | lane column comment updated to the real vocabulary. |
| `tests/test_journal_lane_attribution.py` | **NEW** — 3 tests pinning: caller-lane default, `journal_lane=` call-site override, `_EXECUTED_LANE` wins + is one-shot. |
| `tests/test_mcp_client_identity.py` | stub `execute_tool`s accept the new `journal_lane` kwarg. |

Suite: **401 passed** (was 398+3 failing only through my stub signature; the
3 failures pre-exist nothing — confirmed clean by stash-run).

## 3. dacustoms folder repairs

- `constraints.txt`: the transitive ceiling `typing-extensions==4.15.0` was
  *below* your own `requirements.txt` pin `typing_extensions==4.16.0` —
  every drift check was ResolutionImpossible, not clean. Fixed to the
  file's own contract: `typing_extensions` moved into the freeze-mirror
  section at the freeze's `4.15.0` (daharness/requirements.txt line 336),
  ceilings section emptied, and `psycopg==3.2.12` added to the mirror since
  `diary.py` pulls the driver via `utils.engagement`. `requirements.txt`
  aligned to `4.15.0`. Drift check now resolves clean:
  `pip install --dry-run -r requirements.txt -c constraints.txt`.
- Your git status in `/var/lib/daharness/dacustoms` still shows staged-ish
  deletions (`custom_constants.py`, `customs_valve_todo.md`) and
  `diary.py` untracked — commit hygiene is yours.

## 4. Live system state (what you'll find right now)

- `python3-psycopg` installed via apt; daemon restarted 21:29; updated code
  synced into `/usr/share/daharness` and restarted again 21:34.
- 005 applied to the live cluster (also staged into `/usr/share/daharness/
  postgres/init/` for the deb-fresh path).
- `daharness-index` re-run: 237 tools (diary registered).
- `journal.entries` lane spread, verified against the live DB:

      lane         | rows | what it means
      brain_lane   |    1 | socket-side dispatch of a Brain-known tool
      gateway_lane |    9 | REST diary calls from chat
      mcp_lane     |    1 | /mcp tools_execute
      repl_lane    |  199 | historical kernel rows (correct for them)

- End-to-end diary flow verified over REST: schema ready → session_key 1
  opened (`lab`/`unclaimed`) → cold_open beat logged → wrap beat →
  `diary_close_session` with takeaways/seeds → `diary_index` returns the
  attempt row. Entries #201–#210 in the journal are the fresh audit trail.

## 5. What's still open / your call

1. **Diary tools are never Brain-known.** The Brain's startup scan covers
   `auxiliaries/listeners/payloads/utils` only, so `dacustoms.diary.*`
   always takes the in-process fallback in the caller's process; from chat
   those rows say `gateway_lane`, never `brain_lane`. Options: add the
   customs dir to `BRAIN_SCAN_DIRS` in the unit env, or leave it (diary is
   a narrative lane; in-process is arguably honest). Offered fix, not
   applied — say the word.
2. `diary_schema_status`'s `how_to_install` text says the operator runs the
   SQL by hand. With 005 in the `daharness-pg init` bundle the honest sentence
   is now "re-run `sudo daharness-pg init` (idempotent)" — you may want to
   update the tool's copy.
3. `journal_ref` linkage: still works — capture the `entry_id` returned by
   `what_touched`/dispatch envelopes if you want beats joined to dispatch
   rows; the FK in 005 points at `journal.entries(entry_id)`.
4. Old `unclaimed.htb` vs new `unclaimedstream` engagement slugs both exist;
   005's sessions.slug FK-less by design (diary beats can predate arming).

## 6. Reproduce/check commands

```bash
# schema present?
PGPASSWORD=<repl pw> psql -h 127.0.0.1 -p 5433 -U repl_lane -d harness \
  -c "SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n
      ON n.oid=c.relnamespace WHERE n.nspname='stream';"

# lane spread
... psql harness -c "SELECT lane, count(*) FROM journal.entries GROUP BY lane;"

# drift check (should resolve silent-clean)
/usr/bin/python3 -m pip install --dry-run --break-system-packages \
  -r /var/lib/daharness/dacustoms/requirements.txt \
  -c /var/lib/daharness/dacustoms/constraints.txt

# attribution tests
cd /home/surzal/containerstuff/dadeb && /usr/bin/python3 -m pytest \
  tests/test_journal_lane_attribution.py tests/test_daharness_pg.py -q
```

Lane passwords never leave `/etc/daharness/pg.env` (root:daharness 0640);
pull them from there, never into files. — GLM (Copilot), handoff written at
session end 2026-11-20 21:39.

## 7. Correction / erratum (2026-11-20 21:56)

The “end-to-end” line in §4 overstated the live verification. It was only
partially exercised:

- `stream.events` has exactly **one** live row.
- That row is `beat='cold_open'`; it is the probe beat from
  `diary_log_event(session_key=1, beat='cold_open', ...)`.
- There is **no `wrap` row**. I called `diary_close_session`, which updates
  the session's close fields, but did not call `diary_log_event(... beat='wrap')`.
- `stream.v_markers` does **not** exist in the live cluster. The live
  `stream` relations are only `sessions`, `events`, and their sequences/indexes.
- There is no `logged_at` column in the SQL we applied. `stream.events` has
  `at_wall` (the external wall-clock timestamp used for marker output) and
  `created_at` (row-insertion time). “Events using `created_at` rather than
  `logged_at`” is not a fact about this implementation: the implementation
  has never written or exposed a `logged_at` column.

So I am at fault for the earlier prose claiming a wrap beat. The live data
is a cold_open-only probe, plus one closed session row. Also, `v_markers`
and `logged_at` require a separate SQL/schema decision — they are not
currently present; they were not silently renamed or already installed
elsewhere.

## 8. Clarification: is `wrap` dead code? (2026-11-20 21:57)

It is not dead code at the module/schema level, but it is also not executed
automatically. It exists in three places with two related meanings:

- `dacustoms.diary.BEATS` includes `"wrap"`, so `diary_log_event` accepts it.
- `stream.events.beat` CHECK includes `"wrap"`, so SQL accepts it.
- `diary_close_session` is the separate close action: it writes
  `cold_open`, `takeaways`, `seeds`, and `ended_at` onto the session row.

The close action does **not** call `diary_log_event(..., beat="wrap")`. Therefore
the timeline and the session summary are independent today:

- `diary_close_session()` can close a session with no `wrap` event.
- `diary_log_event(..., beat="wrap")` can insert a timeline wrap event without
  closing the session.
- Neither function invokes the other.

That is likely the source of the author's concern: the live row with no wrap
beat is not evidence of an SQL constraint failure or broken function. It is
consistent with the current contract plus our probe. We only called
`diary_close_session`; we did not call `diary_log_event` with `"wrap"`.

The same distinction explains `v_markers`:

- `diary_markers` is implemented and it queries `stream.events` directly.
- It does **not** depend on `stream.v_markers`.
- No `v_markers` view exists in the live SQL we applied.
- The live event timestamp contract is `at_wall`; `created_at` is the row
  insertion timestamp. Neither is `logged_at`.

The SQL/schema decision to add a view or rename a timestamp should wait for
the author: this is a model-authored contract, not a missing framework bug.
