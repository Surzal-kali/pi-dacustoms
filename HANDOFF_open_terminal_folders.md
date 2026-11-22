# Open Terminal — per-user folder registration oddity

Written 2026-11-21, right after a live session that derailed twice on this
(once into profile-shell plumbing, once into compose binds) before the
actual mechanism was found. This note exists so the next session greps
the right lane on the first try.

## The mechanism (what "adding a folder" actually is)

The **open-terminal lane** (`ghcr.io/open-webui/open-terminal:slim` in
`dockered/docker-compose.yaml`) exposes working folders to the model
through **JSON files on disk**, not through compose mounts, env pins, or
the OWUI valves UI:

```
/var/lib/daharness/dacustoms/.open-webui/users/<owui-user-uuid>/folders/<sha256-of-path>.json
```

- File **name** = `sha256(abs_path_hex)` of the folder path (UTF-8, no
  trailing slash) + `.json`.
- File **content** = `{"path": "<abs path>"}` (39 bytes for the state-root
  paths; exact whitespace irrelevant — a leading space after `:` was
  present on some pre-existing files).
- The registration is **per OWUI user id** — the uuid segment of the path.
  A second operator needs their own three JSONs under their own
  `users/<uuid>/folders/`.

## Current registrations (uid 1000's OWUI user: 469c2fe3-9675-4fe3-8618-b7f3e3236b12)

| folder | file stem (sha256) |
|---|---|
| `/var/lib/daharness/dacustoms` | `d0d3170…0481` (pre-existing) |
| `/var/lib/daharness/dropbox` | `eda61bf4…966c` (2026-11-21) |
| `/var/lib/daharness/binaries` | `1885e09d…cd64` (2026-11-21) |
| `/var/lib/daharness/apk` | `a4a0db2f…8ad9` (2026-11-21) |

## Why no mount/env change was needed (the trap this note guards against)

`docker-compose.yaml` bind-mounts `/var/lib/daharness` (and `/run/daharness`)
**whole-root rw, PATH-identical** into jupyter and open-terminal already.
So `dropbox/`, `binaries/`, `apk/` ride along automatically and both lanes
resolve them identically with the host Brain (`WORKSPACE_ROOT=/var/lib/daharness`
pinned in each service's env; the tool modules fall back to
`resolve_workspace_root()/dropbox|binaries|apk` and read the same inodes).
Verified live 2026-11-21: write probes from both containers succeeded and
in-container resolution of the three roots printed the state-root paths.

**If a "make folder X available to open-terminal" request lands again:
it is a file-drop into the folders/ dir, nothing else.** The two wrong
lanes that wasted the session were (a) `/etc/profile.d/daharness.sh`
operator-shell env carry in the dadeb tree, and (b) explicit env pins in
the compose services — both are real mechanisms for *other* problems and
do not register folder picks.

## Adding one more folder (the one-liner)

```bash
python3 - <<'EOF'
import hashlib, os
d = "/var/lib/daharness/dacustoms/.open-webui/users/469c2fe3-9675-4fe3-8618-b7f3e3236b12/folders"
for path in ["/var/lib/daharness/pcaps"]:
    fp = os.path.join(d, hashlib.sha256(path.encode()).hexdigest() + ".json")
    with open(fp, "w") as f:
        f.write('{"path": "%s"}' % path)
    print("wrote", fp)
EOF
```

Verify by re-reading: hash of the path in the content must equal the
filename stem, and the file must list inside the container
(`docker exec dockered-open-terminal-1 ls .../folders/ | wc -l`).

## Git note

`.open-webui/` lives inside the dacustoms git worktree and shows as
untracked after a registration. It is operator-facing state, not module
code — decide deliberately whether to commit or keep untracked (git
status noise otherwise).
