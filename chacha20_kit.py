"""dacustoms.chacha20_kit — ChaCha20 helper for offline binary RE.

Etched 2026-11-22 after ``rev_crypt_of_the_undead`` (``binaries/rev_crypt_of_the_undead``):
an ELF whose ``chacha20_init_context``/``chacha20_xor`` used a key sitting in
``.rodata`` and an all-zero nonce/counter. The disassembly was the whole fight;
the arithmetic was ten lines. The reusable part is therefore the *parameter
hunt* — once ``iz`` hands you a key you still have to discover how the author
wrote state[12..15] (RFC 8439 32-bit counter at word 12 + 96-bit nonce, versus
Bernstein's original 64-bit counter split over words 12/13 + 64-bit nonce,
versus a counter that starts at 1 because block 0 was reserved).

Stdlib only, no sockets, no file writes, no scope gate: this is offline compute
over bytes you already extracted. The primitive is pinned to RFC 8439 known
answers (fetched from the RFC text, not typed from memory) — see
``chacha20_selftest``, and run it before trusting any decrypt below.
"""

import struct

try:
    from constants import framework_tool
except ImportError:  # pragma: no cover - lets the module be used standalone
    def framework_tool(_capability):
        def _wrap(fn):
            return fn
        return _wrap

_MASK = 0xFFFFFFFF
_SIGMA = b"expand 32-byte k"

# RFC 8439 A.1 test vector #1: key=0*32, nonce=0*12, counter=0
_RFC_A1_1 = ("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc"
             "8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c"
             "c387b669b2ee6586")
# RFC 8439 2.3.2: key=00..1f, nonce=000000090000004a00000000, counter=1
_RFC_232 = ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9a"
            "c3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9"
            "cbd083e8a2503c4e")


def _bytes_of(value, nbytes, what):
    """Accept hex ("4241...") or literal ASCII ("BRAINS...") for a key/nonce.

    RE inputs arrive both ways: ``iz`` shows the ASCII, ``px`` shows the bytes.
    """
    s = (value or "").strip()
    try:
        raw = bytes.fromhex(s)
        if len(raw) == nbytes:
            return raw
    except ValueError:
        pass
    raw = s.encode("utf-8", "surrogateescape")
    if len(raw) != nbytes:
        raise ValueError(f"{what} must be {nbytes} bytes: pass hex "
                         f"({nbytes * 2} chars) or a literal string of that "
                         f"length; got {len(raw)} bytes")
    return raw


def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & _MASK


def _quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & _MASK; x[d] ^= x[a]; x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & _MASK; x[b] ^= x[c]; x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & _MASK; x[d] ^= x[a]; x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & _MASK; x[b] ^= x[c]; x[b] = _rotl32(x[b], 7)


def _block(state, rounds=20):
    x = list(state)
    for _ in range(rounds // 2):
        _quarter_round(x, 0, 4, 8, 12); _quarter_round(x, 1, 5, 9, 13)
        _quarter_round(x, 2, 6, 10, 14); _quarter_round(x, 3, 7, 11, 15)
        _quarter_round(x, 0, 5, 10, 15); _quarter_round(x, 1, 6, 11, 12)
        _quarter_round(x, 2, 7, 8, 13); _quarter_round(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + state[i]) & _MASK for i in range(16)])


def _state(key, nonce, counter, counter_field=12):
    """sigma | key | counter/nonce tail. counter_field says which of the last
    four words holds the counter — that is exactly the wiring question the RE
    has to answer, so it stays a parameter rather than an assumption."""
    if not 12 <= counter_field <= 15:
        raise ValueError("counter_field must be 12..15 (the tail words)")
    st = list(struct.unpack("<4I", _SIGMA) + struct.unpack("<8I", key))
    tail = list(struct.unpack("<3I", nonce))
    st.append(counter & _MASK if counter_field == 12 else 0)
    for i in range(13, 16):
        st.append(counter & _MASK if i == counter_field else tail[i - 13])
    return st


def _stream(key, nonce, counter, nbytes, rounds=20, counter_field=12):
    st = _state(key, nonce, counter, counter_field)
    out = b""
    while len(out) < nbytes:
        out += _block(st, rounds)
        st[counter_field] = (st[counter_field] + 1) & _MASK
    return out[:nbytes]


def _printable_ratio(data):
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return round(good / len(data), 3)


def _ints(spec, default):
    if not spec:
        return list(default)
    return [int(t) for t in str(spec).replace(";", ",").split(",") if t.strip()]


@framework_tool(
    "Print the RFC 8439 known-answer status for this module's ChaCha20 core: "
    "A.1 test vector #1 and the 2.3.2 block-function vector (non-zero nonce and "
    "counter). Run it once before relying on any chacha20_xor/chacha20_hunt "
    "output in a fresh session — a hand-written primitive that silently mishandles "
    "counter carry or nonce placement will still hand you *plausible* garbage on "
    "short inputs. Offline, no I/O."
)
def chacha20_selftest() -> dict:
    v1 = _stream(b"\x00" * 32, b"\x00" * 12, 0, 64).hex()
    v2 = _stream(bytes(range(32)), bytes.fromhex("000000090000004a00000000"),
                 1, 64).hex()
    return {"status": "ok", "result": {
        "rfc8439_a1_1": "pass" if v1 == _RFC_A1_1 else "fail",
        "rfc8439_2_3_2": "pass" if v2 == _RFC_232 else "fail",
        "got": {"a1_1": v1, "2_3_2": v2},
        "want": {"a1_1": _RFC_A1_1, "2_3_2": _RFC_232},
        "all_pass": v1 == _RFC_A1_1 and v2 == _RFC_232}}


@framework_tool(
    "Generate raw ChaCha20 keystream (and the 16 state words) from a key/nonce/"
    "counter you recovered out of a binary. key: 64 hex chars or a 32-char "
    "literal straight from r2 'iz'; nonce: 24 hex chars or a 12-char literal; "
    "counter_field says which state word (12..15) the counter lives in — set it "
    "from what chacha20_init_context's stores actually show, e.g. 12 for RFC 8439, "
    "or the pair 12/13 for a 64-bit counter split across both. rounds=8/12 for "
    "reduced-round variants. Use it to compare your reconstruction word-by-word "
    "against the disassembled init. Offline compute, touches nothing."
)
def chacha20_stream(key: str, nonce: str = "0" * 24, counter: int = 0,
                    nbytes: int = 128, rounds: int = 20,
                    counter_field: int = 12) -> dict:
    k = _bytes_of(key, 32, "key")
    n = _bytes_of(nonce, 12, "nonce")
    nbytes = max(1, min(int(nbytes), 1 << 20))
    ks = _stream(k, n, counter, nbytes, rounds, counter_field)
    return {"status": "ok", "result": {
        "key_hex": k.hex(), "nonce_hex": n.hex(), "counter": counter,
        "rounds": rounds, "counter_field": counter_field,
        "state_words_after_block0": [f"0x{w:08x}" for w in
                                     struct.unpack("<16I", ks[:64])],
        "keystream_hex": ks.hex()}}


@framework_tool(
    "XOR a hex ciphertext against ChaCha20 keystream — one call, works in both "
    "directions (encryption is its own inverse). This is what finishes most "
    "'crypto' RE challenges once static analysis has surfaced the key: pass the "
    "key from 'iz', the nonce/counter read off the init function, and read the "
    "preview. printable_ratio >= 0.95 with a readable preview means the wiring is "
    "right; plausible-looking garbage usually means the nonce/counter packing is "
    "wrong rather than the cipher. ciphertext_hex may carry spaces/0x. Offline "
    "compute over bytes you already have — no target, no files, no scope gate."
)
def chacha20_xor(ciphertext_hex: str, key: str, nonce: str = "0" * 24,
                 counter: int = 0, rounds: int = 20,
                 counter_field: int = 12) -> dict:
    ct = bytes.fromhex(str(ciphertext_hex).replace(" ", "").replace("0x", ""))
    k = _bytes_of(key, 32, "key")
    n = _bytes_of(nonce, 12, "nonce")
    pt = bytes(a ^ b for a, b in zip(ct, _stream(k, n, counter, len(ct),
                                                 rounds, counter_field)))
    return {"status": "ok", "result": {
        "ct_len": len(ct), "plaintext_hex": pt.hex(),
        "printable_ratio": _printable_ratio(pt),
        "preview": pt[:200].decode("utf-8", "replace").replace("\n", "\\n"),
        "params": {"nonce_hex": n.hex(), "counter": counter,
                   "rounds": rounds, "counter_field": counter_field}}}


@framework_tool(
    "Blind-wire hunt for a ChaCha20 build: given only a key recovered from a "
    "binary, try the plausible nonce/counter/rounds/counter-word combinations and "
    "rank the decrypts by printable ratio, so the correct wiring stands out at "
    "~1.0 while near-misses stay visible. nonces is a comma-separated list of hex "
    "or literal values (empty = all-zero; useful guesses are the key's first/last "
    "12 bytes and the ciphertext's first 12 bytes when a nonce was prepended). "
    "counters/rounds/counter_fields likewise comma-separated. Use when the "
    "algorithm is clearly ChaCha20 but the init's state wiring is ambiguous, or "
    "when a nonce is stored somewhere the file already tells you. Offline: pure "
    "compute over supplied bytes."
)
def chacha20_hunt(ciphertext_hex: str, key: str, counters: str = "0,1,2",
                  nonces: str = "", rounds: str = "8,12,20",
                  counter_fields: str = "12,13", top: int = 10) -> dict:
    ct = bytes.fromhex(str(ciphertext_hex).replace(" ", "").replace("0x", ""))
    k = _bytes_of(key, 32, "key")
    nonce_specs = [x for x in str(nonces).split(",") if x.strip()] or ["0" * 24]
    cs, rs, fs = _ints(counters, [0, 1, 2]), _ints(rounds, [8, 12, 20]), \
        _ints(counter_fields, [12, 13])
    out = []
    for nspec in nonce_specs:
        n = _bytes_of(nspec, 12, "nonce")
        for c in cs:
            for r in rs:
                for f in fs:
                    pt = bytes(a ^ b for a, b in
                               zip(ct, _stream(k, n, c, len(ct), r, f)))
                    out.append({"nonce_hex": n.hex(), "counter": c,
                                "rounds": r, "counter_field": f,
                                "printable_ratio": _printable_ratio(pt),
                                "preview": pt[:120].decode("utf-8", "replace")
                                              .replace("\n", "\\n"),
                                "plaintext_hex": pt.hex()})
    out.sort(key=lambda d: -d["printable_ratio"])
    return {"status": "ok", "result": {
        "ct_len": len(ct), "tried": len(out),
        "top": out[:max(1, min(int(top), 50))],
        "next_hints": ["a top hit at 1.0 with readable preview is the wiring; "
                       "re-run chacha20_xor with exactly those params",
                       "if nothing reaches 0.9 the key is wrong or derived — "
                       "go back to axt @ <key addr> and watch for a KDF"]}}
