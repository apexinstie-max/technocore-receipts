#!/usr/bin/env python3
"""Prove technocore.py agrees with the upstream reference signer, byte for byte.

A signer that is subtly wrong does not fail loudly -- it produces a signature the
server refuses with a bare 403, or worse, one it accepts over text that differs
from what a later reader will see. Both upstream starter issues #8 and #9 are
this bug class. So rather than trust that our canonicalisation matches, we run
both implementations over the same adversarial corpus and compare.

Three independent implementations are cross-checked here:

  ours      technocore.py                     (cryptography)
  upstream  reference/sign.py                 (cryptography) -- flop-labs, Apache-2.0
  server    pynacl, the library src/didkey.py actually verifies with

The upstream functions are imported in-process rather than driven over argv,
because a NUL byte cannot survive a command line and NUL is exactly the kind of
character this needs to cover. A couple of cases are additionally run through the
upstream CLI to confirm the wiring, not just the maths.

Usage:  python conformance.py
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import technocore as ours

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "reference" / "sign.py"

# A fixed, throwaway, publicly-known seed. This is a test vector and nothing else:
# it must never be an identity, which is the point of keeping it in the open.
SEED = "00" * 32


def load_upstream():
    if not REFERENCE.exists():
        raise SystemExit(
            f"missing {REFERENCE}\n"
            "fetch it with:\n"
            "  curl -o reference/sign.py https://raw.githubusercontent.com/"
            "flop-labs/technocore-chat/main/scripts/sign.py"
        )
    spec = importlib.util.spec_from_file_location("upstream_sign", REFERENCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Every text below is a case where a naive implementation diverges. The comment
# says what it is, because half of them are invisible by construction.
CORPUS = [
    ("plain ascii", "hello"),
    ("internal spaces", "hello there world"),
    ("leading and trailing space", "   padded   "),
    ("zero width joiner", "a\u200db"),
    ("zero width space", "a\u200bb"),
    ("zero width no-break / BOM", "a\ufeffb"),
    ("soft hyphen", "a\u00adb"),
    ("bidi override", "a\u202eb"),
    ("bidi isolate", "a\u2066b\u2069c"),
    ("newline", "a\nb"),
    ("CRLF", "a\r\nb"),
    ("tab", "a\tb"),
    ("NUL", "a\x00b"),
    ("vertical tab and form feed", "a\x0bb\x0cc"),
    ("C1 control NEL", "a\x85b"),
    ("line separator", "a\u2028b"),
    ("paragraph separator", "a\u2029b"),
    ("private use", "a\ue000b"),
    ("lone surrogate", "a\ud800b"),
    ("NBSP survives (Zs, not swept)", "a\u00a0b"),
    ("emoji", "launch \U0001f680 now"),
    ("emoji ZWJ sequence", "family \U0001f468\u200d\U0001f469\u200d\U0001f467"),
    ("CJK", "\u4f60\u597d\u4e16\u754c"),
    ("RTL arabic", "\u0645\u0631\u062d\u0628\u0627"),
    ("combining marks", "e\u0327\u0301a"),
    ("pipe in the text", "a|b|c"),
    ("pipe-heavy, canonical-ambiguous", "lobby|1|spoofed"),
    ("quotes and backslash", "he said \"hi\\there\""),
    ("percent and plus", "100% a+b"),
    ("slash", "path/to/thing"),
    ("hash and question", "#tag ?q=1"),
    ("long ascii near the cap", "x" * 4000),
    ("mixed invisibles", "a\u200d\n\tb\u202ec"),
]

ROOMS = ["lobby", "technocore", "meta", "d-owned", "mb-box", "e-fast", "p-hidden"]
NONCES = ["1", "42", "1787731987233", "9" * 19]


def main() -> None:
    upstream = load_upstream()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))

    failures: list[str] = []
    compared = 0

    def fail(what: str, got, want) -> None:
        failures.append(f"{what}\n      ours     {got!r}\n      upstream {want!r}")

    # --- the DID -------------------------------------------------------------
    ours_did = ours.did_of(key.public_key())
    upstream_did = upstream.did_of(key)
    if ours_did != upstream_did:
        fail("did:key for the test seed", ours_did, upstream_did)
    print(f"did under test: {ours_did}")

    # A did:key must round-trip back to the same public key bytes, or the
    # identifier is not self-describing and the whole offline story collapses.
    if ours.public_key_of(ours_did).public_bytes_raw() != key.public_key().public_bytes_raw():
        fail("did:key round trip", "mismatch", "the original public key")

    # --- the sweep, then the signature ---------------------------------------
    for label, text in CORPUS:
        try:
            ours_swept = ours.swept(text)
        except SystemExit as exc:
            ours_swept = f"<refused: {exc}>"
        try:
            upstream_swept = upstream.swept(text, upstream.MAX_TEXT_CHARS)
        except SystemExit as exc:
            upstream_swept = f"<refused: {exc}>"

        compared += 1
        if ours_swept != upstream_swept:
            fail(f"sweep [{label}]", ours_swept, upstream_swept)
            continue
        if ours_swept.startswith("<refused"):
            continue

        # The sweep must be idempotent, or signing the swept text and letting the
        # server sweep it again on receipt would change the stored bytes.
        if ours.swept(ours_swept) != ours_swept:
            fail(f"sweep not idempotent [{label}]", ours.swept(ours_swept), ours_swept)

        for room in ROOMS:
            for nonce in NONCES:
                canonical = ours.canonical_message(room, nonce, ours_swept)
                ours_sig = ours.sign(key, canonical)
                upstream_sig = upstream.signature(key, canonical)
                compared += 1
                if ours_sig != upstream_sig:
                    fail(f"signature [{label}] {room}|{nonce}", ours_sig, upstream_sig)
                    continue

                # Our own verifier must accept it...
                if not ours.verify_signature(ours_did, ours_sig, canonical):
                    fail(f"self-verify [{label}] {room}|{nonce}", "rejected", "accepted")
                # ...and so must the library the server actually uses.
                if not server_verifies(ours_did, ours_sig, canonical):
                    fail(f"pynacl verify [{label}] {room}|{nonce}", "rejected", "accepted")

    # --- the note lane -------------------------------------------------------
    for label, value in CORPUS[:12]:
        try:
            swept_value = ours.swept(value, ours.MAX_VALUE_CHARS)
            upstream_value = upstream.swept(value, upstream.MAX_VALUE_CHARS)
        except SystemExit:
            continue
        if swept_value != upstream_value:
            fail(f"note sweep [{label}]", swept_value, upstream_value)
            continue
        canonical = ours.canonical_note("room-owners", "d-demo", "7", swept_value)
        compared += 1
        if ours.sign(key, canonical) != upstream.signature(key, canonical):
            fail(f"note signature [{label}]", "mismatch", "upstream")

    # --- negative cases: the verifier must fail closed ------------------------
    canonical = ours.canonical_message("lobby", "1", "hello")
    good = ours.sign(key, canonical)
    other = ours.did_of(Ed25519PrivateKey.generate().public_key())
    negatives = [
        ("tampered text", ours_did, good, ours.canonical_message("lobby", "1", "hello!")),
        ("tampered room", ours_did, good, ours.canonical_message("meta", "1", "hello")),
        ("tampered nonce", ours_did, good, ours.canonical_message("lobby", "2", "hello")),
        ("wrong key", other, good, canonical),
        ("padded signature", ours_did, good + "==", canonical),
        ("truncated signature", ours_did, good[:-1], canonical),
        ("empty signature", ours_did, "", canonical),
        ("flipped first char", ours_did, ("B" if good[0] != "B" else "C") + good[1:], canonical),
    ]
    for label, did, sig, message in negatives:
        compared += 1
        if ours.verify_signature(did, sig, message):
            fail(f"negative [{label}]", "accepted", "rejected")
        # The server's library must reach the same verdict, or our idea of what
        # is valid differs from the gate that actually runs.
        if server_verifies(did, sig, message):
            fail(f"negative [{label}] under pynacl", "accepted", "rejected")

    # --- the upstream CLI, to confirm the wiring and not only the maths -------
    for room, nonce, text in [("lobby", "1", "hello"), ("technocore", "42", "a b")]:
        canonical = ours.canonical_message(room, nonce, ours.swept(text))
        result = subprocess.run(
            [sys.executable, str(REFERENCE), "--seed", SEED, "say", room, nonce, text],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            fail(f"upstream CLI [{room}]", result.stderr.strip(), "exit 0")
            continue
        cli_did, cli_sig = result.stdout.strip().splitlines()
        compared += 2
        if cli_did != ours_did:
            fail(f"upstream CLI did [{room}]", ours_did, cli_did)
        if cli_sig != ours.sign(key, canonical):
            fail(f"upstream CLI sig [{room}]", ours.sign(key, canonical), cli_sig)

    print(f"comparisons: {compared}")
    if failures:
        print(f"\nFAILED {len(failures)}:\n")
        for f in failures:
            print(f"  {f}\n")
        sys.exit(1)
    print("conformance: ours == upstream == server library, on every case")


def server_verifies(did: str, signature: str, message: str) -> bool:
    """Verify the way src/didkey.py does -- pynacl, not cryptography.

    Two libraries agreeing on a verdict is the part a benchmark cannot tell you,
    and it is the part that decides whether a write is accepted.
    """
    import base64

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if not ours.SIG_RE.fullmatch(signature or ""):
        return False
    try:
        raw_key = ours.public_key_of(did).public_bytes_raw()
        raw_sig = base64.urlsafe_b64decode(signature + "==")
        VerifyKey(raw_key).verify(message.encode("utf-8"), raw_sig)
    except (BadSignatureError, ValueError):
        return False
    return True


if __name__ == "__main__":
    main()
