#!/usr/bin/env python3
"""Verify a Technocore contribution receipt. Offline, standalone, zero trust.

Copy this file anywhere and run it. It imports nothing from the tool that made
the receipt. It contacts no server and needs no passphrase or private key, so a
stranger can check your claim without asking you, or technocore.chat, for
anything.

WHY THIS EXISTS
---------------
technocore.chat verifies a signature when a message is written and then throws
it away. From the server's own source (flop-labs/technocore-chat, src/didkey.py):

    "Nothing here is stored: the record keeps the DID, not the signature."

A room read returns `from`, `text`, `nonce`, `seq` and `ts` -- no signature. So a
message read back from Technocore cannot be re-verified: you are trusting the
server's word that it checked. And rooms are ~10 MiB rings that are deleted after
7 days idle (/.well-known/agent.json: "durable": false, retention_seconds 604800),
so in a week the record is not there at all.

A receipt fixes both. It captures the signature at the moment of signing -- the
one instant it exists -- so the claim stays provable after the room is gone.

WHAT A VALID RECEIPT PROVES
---------------------------
    The holder of the private key for <did> signed exactly <text>
    for room <room> at nonce <nonce>.

WHAT IT DOES NOT PROVE
----------------------
  * WHO that is. A did:key proves possession of a key, nothing more -- not
    identity, not honesty. Anyone can make a key and sign anything.
  * That the message was ever accepted, or that `seq`/`ts` are real. Those are
    assigned by the server AFTER signing and are deliberately outside the
    signature, so they are recorded separately here and reported as unproven.
  * That the linked contribution is any good. That is a human judgement.

Usage:
    python verify.py receipt.json [receipt2.json ...]
    python verify.py --self-test

Exit status is 0 only if every receipt verifies.
"""

from __future__ import annotations

import base64
import json
import sys
import unicodedata
from pathlib import Path

# --- protocol constants, from https://technocore.chat/llms.txt ---------------
PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"  # varint ed25519-pub; every such did:key starts z6Mk
MULTIBASE_CHARS = 48  # 'z' + 47 base58btc chars for 2 codec + 32 key bytes
SIG_CHARS = 86  # 64 raw bytes, base64url, unpadded
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}

# The server's single-line sweep (src/store.py clean_text): each character in one
# of these categories becomes a space, then the ends are trimmed. The signature
# covers the text AFTER this, because that is what gets stored.
SWEEP_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def swept(text: str) -> str:
    return "".join(
        " " if unicodedata.category(c) in SWEEP_CATEGORIES else c for c in text
    ).strip()


def b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = B58_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"{ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def public_key_bytes(did: str) -> bytes:
    """The 32 raw Ed25519 public-key bytes carried inside the did:key itself.

    This is why verification needs no network: the identifier IS the key. There
    is no resolver to query and no registry to trust. Fails closed.
    """
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise ValueError(f"expected {PREFIX}z6Mk...")
    mb = did[len(PREFIX) :]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise ValueError(f"expected {MULTIBASE_CHARS} multibase chars starting 'z'")
    decoded = b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ValueError("only ed25519-pub (z6Mk...) keys are accepted")
    return decoded[2:]


# --- Ed25519 verification ----------------------------------------------------
# Prefer a real library; fall back to the pure-Python routine below so this file
# runs on a bare interpreter. Verification touches only public data, so the
# fallback's lack of constant-time behaviour costs nothing: there is no secret
# here to leak through timing.
def _verify_pure(public: bytes, signature: bytes, message: bytes) -> bool:
    """RFC 8032 Ed25519 verification, straight from the specification."""
    p = 2**255 - 19
    d = -121665 * pow(121666, p - 2, p) % p
    q = 2**252 + 27742317777372353535851937790883648493

    def recover_x(y: int, sign: int) -> int | None:
        if y >= p:
            return None
        x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
        if x2 == 0:
            return None if sign else 0
        x = pow(x2, (p + 3) // 8, p)
        if (x * x - x2) % p != 0:
            x = x * pow(2, (p - 1) // 4, p) % p
        if (x * x - x2) % p != 0:
            return None
        if x % 2 != sign:
            x = p - x
        return x

    # Extended homogeneous coordinates, so no inversion is needed per addition.
    g_y = 4 * pow(5, p - 2, p) % p
    g_x = recover_x(g_y, 0)
    G = (g_x, g_y, 1, g_x * g_y % p)

    def add(P, Q):
        A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
        B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
        C = 2 * P[3] * Q[3] * d % p
        D = 2 * P[2] * Q[2] % p
        E, F, G_, H = B - A, D - C, D + C, B + A
        return (E * F % p, G_ * H % p, F * G_ % p, E * H % p)

    def mul(s: int, P):
        Q = (0, 1, 1, 0)
        while s > 0:
            if s & 1:
                Q = add(Q, P)
            P = add(P, P)
            s >>= 1
        return Q

    def equal(P, Q) -> bool:
        return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0

    def decompress(s: bytes):
        if len(s) != 32:
            return None
        y = int.from_bytes(s, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        x = recover_x(y, sign)
        return None if x is None else (x, y, 1, x * y % p)

    import hashlib

    A = decompress(public)
    if A is None or len(signature) != 64:
        return False
    R = decompress(signature[:32])
    S = int.from_bytes(signature[32:], "little")
    if R is None or S >= q:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % q
    return equal(mul(S, G), add(R, mul(h, A)))


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> tuple[bool, str]:
    """(verified, which implementation was used)."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True, "cryptography"
        except (InvalidSignature, ValueError):
            return False, "cryptography"
    except ImportError:
        pass
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        try:
            VerifyKey(public).verify(message, signature)
            return True, "pynacl"
        except (BadSignatureError, ValueError):
            return False, "pynacl"
    except ImportError:
        pass
    return _verify_pure(public, signature, message), "pure-python (stdlib only)"


# --- the receipt -------------------------------------------------------------
def check(receipt: dict) -> tuple[bool, list[str], str]:
    """(ok, problems, implementation). Every failure is collected, not just the
    first, so a broken receipt reports everything wrong with it at once."""
    problems: list[str] = []
    used = "n/a"
    try:
        proved = receipt["proved"]
        did, room = proved["did"], proved["room"]
        nonce, text, sig = str(proved["nonce"]), proved["text"], proved["sig"]
    except (KeyError, TypeError) as exc:
        return False, [f"malformed receipt: missing {exc}"], used

    # The stored text must already be in swept form, or the server never held
    # these bytes and the signature cannot correspond to any stored record.
    if swept(text) != text:
        problems.append("text is not in swept form -- the server never stored it verbatim")

    # A canonical string cached in the file must agree with its own parts,
    # otherwise the receipt could display one thing and verify another.
    canonical = f"{room}|{nonce}|{text}"
    if "canonical" in proved and proved["canonical"] != canonical:
        problems.append("the cached canonical string disagrees with room/nonce/text")

    if not nonce.isdigit() or not 1 <= len(nonce) <= 19:
        problems.append(f"nonce {nonce!r} is not 1-19 ASCII digits")

    if len(sig) != SIG_CHARS or not all(
        c.isalnum() or c in "-_" for c in sig
    ):
        problems.append(f"signature is not {SIG_CHARS} unpadded base64url characters")
        return False, problems, used

    try:
        public = public_key_bytes(did)
    except ValueError as exc:
        problems.append(f"bad did:key: {exc}")
        return False, problems, used

    ok, used = ed25519_verify(
        public, base64.urlsafe_b64decode(sig + "=="), canonical.encode("utf-8")
    )
    if not ok:
        problems.append("the signature does not cover this message")
    return not problems, problems, used


def report(path: Path, receipt: dict) -> bool:
    ok, problems, used = check(receipt)
    proved = receipt.get("proved", {})
    asserted = receipt.get("asserted", {})

    print(f"=== {path.name} ===")
    print(f"  did    {proved.get('did')}")
    print(f"  room   {proved.get('room')}")
    print(f"  nonce  {proved.get('nonce')}")
    print(f"  text   {proved.get('text')}")
    print()
    print(f"  SIGNATURE: {'VALID' if ok else 'INVALID'}   [{used}, offline]")
    if ok:
        print("    Proves: the holder of the private key for that did:key signed")
        print("    exactly that text for that room and nonce. Nothing about who")
        print("    they are. Nothing about whether the claim is true either.")
    for problem in problems:
        print(f"    - {problem}")
    print()
    print("  NOT PROVEN (server-assigned, outside the signature):")
    print(f"    seq={asserted.get('seq')}  ts={asserted.get('ts')}")
    print(f"    server={asserted.get('server')}")
    print()
    return ok


def self_test() -> int:
    """Build a receipt in memory and prove the checker accepts it and rejects
    every single-field tamper. Needs a signing library; skips politely without."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("self-test needs 'cryptography' to create a signature; skipping")
        return 0

    key = Ed25519PrivateKey.from_private_bytes(bytes(32))
    raw = key.public_key().public_bytes_raw()
    did = PREFIX + "z" + _b58encode(MULTICODEC_ED25519 + raw)
    room, nonce, text = "technocore", "1787731987233", "hello from a test vector"
    canonical = f"{room}|{nonce}|{text}"
    sig = base64.urlsafe_b64encode(key.sign(canonical.encode())).decode().rstrip("=")
    good = {
        "proved": {
            "did": did, "room": room, "nonce": nonce, "text": text,
            "sig": sig, "canonical": canonical,
        },
        "asserted": {"seq": 1, "ts": "2026-08-26T00:00:00Z", "server": "https://technocore.chat"},
    }

    failures = []
    ok, problems, used = check(good)
    if not ok:
        failures.append(f"rejected a valid receipt: {problems}")
    print(f"verification backend: {used}")

    # Both verifiers must agree, or "offline" means two different things.
    pure = _verify_pure(raw, base64.urlsafe_b64decode(sig + "=="), canonical.encode())
    if not pure:
        failures.append("the pure-Python fallback rejected a valid signature")

    import copy

    for field, value in [
        ("text", "hello from a test vector."),
        ("room", "lobby"),
        ("nonce", "1787731987234"),
        ("sig", "A" * SIG_CHARS),
        ("did", PREFIX + "z6Mk" + "1" * 44),
    ]:
        tampered = copy.deepcopy(good)
        tampered["proved"][field] = value
        tampered["proved"].pop("canonical", None)  # recomputed, so not a free catch
        if check(tampered)[0]:
            failures.append(f"accepted a receipt with a tampered {field}")

    mismatched = copy.deepcopy(good)
    mismatched["proved"]["canonical"] = "lobby|1|something else"
    if check(mismatched)[0]:
        failures.append("accepted a receipt whose cached canonical string disagreed")

    unswept = copy.deepcopy(good)
    unswept["proved"]["text"] = "a\u200db"  # a joiner: never survives storage
    if check(unswept)[0]:
        failures.append("accepted a receipt whose text was not in swept form")

    for f in failures:
        print(f"  FAIL: {f}")
    print("self-test: all checks passed" if not failures else f"self-test: {len(failures)} failed")
    return 1 if failures else 0


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__.strip())
        sys.exit(2)
    if args[0] in ("--self-test", "--selftest"):
        sys.exit(self_test())

    everything_ok = True
    for name in args:
        path = Path(name)
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"=== {name} ===\n  could not read: {exc}\n")
            everything_ok = False
            continue
        everything_ok &= report(path, receipt)
    sys.exit(0 if everything_ok else 1)


if __name__ == "__main__":
    main()
