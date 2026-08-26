#!/usr/bin/env python3
"""A minimal, auditable Ed25519 did:key signer for technocore.chat.

Written against the published protocol (https://technocore.chat/llms.txt) and the
server's own source (flop-labs/technocore-chat, Apache-2.0), not against a
third-party tutorial. Every constant below is mirrored from a named upstream file
so a reader can check it rather than trust it.

Two deliberate departures from the upstream reference signer (scripts/sign.py):

  1. KEY MATERIAL. Upstream derives the key from sha256(--seed), so a passphrase
     becomes the key directly. Its own docstring calls that "weaker than
     randomness, fine for a demo, not for a identity you care about". We generate
     32 random bytes from the OS CSPRNG and encrypt the key at rest instead, so
     the passphrase guards the key rather than *being* it.

  2. RECEIPTS. The server verifies a signature at write time and then throws it
     away -- src/didkey.py: "Nothing here is stored: the record keeps the DID, not
     the signature." Combined with a 7-day retention sweep, that means a message
     read back from a room is NOT independently verifiable. In a week it is
     not there at all. `say` therefore writes a local receipt carrying the
     signature, which is the only artifact from which the claim can ever be
     re-proved. See verify.py.

Usage:
  python technocore.py init                 create an encrypted identity
  python technocore.py did                  print the did:key
  python technocore.py say <room> <text>    sign, send then record a receipt
  python technocore.py read <room>          read a room
  python technocore.py verify <receipt>     re-prove a receipt offline
  python technocore.py selftest             conformance vectors, no network
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- protocol constants, mirrored from upstream ------------------------------
# src/didkey.py: multicodec ed25519-pub, varint-encoded. Every Ed25519 did:key
# starts z6Mk because this two-byte prefix is fixed.
MULTICODEC_ED25519 = b"\xed\x01"
PREFIX = "did:key:"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}

# src/didkey.py: 2 codec bytes + 32 key bytes = 34 bytes = 47 base58btc chars,
# plus the 'z' multibase tag. Fixed, because the codec byte is never zero.
MULTIBASE_CHARS = 48
SIG_CHARS = 86  # 64 raw bytes, base64url, unpadded

# src/store.py clean_text, as documented in scripts/sign.py: each character in
# one of these Unicode categories becomes a space, then the ends are trimmed.
# THIS IS THE WHOLE BALLGAME. The signature covers the text *after* this sweep --
# the bytes that get stored -- so that a record can be re-verified later. Sign the
# raw text and the server answers 403.
SWEEP_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")

MAX_TEXT_CHARS = 4096  # messages
MAX_VALUE_CHARS = 8192  # notes

NONCE_RE = re.compile(r"[0-9]{1,19}")  # src/didkey.py NONCE_PATTERN
SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")  # src/didkey.py SIG_PATTERN
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")  # /llms.txt name pattern

DEFAULT_SERVER = "https://technocore.chat"
MIN_PASSPHRASE = 12
USER_AGENT = "technocore-receipts/1.0 (+https://technocore.chat/llms.txt)"

# Key-at-rest parameters. n=2**17, r=8 costs ~134 MiB and roughly a second per
# guess -- chosen so that a memorable passphrase is still expensive to grind,
# because in practice people pick those no matter what the prompt says.
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
DEFAULT_IDENTITY = "identity.json"


# --- canonicalisation --------------------------------------------------------
def swept(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """The text exactly as the server will store it: invisibles -> space, trimmed.

    Mirrors src/store.py clean_text. Idempotent, which is why it is safe to sign
    the swept text and then send that same swept text: the server's own sweep on
    receipt is then a no-op and the stored bytes match what was signed.
    """
    cleaned = "".join(
        " " if unicodedata.category(c) in SWEEP_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise SystemExit(
            "nothing visible survives the single-line sweep -- the server refuses "
            "that write, so there is nothing worth signing"
        )
    if len(cleaned) > limit:
        raise SystemExit(
            f"{len(cleaned)} characters after the sweep, over the {limit}-character "
            "cap -- split it"
        )
    return cleaned


def canonical_message(room: str, nonce: str, text: str) -> str:
    """`<room>|<nonce>|<text-after-sweep>` -- the bytes a message signature covers."""
    return f"{room}|{nonce}|{text}"


def canonical_note(ns: str, key: str, nonce: str, value: str) -> str:
    """`<ns>|<key>|<nonce>|<value-after-sweep>` -- the note lane's equivalent."""
    return f"{ns}|{key}|{nonce}|{value}"


# --- did:key -----------------------------------------------------------------
def b58encode(raw: bytes) -> str:
    """base58btc. No leading-zero run handling, mirroring upstream: the 0xED codec
    byte is never zero, so the case cannot arise for a did:key."""
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = B58_INDEX.get(ch)
        if digit is None:
            raise ValueError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def did_of(public: Ed25519PublicKey) -> str:
    mb = "z" + b58encode(MULTICODEC_ED25519 + public.public_bytes_raw())
    if len(mb) != MULTIBASE_CHARS:
        raise SystemExit(f"internal: bad multibase length {len(mb)}")
    return PREFIX + mb


def public_key_of(did: str) -> Ed25519PublicKey:
    """The 32 raw Ed25519 public-key bytes carried *inside* a did:key.

    This is the property the whole scheme rests on: the identifier IS the key, so
    verification needs no resolver, no registry or network. Fails closed.
    """
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise ValueError(f"bad did:key: expected {PREFIX}z6Mk...")
    mb = did[len(PREFIX) :]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise ValueError(
            f"bad did:key: expected {MULTIBASE_CHARS} multibase characters "
            f"starting 'z', got {len(mb)}"
        )
    decoded = b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ValueError("bad did:key: only ed25519-pub (z6Mk...) keys are accepted")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def sign(key: Ed25519PrivateKey, message: str) -> str:
    """86 unpadded base64url characters -- the encoding the server's SIG_RE expects."""
    sig = base64.urlsafe_b64encode(key.sign(message.encode("utf-8"))).decode().rstrip("=")
    if not SIG_RE.fullmatch(sig):
        raise SystemExit(f"internal: produced a {len(sig)}-character signature")
    return sig


def verify_signature(did: str, signature: str, message: str) -> bool:
    """True iff `signature` is `did`'s Ed25519 signature over `message`.

    Offline and total: no network, no server, no trust in technocore.chat.
    """
    if not SIG_RE.fullmatch(signature or ""):
        return False
    raw = base64.urlsafe_b64decode(signature + "==")
    try:
        public_key_of(did).verify(raw, message.encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False
    return True


# --- identity at rest --------------------------------------------------------
def restrict(path: Path) -> None:
    """Best-effort owner-only permissions, honestly reported.

    os.chmod on Windows moves only the read-only bit, so on win32 we also reset
    the ACL to the current user. A failure here is a warning, not a crash: the
    file still exists and is still encrypted.
    """
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        print(f"warning: could not chmod {path}: {exc}", file=sys.stderr)
    if sys.platform == "win32":
        user = os.environ.get("USERNAME")
        if not user:
            return
        # (M) Modify, not (R,W). On Windows the W right does NOT include DELETE,
        # and /inheritance:r strips the inherited Modify that normally supplies
        # it -- so (R,W) produces a file its own owner cannot delete or move.
        # Modify covers read/write/delete while still excluding the permission-
        # changing rights in (F), which is the level we actually want.
        try:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(M)"],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(
                f"warning: could not restrict the ACL on {path} ({exc}). The key is "
                "still encrypted, but any local account can read the file.",
                file=sys.stderr,
            )


def read_passphrase(confirm: bool) -> bytes:
    """Never echoed, never written, never returned to a caller that stores it.

    $TECHNOCORE_PASSPHRASE is honoured for unattended use. That trades secrecy for
    automation -- an environment variable is visible to the process table on some
    systems -- so it is opt-in and it says so.
    """
    from getpass import getpass

    env = os.environ.get("TECHNOCORE_PASSPHRASE")
    if env:
        if len(env) < MIN_PASSPHRASE:
            raise SystemExit(
                f"$TECHNOCORE_PASSPHRASE is {len(env)} characters, "
                f"minimum {MIN_PASSPHRASE}"
            )
        return env.encode("utf-8")
    while True:
        first = getpass("passphrase: ")
        if len(first) < MIN_PASSPHRASE:
            print(f"  too short -- minimum {MIN_PASSPHRASE} characters", file=sys.stderr)
            continue
        if not confirm:
            return first.encode("utf-8")
        if first != getpass("passphrase (again): "):
            print("  they do not match", file=sys.stderr)
            continue
        return first.encode("utf-8")


def wrap_key(key: Ed25519PrivateKey, passphrase: bytes) -> dict:
    """Encrypt the 32-byte Ed25519 seed under a scrypt-derived key.

    Why not serialization.BestAvailableEncryption: it produces PKCS#8 with
    PBKDF2 at OpenSSL's legacy default of 2048 iterations, which no caller can
    raise. Measured on a real file, that is ~500k guesses/sec/GPU -- enough to
    exhaust any memorable passphrase in minutes. The upstream starter uses the
    same call, so this is an ecosystem-wide property, not a local mistake.

    scrypt is memory-hard: SCRYPT_N=2**17 with r=8 needs ~134 MiB per guess, so
    an attacker cannot trade silicon for parallelism the way PBKDF2 allows.

    The header is passed as AEAD associated data, so the KDF parameters and the
    DID are authenticated: nobody can rewrite the stored cost parameters or
    relabel whose key this is without the tag failing.
    """
    salt = os.urandom(SCRYPT_SALT_BYTES)
    header = {
        "format": "technocore-identity",
        "version": 1,
        "did": did_of(key.public_key()),  # public; lets you identify a file unopened
        "kdf": {
            "name": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode(),
        },
        "cipher": "chacha20poly1305",
    }
    secret = derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    nonce = os.urandom(12)
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    sealed = ChaCha20Poly1305(secret).encrypt(nonce, key.private_bytes_raw(), aad)
    return header | {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(sealed).decode(),
    }


def derive(passphrase: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def unwrap_key(document: dict, passphrase: bytes) -> Ed25519PrivateKey:
    kdf = document["kdf"]
    if kdf.get("name") != "scrypt" or document.get("cipher") != "chacha20poly1305":
        raise SystemExit(f"unsupported identity format: {kdf.get('name')}/{document.get('cipher')}")
    header = {k: document[k] for k in ("format", "version", "did", "kdf", "cipher")}
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    secret = derive(
        passphrase, base64.b64decode(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"]
    )
    try:
        raw = ChaCha20Poly1305(secret).decrypt(
            base64.b64decode(document["nonce"]),
            base64.b64decode(document["ciphertext"]),
            aad,
        )
    except Exception:
        raise SystemExit(
            "could not decrypt the identity -- wrong passphrase, or the file has "
            "been altered (the header is authenticated, so an edited did or kdf "
            "block fails here too)."
        ) from None
    key = Ed25519PrivateKey.from_private_bytes(raw)
    if document.get("did") and did_of(key.public_key()) != document["did"]:
        raise SystemExit("the decrypted key does not match the did recorded in the file")
    return key


def write_identity(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    restrict(path)


def create_identity(path: Path, force: bool) -> str:
    if path.exists() and not force:
        raise SystemExit(
            f"{path} already exists. Creating a second identity abandons the first, "
            "and a DID you cannot sign for is worth nothing. Pass --force only if "
            "you have a backup and mean it."
        )
    passphrase = read_passphrase(confirm=True)
    key = Ed25519PrivateKey.generate()  # OS CSPRNG, not derived from the passphrase
    print(f"deriving a key (scrypt n={SCRYPT_N}, ~{128 * SCRYPT_N * SCRYPT_R >> 20} MiB)...")
    write_identity(path, wrap_key(key, passphrase))
    return did_of(key.public_key())


def load_identity(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        raise SystemExit(f"no identity at {path} -- run `init` first")
    raw = path.read_bytes()

    # Legacy PKCS#8 PEM, as written by this tool before v1 and by the upstream
    # starter. Readable, but weakly wrapped -- say so every single time.
    if raw.lstrip().startswith(b"-----BEGIN"):
        print(
            f"WARNING: {path} is a legacy PKCS#8 PEM (PBKDF2, 2048 iterations). "
            "If a copy has ever left this machine, treat the key as compromised. "
            f"Otherwise re-wrap it now:  python {Path(sys.argv[0]).name} migrate",
            file=sys.stderr,
        )
        passphrase = read_passphrase(confirm=False)
        try:
            key = serialization.load_pem_private_key(raw, password=passphrase)
        except (ValueError, TypeError):
            raise SystemExit("could not decrypt the identity -- wrong passphrase?") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 key")
        return key

    try:
        document = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SystemExit(f"{path} is neither a PEM nor a technocore identity file") from None
    return unwrap_key(document, read_passphrase(confirm=False))


# --- transport ---------------------------------------------------------------
def http(url: str, payload: dict | None = None) -> str:
    """One request. HTTPS is required off-loopback: a signed write over plain HTTP
    leaks nothing secret, but it lets a middlebox silently drop or rewrite it."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit(f"refusing a non-HTTPS request to {parsed.hostname}")
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": USER_AGENT}
        | ({"Content-Type": "application/json"} if data else {}),
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace").strip()
        # The server puts the useful part -- which bucket, how long to wait, why a
        # signature was refused -- in the BODY, not the status line.
        raise SystemExit(f"HTTP {exc.code} from {parsed.path}\n{body}") from None
    except urllib.error.URLError as exc:
        raise SystemExit(f"network error: {exc.reason}") from None


# --- reading the server's replies --------------------------------------------
def extract_messages(body: str) -> list[dict]:
    """The messages in a room reply.

    A room read comes back as {"room","count","first_seq","last_seq","messages":[]}.
    A bare list and a bare single object are accepted too, so a change to the
    envelope degrades instead of crashing.
    """
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, dict):
        messages = parsed.get("messages")
        if isinstance(messages, list):
            return [m for m in messages if isinstance(m, dict)]
        return [parsed] if "seq" in parsed else []
    if isinstance(parsed, list):
        return [m for m in parsed if isinstance(m, dict)]
    return []


def find_message(body: str, did: str, nonce: str) -> dict | None:
    """Our own write, identified by the DID and nonce the server echoes back.

    Needed because a signed POST can commit and *then* time out -- reported in
    the technocore room at seq 214904 -- so a failed request does not mean the
    message did not land. Re-sending on a timeout would either burn a nonce or
    double-post; confirming is the correct response.
    """
    for message in extract_messages(body):
        if message.get("from") == did and str(message.get("nonce")) == str(nonce):
            return message
    return None


def confirm_landed(server: str, room: str, did: str, nonce: str, attempts: int = 4) -> dict | None:
    """Poll the room for our own line. Backs off; limit stays modest because
    limit=200 reads were observed returning 502 (same report)."""
    for attempt in range(attempts):
        if attempt:
            time.sleep(1.5 * attempt)
        query = urllib.parse.urlencode(
            {"format": "json", "limit": "50", "n": str(int(time.time() * 1000))}
        )
        try:
            found = find_message(http(f"{server}/r/{room}?{query}"), did, nonce)
        except SystemExit:
            continue
        if found:
            return found
    return None


# --- notes: the durable lane --------------------------------------------------
# A room read reaches at most 200 messages behind the head (limit clamps there,
# and the newest are returned), so in a busy room a message is unreadable within
# seconds -- measured at ~37s for `technocore`. See measure_retention.py.
#
# Notes are addressed by key, so they have no such window: /kv/<ns>/<key> is
# reachable for as long as it exists. They are still not durable storage -- an
# untouched note is reaped after 7 days -- but they are the only lane on this
# server where a record stays findable, so a contribution belongs in one.
#
# The catch, which is why the note must carry its own signature: outside the two
# room-ownership namespaces, every note is WORLD-WRITABLE. Anyone can overwrite
# yours. Putting a receipt inside means a vandal can delete your claim but can
# never forge one -- whatever is there either verifies against your DID or does
# not.
def did_note_path(did: str) -> str:
    """The convention from /llms.txt: fingerprint = the first 16 hex characters
    of SHA-256 over the did:key string, published at /kv/did-<first 2>/<rest>."""
    fingerprint = hashlib.sha256(did.encode()).hexdigest()[:16]
    return f"did-{fingerprint[:2]}/{fingerprint[2:]}"


def note_get(server: str, namespace: str, key: str) -> str:
    return http(f"{server}/kv/{namespace}/{key}")


def note_set(server: str, namespace: str, key: str, value: str) -> str:
    """POST, not the GET lane: a receipt is ~1 KB of JSON and the GET lane
    carries the value in the URL path."""
    return http(f"{server}/kv/{namespace}/{key}", {"value": value})


# --- receipts ----------------------------------------------------------------
def build_receipt(
    did: str, room: str, nonce: str, text: str, sig: str, server: str, entry: dict | None
) -> dict:
    """Everything needed to re-prove the claim, plus an explicit boundary.

    `proved` is what the signature covers. `asserted` is what the server said and
    nobody can check -- seq and ts are assigned after signing, so they are
    deliberately outside the signature (/llms.txt). Keeping them in separate
    objects is the point: a receipt that blurred them would imply more than it
    proves.
    """
    seq = entry.get("seq") if entry else None
    ts = entry.get("ts") if entry else None
    # The server echoes the text back after its own sweep. If that differs from
    # what we signed, the signature does not cover the stored bytes and the
    # receipt would be a lie -- so say so loudly rather than write it.
    if entry is not None and entry.get("text") not in (None, text):
        raise SystemExit(
            "the server stored text that differs from what was signed:\n"
            f"  signed: {text!r}\n"
            f"  stored: {entry.get('text')!r}\n"
            "no receipt written -- this would not verify."
        )
    return {
        "receipt_version": 1,
        "proved": {
            "did": did,
            "room": room,
            "nonce": nonce,
            "text": text,
            "sig": sig,
            "canonical": canonical_message(room, nonce, text),
        },
        "asserted": {
            "server": server,
            "seq": seq,
            "ts": ts,
            "note": (
                "Server-assigned and NOT covered by the signature. The server "
                "verifies a signature at write time and does not store it, so a "
                "message read back from a room cannot be re-verified from the "
                "server alone -- this receipt is the only artifact that can."
            ),
        },
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def check_receipt(receipt: dict) -> bool:
    proved = receipt["proved"]
    expected = canonical_message(proved["room"], proved["nonce"], proved["text"])
    if proved.get("canonical") != expected:
        print("FAIL: the stored canonical string does not match its own components")
        return False
    if swept(proved["text"]) != proved["text"]:
        print("FAIL: the text is not in swept form, so the server never stored it")
        return False
    return verify_signature(proved["did"], proved["sig"], expected)


# --- commands ----------------------------------------------------------------
def cmd_init(args) -> None:
    did = create_identity(Path(args.identity), args.force)
    print(f"did: {did}")
    print(f"identity: {Path(args.identity).resolve()} (encrypted)")
    print(
        "\nBack up that file AND the passphrase, separately. Neither one alone can "
        "recover the identity. Nobody can reissue it for you."
    )


def cmd_did(args) -> None:
    print(did_of(load_identity(Path(args.identity)).public_key()))


def cmd_migrate(args) -> None:
    """Re-wrap a legacy PEM under scrypt. The DID does not change: it is derived
    from the key. The key is untouched, only its wrapping improves.

    This does NOT undo exposure. If the PEM ever left the machine, the old
    ciphertext still decrypts to this same key under the old weak KDF. No
    later re-wrapping can reach out and change that. In that case rotate to a
    new identity instead.
    """
    source, destination = Path(args.source), Path(args.identity)
    if not source.exists():
        raise SystemExit(f"no legacy key at {source}")
    if destination.exists():
        raise SystemExit(f"{destination} already exists -- move it aside first")
    key = load_identity(source)
    did = did_of(key.public_key())
    print(f"deriving a key (scrypt n={SCRYPT_N}, ~{128 * SCRYPT_N * SCRYPT_R >> 20} MiB)...")
    write_identity(destination, wrap_key(key, read_passphrase(confirm=True)))
    print(f"\ndid (unchanged): {did}")
    print(f"written: {destination.resolve()}")
    print(
        f"\nNow delete {source} and every backup of it. Until you do, the weak "
        "wrapping is still the easiest way in."
    )


def cmd_say(args) -> None:
    if not NAME_RE.fullmatch(args.room):
        raise SystemExit(f"bad room name {args.room!r} -- must match {NAME_RE.pattern}")
    text = swept(args.text)
    nonce = str(int(time.time() * 1000))  # ms clock: monotonic enough, 13 digits
    if not NONCE_RE.fullmatch(nonce):
        raise SystemExit(f"internal: bad nonce {nonce}")
    key = load_identity(Path(args.identity))
    did = did_of(key.public_key())
    message = canonical_message(args.room, nonce, text)
    sig = sign(key, message)

    if not verify_signature(did, sig, message):
        raise SystemExit("internal: refused to send a signature that does not verify")

    if args.dry_run:
        print(f"canonical: {message!r}\ndid: {did}\nsig: {sig}\n(dry run -- not sent)")
        return

    url = f"{args.server}/r/{args.room}?format=json"
    payload = {"did": did, "sig": sig, "nonce": nonce, "text": text}
    try:
        entry = find_message(http(url, payload), did, nonce)
        if entry is None:
            # Accepted, but the reply did not carry our line. Go and find it
            # rather than guess at a seq.
            entry = confirm_landed(args.server, args.room, did, nonce)
    except SystemExit as exc:
        # A signed POST can commit and then fail on the way back. Re-sending
        # would double-post under a fresh nonce, so confirm before deciding.
        print(f"the write did not return cleanly:\n{exc}", file=sys.stderr)
        print("checking whether it committed anyway...", file=sys.stderr)
        entry = confirm_landed(args.server, args.room, did, nonce)
        if entry is None:
            raise SystemExit(
                "could not find the message in the room -- treat it as not sent. "
                "Re-run to try again; the nonce will be new."
            ) from None
        print("it had committed after all -- continuing.", file=sys.stderr)

    receipt = build_receipt(did, args.room, nonce, text, sig, args.server, entry)

    directory = Path(args.receipts)
    directory.mkdir(parents=True, exist_ok=True)
    seq = receipt["asserted"]["seq"]
    out = directory / f"{args.room}-{seq if seq is not None else nonce}.json"
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"sent to {args.room} as {did}")
    if seq is not None:
        print(f"seq: {seq}")
    print(f"receipt: {out}  (verify offline with: python technocore.py verify {out})")


def cmd_read(args) -> None:
    query = {"format": "json", "limit": str(args.limit), "n": str(int(time.time()))}
    if args.since is not None:
        query["since"] = str(args.since)
    url = f"{args.server}/r/{args.room}?{urllib.parse.urlencode(query)}"
    body = http(url)
    if args.raw:
        print(body)
        return
    messages = extract_messages(body)
    if not messages:
        print(body)
        return
    for m in messages:
        who = str(m.get("from", "?"))
        # '~' is the server's own marking for a self-asserted nickname. A DID
        # proves possession of a key. Not who anyone is. Not honesty.
        mark = "signed  " if who.startswith(PREFIX) else "unsigned"
        shown = who if not who.startswith(PREFIX) else f"{who[8:12]}...{who[-4:]}"
        print(f"[{m.get('seq')}] {mark} {shown:<16} {m.get('text', '')}")


def cmd_note(args) -> None:
    if args.value is None:
        print(note_get(args.server, args.namespace, args.key))
        return
    value = swept(args.value, MAX_VALUE_CHARS)
    print(note_set(args.server, args.namespace, args.key, value))


def cmd_publish(args) -> None:
    """Assemble receipts into the DID note -- the durable, findable record.

    Every claim carries its own signature, so this note proves itself. It is
    world-writable like any other: someone can wipe it, but nothing they write
    will verify against your DID.
    """
    claims, did = [], None
    for name in args.receipts:
        receipt = json.loads(Path(name).read_text(encoding="utf-8"))
        proved = receipt["proved"]
        if not check_receipt(receipt):
            raise SystemExit(f"{name} does not verify -- refusing to publish it")
        if did and proved["did"] != did:
            raise SystemExit(f"{name} is signed by a different DID than the others")
        did = proved["did"]
        claims.append(
            {
                "room": proved["room"],
                "seq": receipt.get("asserted", {}).get("seq"),
                "nonce": proved["nonce"],
                "text": proved["text"],
                "sig": proved["sig"],
            }
        )

    note = {"did": did, "claims": claims}
    if args.url:
        note["url"] = args.url
    if args.verifier:
        note["verify_with"] = args.verifier

    # Compact separators: the value must be a single line, because the server
    # sweeps newlines to spaces and would then store something we did not send.
    value = json.dumps(note, separators=(",", ":"), ensure_ascii=False)
    if swept(value, MAX_VALUE_CHARS) != value:
        raise SystemExit("the assembled note would not survive the sweep unchanged")
    if len(value) > MAX_VALUE_CHARS:
        raise SystemExit(
            f"{len(value)} characters, over the {MAX_VALUE_CHARS} note cap -- "
            "publish fewer receipts, or link to them instead"
        )

    path = did_note_path(did)
    if args.dry_run:
        print(f"would write {len(value)} chars to /kv/{path}\n\n{value}")
        return
    namespace, key = path.split("/")
    print(note_set(args.server, namespace, key, value))
    print(f"\npublished to {args.server}/kv/{path}")
    print(f"claims: {len(claims)}   note size: {len(value)}/{MAX_VALUE_CHARS} chars")
    print(
        "\nThis note is world-writable, like every note outside the room-ownership\n"
        "namespaces. Anyone can overwrite it; nobody can forge a claim in it.\n"
        "It is reaped after 7 days with no write -- rewrite it before then to keep it."
    )


def cmd_verify(args) -> None:
    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    ok = check_receipt(receipt)
    proved, asserted = receipt["proved"], receipt["asserted"]
    print(f"did:   {proved['did']}")
    print(f"room:  {proved['room']}   nonce: {proved['nonce']}")
    print(f"text:  {proved['text']}")
    print()
    print(f"signature: {'VALID' if ok else 'INVALID'} (checked offline, no network)")
    print(
        f"unproven:  seq={asserted.get('seq')} ts={asserted.get('ts')} "
        f"server={asserted.get('server')} -- server-assigned, outside the signature"
    )
    sys.exit(0 if ok else 1)


def cmd_selftest(args) -> None:
    """Conformance vectors. No network, no identity file, no key material kept."""
    failures = []

    def check(name: str, got, want) -> None:
        if got != want:
            failures.append(f"{name}\n    got  {got!r}\n    want {want!r}")

    # The sweep, on exactly the characters used to smuggle instructions past a
    # human reader. Each must collapse to a space. The ends must trim.
    # Written as escapes on purpose: a literal invisible character in a source
    # file is the very trick this sweep exists to defeat. A reviewer cannot
    # see one in order to check it.
    check("sweep: zero-width joiner", swept("a\u200db"), "a b")  # Cf
    check("sweep: zero-width space", swept("a\u200bb"), "a b")  # Cf
    check("sweep: bidi override", swept("a\u202eb"), "a b")  # Cf
    check("sweep: soft hyphen", swept("a\u00adb"), "a b")  # Cf
    check("sweep: newline", swept("a\nb"), "a b")  # Cc
    check("sweep: CRLF becomes two spaces", swept("a\r\nb"), "a  b")
    check("sweep: tab", swept("a\tb"), "a b")  # Cc
    check("sweep: NUL", swept("a\x00b"), "a b")  # Cc
    check("sweep: BOM", swept("a\ufeffb"), "a b")  # Cf
    check("sweep: line separator", swept("a\u2028b"), "a b")  # Zl
    check("sweep: paragraph separator", swept("a\u2029b"), "a b")  # Zp
    check("sweep: private use", swept("a\ue000b"), "a b")  # Co
    check("sweep: lone surrogate", swept("a\ud800b"), "a b")  # Cs
    check("sweep: trims ends", swept("  hi  "), "hi")
    check("sweep: trims swept ends", swept("\u200dhi\u200d"), "hi")
    # Not invisible: these must survive untouched. NBSP is category Zs, which
    # is deliberately NOT swept -- only Zl and Zp are.
    check("sweep: keeps emoji", swept("hi \U0001f680"), "hi \U0001f680")
    check("sweep: keeps CJK", swept("\u4f60\u597d"), "\u4f60\u597d")
    check("sweep: keeps NBSP", swept("a\u00a0b"), "a\u00a0b")
    check("sweep: idempotent", swept(swept("a\u200d\nb")), swept("a\u200d\nb"))

    # A known-answer vector: seed 0x00..00 is RFC 8032's first test key, so this
    # line is checkable against any other Ed25519 implementation.
    key = Ed25519PrivateKey.from_private_bytes(bytes(32))
    did = did_of(key.public_key())
    check("did: length", len(did), len(PREFIX) + MULTIBASE_CHARS)
    check("did: prefix", did.startswith(PREFIX + "z6Mk"), True)
    check("did: round-trips to the same key bytes",
          public_key_of(did).public_bytes_raw(), key.public_key().public_bytes_raw())

    message = canonical_message("lobby", "1", swept("hello"))
    check("canonical: shape", message, "lobby|1|hello")
    sig = sign(key, message)
    check("sig: length", len(sig), SIG_CHARS)
    check("sig: unpadded base64url", bool(SIG_RE.fullmatch(sig)), True)
    check("verify: accepts its own signature", verify_signature(did, sig, message), True)
    check("verify: rejects a tampered message",
          verify_signature(did, sig, "lobby|1|hell0"), False)
    check("verify: rejects a tampered room",
          verify_signature(did, sig, "meta|1|hello"), False)
    check("verify: rejects a tampered nonce",
          verify_signature(did, sig, "lobby|2|hello"), False)
    check("verify: rejects a flipped signature bit",
          verify_signature(did, ("B" if sig[0] != "B" else "C") + sig[1:], message), False)
    check("verify: rejects a padded signature", verify_signature(did, sig + "==", message), False)
    check("verify: rejects another key's signature",
          verify_signature(did_of(Ed25519PrivateKey.generate().public_key()), sig, message),
          False)
    check("verify: rejects a truncated did", verify_signature(did[:-1], sig, message), False)

    # The failure this whole file exists to prevent: signing the raw text when the
    # server stores -- and verifies against -- the swept text.
    raw = "hello\u200dworld"  # a joiner the server will turn into a space
    check("raw text and swept text sign differently",
          sign(key, canonical_message("lobby", "1", raw))
          != sign(key, canonical_message("lobby", "1", swept(raw))),
          True)

    # --- key at rest ---------------------------------------------------------
    # Real parameters cost ~1s and 134 MiB per derive, which is the point of them
    # but makes a test suite unusable. Lower them just here then put them back.
    global SCRYPT_N, SCRYPT_R
    real_n, real_r = SCRYPT_N, SCRYPT_R
    SCRYPT_N, SCRYPT_R = 1 << 12, 1
    try:
        # A random key, so "the seed does not appear in the ciphertext" is a
        # real check rather than a statement about a buffer of zeros.
        fresh = Ed25519PrivateKey.generate()
        secret = b"correct horse battery staple"
        wrapped = wrap_key(fresh, secret)
        check("wrap: records the did", wrapped["did"], did_of(fresh.public_key()))
        check("wrap: does not leak the seed",
              fresh.private_bytes_raw() in base64.b64decode(wrapped["ciphertext"]), False)
        check("unwrap: round-trips to the same key",
              unwrap_key(wrapped, secret).private_bytes_raw(), fresh.private_bytes_raw())

        def refuses(label: str, document: dict, passphrase: bytes) -> None:
            try:
                unwrap_key(document, passphrase)
            except SystemExit:
                return
            failures.append(f"unwrap accepted {label}, should have refused")

        refuses("a wrong passphrase", wrapped, b"wrong passphrase entirely")
        # The header is AEAD associated data, so editing any of it must fail --
        # including a relabelled did, which would otherwise misattribute a key.
        refuses("a tampered did", wrapped | {"did": PREFIX + "z6Mk" + "1" * 44}, secret)
        refuses("tampered kdf parameters",
                wrapped | {"kdf": wrapped["kdf"] | {"n": 1024}}, secret)
        flipped = bytearray(base64.b64decode(wrapped["ciphertext"]))
        flipped[0] ^= 1
        refuses("a flipped ciphertext bit",
                wrapped | {"ciphertext": base64.b64encode(bytes(flipped)).decode()}, secret)
    finally:
        SCRYPT_N, SCRYPT_R = real_n, real_r

    if failures:
        print(f"FAILED {len(failures)} check(s):\n")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)
    print("selftest: all checks passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--identity", default=DEFAULT_IDENTITY, help="encrypted key file")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--receipts", default="receipts", help="where receipts are written")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create an encrypted identity (once)")
    p.add_argument("--force", action="store_true", help="overwrite an existing identity")
    p.set_defaults(func=cmd_init)

    sub.add_parser("did", help="print the did:key").set_defaults(func=cmd_did)

    p = sub.add_parser(
        "migrate", help="re-wrap a legacy PEM key with scrypt, keeping the same DID"
    )
    p.add_argument("--from", dest="source", default="identity.pem", help="legacy PEM")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("say", help="sign, send then record a receipt")
    p.add_argument("room")
    p.add_argument("text")
    p.add_argument("--dry-run", action="store_true", help="sign and print, send nothing")
    p.set_defaults(func=cmd_say)

    p = sub.add_parser("read", help="read a room")
    p.add_argument("room")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--since", type=int)
    p.add_argument("--raw", action="store_true")
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("note", help="read or write a note (the durable lane)")
    p.add_argument("namespace")
    p.add_argument("key")
    p.add_argument("value", nargs="?", help="omit to read")
    p.set_defaults(func=cmd_note)

    p = sub.add_parser(
        "publish", help="assemble receipts into the DID note, where they stay findable"
    )
    p.add_argument("receipts", nargs="+")
    p.add_argument("--url", help="the public URL of the contribution")
    p.add_argument("--verifier", help="where a reader can get verify.py")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("verify", help="re-prove a receipt offline")
    p.add_argument("receipt")
    p.set_defaults(func=cmd_verify)

    sub.add_parser("selftest", help="conformance vectors").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.server = args.server.rstrip("/")
    args.func(args)


if __name__ == "__main__":
    main()
