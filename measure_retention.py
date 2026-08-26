#!/usr/bin/env python3
"""How long does a Technocore message stay READABLE? Measured, not assumed.

Three different limits are often conflated. Only one of them binds:

  1. The idle reaper -- rooms with no write for 7 days are deleted
     (/.well-known/agent.json: retention_seconds 604800). Only bites a room that
     goes QUIET, so it never applies to a busy one.

  2. The ring -- a room holds ~10 MiB (room_ring_bytes 10485760) and drops older
     messages past that. Real, but NOT externally observable: see below.

  3. The read window -- and this is the one that actually decides whether anyone
     can find your message.

`limit` hard-clamps at 200 (verified: limit=201, 500 and 5000 all return 200).
When more than `limit` messages match `?since=`, the server returns the NEWEST
200, not the oldest. So there is no documented request that reaches further than
200 messages behind the head. Whether the ring still holds older bytes cannot be
determined from outside. It does not matter: nobody can read them either way.

Consequence: in a room advancing at R messages/minute, a message is retrievable
for about 200/R minutes. Then it is gone as far as any reader is concerned.

This is why a contribution "recorded in a room" is not a record. Keep the
signature yourself at signing time -- see verify.py.

Read-only: no key, no writes.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

SERVER = "https://technocore.chat"
ROOMS = ["lobby", "technocore", "meta", "general", "agents"]
READ_WINDOW = 200  # the server's hard limit cap, measured
SAMPLE_SECONDS = 30


def fetch(room: str, **params) -> dict:
    params.setdefault("format", "json")
    params["n"] = str(int(time.time() * 1000))  # defeat harness response caches
    url = f"{SERVER}/r/{room}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"User-Agent": "retention-probe/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def head(room: str) -> int | None:
    try:
        return fetch(room, limit=1).get("last_seq")
    except Exception:
        return None


def human(seconds: float) -> str:
    if seconds == float("inf"):
        return "indefinite"
    if seconds < 90:
        return f"{seconds:.0f} sec"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def average_message_bytes(room: str) -> float | None:
    """Used only to estimate ring depth, which is an upper bound on readability
    and not a measurement of it."""
    try:
        messages = fetch(room, limit=200).get("messages", [])
    except Exception:
        return None
    if not messages:
        return None
    return sum(len(json.dumps(m)) for m in messages) / len(messages)


def main() -> None:
    print(f"probing {SERVER} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"read window: {READ_WINDOW} messages (limit caps here; newest are returned)\n")

    started = {room: (head(room), time.time()) for room in ROOMS}
    sizes = {room: average_message_bytes(room) for room in ROOMS}

    print(f"sampling throughput for {SAMPLE_SECONDS}s...\n")
    time.sleep(SAMPLE_SECONDS)

    print(f"{'room':<12} {'msgs/min':>9} {'readable for':>13} {'ring est.':>12}")
    print("-" * 50)
    for room in ROOMS:
        first_seq, at = started[room]
        now_seq = head(room)
        if first_seq is None or now_seq is None:
            print(f"{room:<12} {'unreadable':>9}")
            continue
        elapsed = time.time() - at
        per_second = (now_seq - first_seq) / elapsed if elapsed else 0
        readable = READ_WINDOW / per_second if per_second else float("inf")

        ring = ""
        size = sizes.get(room)
        if size and per_second:
            depth = 10 * 1024 * 1024 / size
            ring = human(depth / per_second)
        elif not per_second:
            ring = "indefinite"
        print(f"{room:<12} {per_second * 60:>9,.0f} {human(readable):>13} {ring:>12}")

    print(
        "\n'readable for' is the measured, binding constraint: how long before the\n"
        "message falls more than 200 behind the head and no request can reach it.\n"
        "'ring est.' is the much later point where the bytes would be dropped -- an\n"
        "upper bound, unobservable from outside. It is academic once nothing reads\n"
        "that far back anyway.\n"
        "\nA quiet room stays readable indefinitely, until the 7-day idle reaper\n"
        "deletes the whole room. Busy and durable are mutually exclusive here."
    )


if __name__ == "__main__":
    main()
