#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Raw wire-protocol probes used by test_hardening.sh.
#
# The owsync CLI always writes well-formed, single-write messages, so the
# framing defects these probes target (fragmented reads, zero-length frames,
# oversized announcements) are unreachable from the CLI. Each probe speaks the
# wire format directly and exits 0 only if the daemon behaves as intended.

import json
import socket
import struct
import sys
import time

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 21781
HOST = "127.0.0.1"


def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    return s


def recv_exact(sock, n):
    """Read exactly n bytes. Returns None if the peer closed first."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_message(sock):
    """Read one length-prefixed message. Returns the decoded dict, or None on EOF."""
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    payload = recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode())


def hello_bytes():
    msg = {
        "type": "Hello",
        "hostname": "probe",
        "timestamp": int(time.time()),
        "version": 1,
    }
    return json.dumps(msg).encode()


def probe_fragmented():
    """
    Send a HELLO split across several writes, including a split length prefix.

    TCP is a byte stream, so this is what any real network can deliver. A daemon
    that demands the 4-byte prefix in a single read() drops the session here.
    """
    s = connect()
    if recv_message(s) is None:
        print("FAIL: server did not send its Hello")
        return 1

    payload = hello_bytes()
    prefix = struct.pack(">I", len(payload))

    # Split the length prefix itself, then the payload
    s.sendall(prefix[:1])
    time.sleep(0.2)
    s.sendall(prefix[1:3])
    time.sleep(0.2)
    s.sendall(prefix[3:])
    time.sleep(0.2)
    half = len(payload) // 2
    s.sendall(payload[:half])
    time.sleep(0.2)
    s.sendall(payload[half:])

    reply = recv_message(s)
    s.close()

    if reply is None:
        print("FAIL: session dropped after a fragmented Hello")
        return 1
    if reply.get("type") != "SyncState":
        print("FAIL: expected SyncState after handshake, got %r" % reply.get("type"))
        return 1

    print("OK: fragmented Hello accepted, handshake completed")
    return 0


def probe_zero_length():
    """
    Announce a zero-length message.

    The daemon must reject the frame and stay serving; parsing a zero-byte
    buffer as a C string reads whatever follows it on the heap.
    """
    s = connect()
    if recv_message(s) is None:
        print("FAIL: server did not send its Hello")
        return 1

    s.sendall(struct.pack(">I", 0))
    closed = recv_exact(s, 1) is None
    s.close()

    if not closed:
        print("FAIL: server kept the session open after a zero-length frame")
        return 1

    # The daemon must have survived: a fresh connection still gets served
    try:
        s2 = connect()
    except OSError as exc:
        print("FAIL: daemon stopped accepting connections: %s" % exc)
        return 1

    alive = recv_message(s2) is not None
    s2.close()

    if not alive:
        print("FAIL: daemon no longer completes a handshake")
        return 1

    print("OK: zero-length frame rejected, daemon still serving")
    return 0


def probe_alloc_cap(announce, allowed):
    """
    Open several sessions that each announce a maximum-size message and then
    stall without sending a byte of payload.

    Only `allowed` of them fit in the receive budget; the next one must be
    refused instead of making the daemon reserve another `announce` bytes.
    """
    socks = []
    for i in range(allowed + 1):
        s = connect()
        if recv_message(s) is None:
            print("FAIL: server did not send its Hello on session %d" % i)
            return 1
        s.sendall(struct.pack(">I", announce))
        socks.append(s)
        time.sleep(0.5)  # Keep the reservation order deterministic

    # The sessions within budget stay open; the one over it is dropped
    for i, s in enumerate(socks):
        s.settimeout(3)
        try:
            closed = s.recv(1) == b""
        except socket.timeout:
            closed = False

        if i < allowed and closed:
            print("FAIL: session %d was refused while still within budget" % i)
            return 1
        if i == allowed and not closed:
            print("FAIL: session %d exceeded the budget but was not refused" % i)
            return 1

    for s in socks:
        s.close()

    print("OK: receive budget capped after %d concurrent large messages" % allowed)
    return 0


PROBES = {
    "fragmented": probe_fragmented,
    "zero-length": probe_zero_length,
}

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        if name == "alloc-cap":
            sys.exit(probe_alloc_cap(int(sys.argv[3]), int(sys.argv[4])))
        sys.exit(PROBES[name]())
    except (BrokenPipeError, ConnectionResetError) as exc:
        # The daemon closed on us mid-probe: that is the failure, not a crash here
        print("FAIL: daemon dropped the connection (%s)" % exc)
        sys.exit(1)
    except OSError as exc:
        print("FAIL: %s" % exc)
        sys.exit(1)
