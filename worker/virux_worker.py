#!/usr/bin/env python3
"""Virux analysis worker (M1 skeleton).

Design constraints (see REQUIREMENTS / DECISIONS):
  - Isolated, on-demand only. Never a privileged always-on bottleneck.
  - Talks to the Swift daemon over a Unix-domain socket in a directory the
    daemon owns (mode 0700), after verifying peer credentials (uid/gid).
  - Does local work only: hashing, lightweight heuristics, report assembly.
    No automatic upload of personal files or samples.

This file is a skeleton: the transport and peer-credential check are real; the
analysis is a placeholder that returns an explicit "inconclusive" verdict so it
is never mistaken for a real determination.
"""
import argparse
import ctypes
import hashlib
import json
import os
import socket
import struct
import sys
import threading

LIB_C = ctypes.CDLL(None, use_errno=True)
LIB_C.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                             ctypes.POINTER(ctypes.c_uint)]
LIB_C.getpeereid.restype = ctypes.c_int


def peer_credentials(fd):
    """Return (uid, gid) of the peer on a connected AF_UNIX socket, or None."""
    uid = ctypes.c_uint(0)
    gid = ctypes.c_uint(0)
    rc = LIB_C.getpeereid(fd, ctypes.byref(uid), ctypes.byref(gid))
    if rc != 0:
        return None
    return (uid.value, gid.value)


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def recv_message(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    return json.loads(recv_exact(conn, length).decode("utf-8"))


def send_message(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)


def sha256_file(path, max_bytes=256 * 1024 * 1024):
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return None
            h.update(chunk)
    return h.hexdigest()


def handle_request(req):
    cmd = req.get("cmd")
    if cmd == "ping":
        return {"pong": {"version": "0.1.0-m1"}}
    if cmd == "analyze":
        path = req.get("path")
        digest = req.get("sha256")
        notes = [f"worker received analyze for {path}"]
        if digest is None and path and os.path.isfile(path):
            digest = sha256_file(path)
            notes.append("computed local sha256")
        # Honest placeholder: never claim a verdict we did not earn.
        return {"analysis": {"verdict": "inconclusive",
                             "notes": notes,
                             "confidence": "low",
                             "sha256": digest}}
    return {"error": f"unknown command: {cmd}"}


def serve(sock_path):
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, 0o600)
    server.listen(4)
    my_uid = os.getuid()
    print(f"virux-worker listening on {sock_path} (uid={my_uid})", flush=True)
    while True:
        conn, _ = server.accept()
        creds = peer_credentials(conn.fileno())
        if creds is None or creds[0] != my_uid:
            print(f"rejected peer with credentials {creds}", flush=True)
            conn.close()
            continue
        threading.Thread(target=handle_connection, args=(conn,), daemon=True).start()


def handle_connection(conn):
    try:
        while True:
            req = recv_message(conn)
            send_message(conn, handle_request(req))
    except ConnectionError:
        pass
    finally:
        conn.close()


def selftest():
    ok = True
    tmp = "/tmp/virux-worker-selftest"
    with open(tmp, "wb") as fh:
        fh.write(b"abc")
    got = sha256_file(tmp)
    want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print(f"sha256 selftest: {got}")
    ok = ok and (got == want)
    print(f"peer-credential symbol available: {bool(LIB_C.getpeereid)}")
    print("SELFTEST PASS" if ok else "SELFTEST FAIL")
    os.unlink(tmp)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Virux analysis worker (M1 skeleton)")
    ap.add_argument("--socket", default=os.path.expanduser("~/Library/Application Support/Virux/worker.sock"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    os.makedirs(os.path.dirname(args.socket), exist_ok=True)
    serve(args.socket)


if __name__ == "__main__":
    main()