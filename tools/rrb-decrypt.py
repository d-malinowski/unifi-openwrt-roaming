#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 d-malinowski
"""Decrypt captured 802.11r RRB-OUI frames (ethertype 0x88b7) from hostapd APs.

Use it to check whether two APs (for example UniFi and OpenWrt) share the same
FT key holder key, and which frame format each of them uses:

  upstream hostapd: 00 13 74 00 01 | type | auth_len | auth TLVs | encrypted
  UniFi:            00 13 74 00 01 | type | src AP(6) | dst AP(6) | auth_len | ...

Input is either a pcap file or the text output of tcpdump, for example:

  tcpdump -i br-lan -e -n -w rrb.pcap 'ether proto 0x88b7'
  tcpdump -i br-lan -e -n -l 'ether proto 0x88b7' | tee rrb.txt

The key is the r0kh/r1kh key from the hostapd config (32 or 64 hex characters).
Requires: pip install cryptography
"""
import argparse
import hashlib
import hmac
import re
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

ETH_P_OUI = 0x88B7
RRB_OUI = bytes([0x00, 0x13, 0x74, 0x00, 0x01])

MSG_TYPES = {1: "pull", 2: "pull-resp", 3: "push", 4: "seq-req", 5: "seq-resp"}
TLV_R0KH_ID = 4
TLV_R1KH_ID = 5


def derive_key(hexkey):
    """Same as hostapd rkh_derive_key(): a 256-bit key is used as is, a legacy
    128-bit key is expanded with hmac_sha256_kdf(key, "FT OLDKEY")."""
    raw = bytes.fromhex(hexkey)
    if len(raw) == 32:
        return raw
    if len(raw) == 16:
        # hmac_sha256_kdf: HMAC-SHA256(key, label || '\0' || seed || counter), 32 bytes
        return hmac.new(raw, b"FT OLDKEY\x00" + b"\x01", hashlib.sha256).digest()
    raise ValueError("key must be 32 or 64 hex characters")


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def read_pcap(path):
    """Yield Ethernet frames from a classic pcap file (link type Ethernet)."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = hdr[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("not a pcap file (pcapng is not supported, use tcpdump -w)")
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != 1:
            raise ValueError(f"unsupported pcap link type {linktype}, need Ethernet (1)")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            incl_len = struct.unpack(endian + "I", rec[8:12])[0]
            yield f.read(incl_len)


def read_tcpdump_text(path):
    """Yield Ethernet frames rebuilt from 'tcpdump -e' text output with hex dump."""
    head_re = re.compile(r"^\S+ ([0-9a-f:]{17}) > ([0-9a-f:]{17}), ethertype .*\((0x[0-9a-f]+)")
    hex_re = re.compile(r"^\s+0x[0-9a-f]{4}:\s+((?:[0-9a-f]{2,4}\s?)+)")
    cur = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = head_re.match(line)
            if m:
                if cur:
                    yield cur
                src, dst, etype = m.group(1), m.group(2), int(m.group(3), 16)
                cur = (bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", ""))
                       + struct.pack(">H", etype))
                continue
            m = hex_re.match(line)
            if m and cur is not None:
                cur += bytes.fromhex(m.group(1).replace(" ", ""))
    if cur:
        yield cur


def parse_tlvs(data):
    tlvs, pos = {}, 0
    while pos + 4 <= len(data):
        t, ln = struct.unpack("<HH", data[pos:pos + 4])
        tlvs.setdefault(t, data[pos + 4:pos + 4 + ln])
        pos += 4 + ln
    return tlvs


def try_decrypt(key, ap_src, msg_type, body):
    """body = LE16 auth_len | auth TLVs | AES-SIV(SIV || ciphertext).
    hostapd AD = [src AP address, auth TLVs, message type]."""
    if len(body) < 2:
        return None
    alen = struct.unpack("<H", body[:2])[0]
    auth, enc = body[2:2 + alen], body[2 + alen:]
    if len(auth) != alen or len(enc) < 16:
        return None
    try:
        plain = AESSIV(key).decrypt(enc, [ap_src, auth, bytes([msg_type])])
    except InvalidTag:
        return None
    return auth, plain


def analyze(frame, key):
    """Return a dict describing one frame, or None if it is not RRB-OUI."""
    if len(frame) < 20 or struct.unpack(">H", frame[12:14])[0] != ETH_P_OUI:
        return None
    if frame[14:19] != RRB_OUI:
        return None
    msg_type = frame[19]
    res = {"eth_dst": mac(frame[0:6]), "eth_src": mac(frame[6:12]), "type": msg_type}
    candidates = [("upstream", frame[6:12], frame[0:6], frame[20:])]
    if len(frame) >= 34:
        candidates.append(("unifi", frame[20:26], frame[26:32], frame[32:]))
    for fmt, ap_src, ap_dst, body in candidates:
        out = try_decrypt(key, ap_src, msg_type, body)
        if out:
            auth, plain = out
            tlvs = parse_tlvs(auth)
            res.update(format=fmt, ap_src=mac(ap_src), ap_dst=mac(ap_dst), plain=plain,
                       r0kh_id=tlvs.get(TLV_R0KH_ID), r1kh_id=tlvs.get(TLV_R1KH_ID))
            return res
    res["format"] = None
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="pcap file or tcpdump text output")
    ap.add_argument("--key", required=True, help="r0kh/r1kh key, 32 or 64 hex characters")
    ap.add_argument("--unique", action="store_true",
                    help="show only the first frame per (format, sender, message type)")
    ap.add_argument("--plaintext", action="store_true", help="also print decrypted TLVs as hex")
    args = ap.parse_args()

    key = derive_key(args.key)
    with open(args.capture, "rb") as f:
        is_pcap = f.read(4) in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    frames = read_pcap(args.capture) if is_pcap else read_tcpdump_text(args.capture)

    seen, total, ok = set(), 0, 0
    for frame in frames:
        r = analyze(frame, key)
        if r is None:
            continue
        total += 1
        ok += r["format"] is not None
        sig = (r["format"], r.get("ap_src", r["eth_src"]), r["type"])
        if args.unique and sig in seen:
            continue
        seen.add(sig)
        tname = MSG_TYPES.get(r["type"], "?")
        if r["format"] is None:
            print(f"type={r['type']} ({tname}) eth {r['eth_src']} -> {r['eth_dst']}: "
                  f"NOT decrypted (wrong key or unknown format)")
            continue
        line = (f"{r['format']:8} type={r['type']} ({tname}) {r['ap_src']} -> {r['ap_dst']} "
                f"[eth {r['eth_src']}]: decrypted, {len(r['plain'])} bytes")
        if r["r0kh_id"]:
            line += f", R0KH-ID={r['r0kh_id'].decode(errors='replace')}"
        if r["r1kh_id"]:
            line += f", R1KH-ID={mac(r['r1kh_id'])}"
        print(line)
        if args.plaintext:
            print("    " + r["plain"].hex())

    print(f"\n{ok}/{total} RRB-OUI frames decrypted")
    return 0 if total and ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
