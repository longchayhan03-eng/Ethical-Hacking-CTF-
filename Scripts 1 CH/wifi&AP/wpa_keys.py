#!/usr/bin/env python3
"""Work out the WPA2 session keys (KCK, KEK, TK) from a captured 4-way handshake.

    python3 wpa_keys.py capture.cap PASSPHRASE SSID [BSSID]

PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32 bytes)
PTK = PRF-512(PMK, "Pairwise key expansion", min/max(AP MAC, client MAC) + min/max(ANonce, SNonce))
KCK = PTK[0:16]   KEK = PTK[16:32]   TK = PTK[32:48]
The MIC in message 2 is checked against the KCK, so a printed result is known to be right.
Reads .pcap and .pcapng, plain 802.11 or with a radiotap header. Needs only python3.
"""
import hashlib, hmac, struct, sys


def frames(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack(e + "I", data[20:24])[0]
        i = 24
        while i + 16 <= len(data):
            incl = struct.unpack(e + "I", data[i + 8:i + 12])[0]
            yield link, data[i + 16:i + 16 + incl]
            i += 16 + incl
    elif magic == b"\x0a\x0d\x0d\x0a":
        links, i, e = [], 0, "<"
        while i + 12 <= len(data):
            if data[i:i + 4] == b"\x0a\x0d\x0d\x0a":
                e = "<" if data[i + 8:i + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                links = []
            btype, blen = struct.unpack(e + "II", data[i:i + 8])
            if blen < 12: break
            body = data[i + 8:i + blen - 4]
            if btype == 1:
                links.append(struct.unpack(e + "H", body[:2])[0])
            elif btype == 6:
                iface, _, _, cap = struct.unpack(e + "IIII", body[:16])
                yield (links[iface] if iface < len(links) else 105), body[20:20 + cap]
            elif btype == 3:
                yield (links[0] if links else 105), body[4:]
            i += blen
    else:
        sys.exit("Not a pcap/pcapng file")


def dot11(link, pkt):
    if link == 127:                      # radiotap
        if len(pkt) < 4: return None
        return pkt[struct.unpack("<H", pkt[2:4])[0]:]
    if link == 119:                      # prism
        return pkt[144:]
    if link == 163:                      # AVS
        return pkt[struct.unpack(">I", pkt[4:8])[0]:]
    return pkt if link == 105 else None


def mac(b): return ":".join("%02x" % x for x in b)


def eapol_key(f):
    """Return (src, dst, bssid, eapol_bytes) for an 802.11 data frame that carries EAPOL."""
    if len(f) < 24: return None
    fc = f[0] | f[1] << 8
    if (fc >> 2) & 3 != 2: return None   # data frames only
    subtype = (fc >> 4) & 0xF
    tods, fromds = fc >> 8 & 1, fc >> 9 & 1
    a1, a2, a3 = f[4:10], f[10:16], f[16:22]
    hdr = 24 + (6 if tods and fromds else 0) + (2 if subtype & 8 else 0)
    if fc & 0x4000: return None          # protected: not a handshake frame
    body = f[hdr:]
    if body[:8] != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e": return None
    if tods and not fromds:   dst, src, bssid = a3, a2, a1
    elif fromds and not tods: dst, src, bssid = a1, a3, a2
    else:                     dst, src, bssid = a1, a2, a3
    return src, dst, bssid, body[8:]


def parse_key(e):
    """EAPOL-Key fields we need. Layout: ver(1) type(1) len(2) desc(1) info(2) keylen(2) replay(8) nonce(32) iv(16) rsc(8) id(8) mic(16) dlen(2)"""
    if len(e) < 99 or e[1] != 3: return None
    info = struct.unpack(">H", e[5:7])[0]
    blen = struct.unpack(">H", e[2:4])[0]
    return {"info": info, "ver": info & 7, "ack": bool(info & 0x80), "mic": bool(info & 0x100),
            "install": bool(info & 0x40), "nonce": e[17:49], "micval": e[81:97], "raw": e[:4 + blen]}


def prf512(key, label, data):
    out = b""
    for i in range(4):
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
    return out[:64]


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    path, pw, ssid = sys.argv[1], sys.argv[2], sys.argv[3]
    want = sys.argv[4].lower() if len(sys.argv) > 4 and sys.argv[4] else None

    anonces, msgs2 = {}, []
    for link, pkt in frames(path):
        f = dot11(link, pkt)
        if not f: continue
        r = eapol_key(f)
        if not r: continue
        src, dst, bssid, e = r
        k = parse_key(e)
        if not k: continue
        if want and mac(bssid) != want: continue
        if k["ack"] and not k["mic"]:                     # message 1: AP -> client, ANonce
            anonces.setdefault((src, dst), []).append(k["nonce"])
        elif k["mic"] and not k["ack"] and not k["install"] and k["nonce"].strip(b"\0"):
            msgs2.append((src, dst, bssid, k))             # message 2: client -> AP, SNonce + MIC
        elif k["ack"] and k["mic"] and k["install"]:       # message 3 also carries the ANonce
            anonces.setdefault((src, dst), []).append(k["nonce"])

    if not msgs2:
        sys.exit("No EAPOL message 2 found (need a handshake with the client's reply)")

    pmk = hashlib.pbkdf2_hmac("sha1", pw.encode(), ssid.encode(), 4096, 32)
    for sta, ap, bss, k2 in msgs2:
        for an, aa in [(n, a) for n in anonces.get((ap, sta), []) for a in dict.fromkeys((ap, bss))]:
            # the AP address used in the key maths is normally the BSSID; some captures send from a second address
            data = min(aa, sta) + max(aa, sta) + min(an, k2["nonce"]) + max(an, k2["nonce"])
            ptk = prf512(pmk, b"Pairwise key expansion", data)
            kck = ptk[:16]
            raw = bytearray(k2["raw"]); raw[81:97] = b"\0" * 16
            if k2["ver"] == 1:
                mic = hmac.new(kck, raw, hashlib.md5).digest()
            else:
                mic = hmac.new(kck, raw, hashlib.sha1).digest()[:16]
            if mic == k2["micval"]:
                print("MIC check : OK (passphrase and handshake match)")
                print("AP (BSSID): " + mac(aa))
                print("Client    : " + mac(sta))
                print("PMK       : " + pmk.hex())
                print("KCK       : " + ptk[:16].hex())
                print("KEK       : " + ptk[16:32].hex())
                print("TK        : " + ptk[32:48].hex())
                return
    sys.exit("MIC did not match: wrong passphrase, wrong SSID (case matters), or messages 1/2 are from different handshakes")


if __name__ == "__main__":
    main()
