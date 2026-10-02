#!/usr/bin/env python3
"""Decode an AmneziaVPN share link (vpn://...) into a readable config.

Usage:
    python parse_vpn_config.py "vpn://AAAMMXja..."

Amnezia link format: base64url( 4-byte big-endian length + zlib(JSON) ),
sometimes wrapped in an extra outer zlib layer. Prints host, port, DNS,
protocol version, obfuscation parameters and the client keys/PSK found
in the link.
"""

import base64
import json
import struct
import sys
import zlib


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("vpn://"):
        print(__doc__)
        sys.exit(1)

    b = sys.argv[1][len("vpn://"):]
    data = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))
    print("outer head:", data[:16].hex(), "len:", len(data), file=sys.stderr)

    # Unwrap an optional outer zlib layer
    try:
        data = zlib.decompress(data)
    except zlib.error:
        pass

    # 4-byte big-endian length prefix + zlib(JSON)
    if data[:4] != b"{":
        ln = struct.unpack(">I", data[:4])[0]
        payload = data[4:4 + ln]
        data = zlib.decompress(payload) if payload[:2] in (b"\x78\xda", b"\x78\x9c") else payload

    cfg = json.loads(data.decode("utf-8"))

    awg = {}
    for c in cfg.get("containers", []):
        if "awg" in c:
            awg = c["awg"]
            break

    out = {
        "hostName": cfg.get("hostName"),
        "port": awg.get("port"),
        "dns1": cfg.get("dns1"),
        "dns2": cfg.get("dns2"),
        "protocol_version": awg.get("protocol_version"),
        "container": awg.get("container"),
        "params": {k: awg.get(k) for k in (
            "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
            "H1", "H2", "H3", "H4", "HeaderProtectionKey",
            "ContentPaddingAddition", "RandomTrailers", "DisableCookies",
            "I1", "I2", "I3", "I4", "I5") if awg.get(k)},
    }

    lc = awg.get("last_config")
    inner = json.loads(lc) if isinstance(lc, str) else (lc or {})
    out["client"] = {k: inner.get(k) for k in (
        "client_ip", "client_priv_key", "psk_key", "server_pub_key",
        "port", "mtu", "persistent_keep_alive")}

    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
