# AmneziaWG-ESP32

**AmneziaWG VPN client for ESP32** (Arduino / PlatformIO): obfuscated WireGuard
(AmneziaWG protocol 3.x) on top of a WireGuard-lwIP core. Creates a lwIP network
interface, switches the default route to it, and routes **all device traffic**
(TCP/UDP/DNS — e.g. HTTPS to any API) through the tunnel, while the tunnel's own
UDP packets keep using the WiFi interface directly.

Tested against a self-hosted `amneziawg-go` 3.x server (AmneziaVPN
`amnezia-awg` containers, `protocol_version 3.1`) on an ESP32-CAM with
`arduino-esp32` core 3.2.1 (ESP-IDF 5.4).

Real-world use: an ESP32-CAM Telegram bot whose entire Telegram traffic goes
through the tunnel.

> 🇷🇺 Полная инструкция на русском: [README.ru.md](README.ru.md)

---

## What it implements

| Feature | Status |
|---|---|
| Junk packets (`Jc`, `Jmin`, `Jmax`) before every handshake | ✅ (3.x size formula `[Jmin, Jmax-1]`) |
| Prefixes `S1`/`S2`/`S3`/`S4` for initiation/response/cookie/transport | ✅ |
| Header protection (`HeaderProtectionKey`, raw ChaCha20 keystream) | ✅ |
| Preshared key | ✅ |
| `ContentPaddingAddition` (zero padding inside encrypted payload) | ✅ |
| Monotonic handshake timestamps (survive reboots & NTP jumps, stored in NVS) | ✅ |
| `RandomTrailers` on receive / `DisableCookies` servers | ✅ (accepted passively) |
| Special signature packets `I1…I5` (AWG 1.5+) | ❌ |
| Sending trailers, cookie replies with `S3` masking | ❌ (rarely needed: servers with `DisableCookies=on` never send cookies) |
| Peers per device / device instances | 1 / 1 |
| Inner-tunnel IPv6 | ❌ (IPv4 only) |

Plain WireGuard servers are supported too: pass zeros / `nullptr` for the
obfuscation parameters.

## Requirements

- ESP32 board, Arduino framework (`arduino-esp32` core 3.x / ESP-IDF 5.x).
- A reachable NTP server **before** the tunnel goes up (handshake carries
  TAI64N timestamps — a device with a 1970 clock gets silently rejected).
- AmneziaWG server config: private key, client IP, server public key,
  endpoint, PSK (if enabled) and the obfuscation parameters (`Jc…H4`,
  `HeaderProtectionKey`) — **every parameter must match the server exactly**.

## Install (PlatformIO)

Copy the library into the project:

```
your_project/
├── lib/AmneziaWG-ESP32/   <- this folder
├── src/main.cpp
└── platformio.ini
```

or keep it outside and point `platformio.ini` at it:

```ini
lib_extra_dirs = C:/path/to/AmneziaWG-ESP32
```

(For a git repo, `lib_deps = https://github.com/xISPx/AmneziaWG-ESP32.git` also
works.)

## Quick start

Full sketch: [`examples/SimpleVPN/SimpleVPN.ino`](examples/SimpleVPN/SimpleVPN.ino).
Minimal flow:

```cpp
#include <WiFi.h>
#include <WireGuard-ESP32.h>     // or <AmneziaWG-ESP32.h>
#include "lwip/dns.h"
#include "lwip/tcpip.h"

static WireGuard wg;

void setup() {
  // 1. WiFi ...
  // 2. Time (mandatory - see Troubleshooting):
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  struct tm t;
  getLocalTime(&t, 15000);

  // 3. Tunnel: becomes the lwIP default route
  wg.beginAWG(
      IPAddress(10, 8, 1, 100),     // client IP inside the VPN subnet
      "YOUR_PRIVATE_KEY_BASE64",    // [Interface] PrivateKey
      "203.0.113.10",               // [Peer] Endpoint (IP literal recommended)
      "YOUR_SERVER_PUBLIC_KEY",     // [Peer] PublicKey
      51820,                        // [Peer] Endpoint port
      "YOUR_PSK_OR_nullptr",        // [Peer] PresharedKey (base64) / nullptr
      25,                           // persistent keepalive, seconds
      5, 10, 50,                    // Jc, Jmin, Jmax   (0 = disabled)
      108, 79, 40, 12,              // S1, S2, S3, S4   (0 = disabled)
      "YOUR_HP_KEY_OR_nullptr");    // HeaderProtectionKey (base64) / nullptr

  // 4. DNS reachable through the tunnel (WiFi-side DNS is off the default route)
  LOCK_TCPIP_CORE();
  ip_addr_t dns = IPADDR4_INIT(static_cast<uint32_t>(IPAddress(1, 1, 1, 1)));
  dns_setserver(0, &dns);
  UNLOCK_TCPIP_CORE();
}
```

`wg.begin(...)` (without `AWG`) is also available: plain WireGuard, no PSK.

## Parameter reference

| `beginAWG` parameter | Meaning | Where to get it |
|---|---|---|
| `localIP` | Client IP inside the VPN subnet | server assigns (`client_ip`) |
| `privateKey` | Client private key, base64 | `[Interface] PrivateKey` |
| `endpointHost` | Server address (IP literal recommended — hostnames resolve before the tunnel comes up) | `[Peer] Endpoint` |
| `serverPublicKey` | Server public key, base64 | `[Peer] PublicKey` |
| `remotePeerPort` | Server UDP port | `[Peer] Endpoint` |
| `presharedKey` | PSK, base64, or `nullptr` | `[Peer] PresharedKey` |
| `keepAlive` | Persistent keepalive seconds (0 → 10 s) | `PersistentKeepalive` |
| `jc, jmin, jmax` | Junk datagrams sent before each handshake | `Jc/Jmin/Jmax` |
| `s1, s2, s3, s4` | Random prefix sizes: init / response / cookie / transport | `S1/S2/S3/S4` |
| `headerProtectionKey` | HP key, base64, or `nullptr` | `HeaderProtectionKey` |

`H1…H4` are fixed to the standard `1/2/3/4` (the values most Amnezia servers
use). Netif MTU is set to `1420 − S4` automatically.

Use `tools/parse_vpn_config.py` to decode an Amnezia `vpn://…` share link into
readable parameters:

```sh
python tools/parse_vpn_config.py "vpn://AAAMMXja..."
```

## Integration notes

- **Time first.** `configTime(...)` + wait for `getLocalTime()` before
  `beginAWG()`. The library also keeps a monotonic timestamp in NVS
  (namespace `wgtime`) so reboots and NTP corrections cannot trip the server's
  replay protection — but it needs at least one successful NTP sync at some
  point to bootstrap real time.
- **DNS.** After the default route switches to the tunnel, set a DNS server
  that is reachable *through the tunnel* (e.g. `1.1.1.1`), or resolve names
  before enabling the tunnel.
- **ESP-IDF 5 core locking** is handled internally (`LOCK_TCPIP_CORE` around
  `netif_add` etc.) — no extra work in the sketch.
- **One key = one device.** Two devices sharing a private key will steal the
  session from each other (the symptom: works for a few minutes, then dies).
  Get a separate peer/client config per device.
- Telegram-bot integration (keep-alive TLS, long-poll caveats) is documented in
  the project that battle-tested this library.

## Diagnostics & troubleshooting

Build with `-DCORE_DEBUG_LEVEL=3` to see `[WireGuard]` logs:
`start handshake` → `HANDSHAKE_RESPONSE` → `good handshake from IP:port`.

| Symptom | Likely cause |
|---|---|
| Endless `start handshake`, never `good handshake` | time not synced (server rejects timestamps as replay); same private key used on another device; `Jc/Sx/HP` mismatch with server; server down / UDP blocked |
| `DNS Failed ... error -54`, `Host is unreachable` | tunnel is down (see above) or the DNS server is unreachable through it |
| Cycles take 1.5–2 s, then recover | intermittent path degradation (common: ISP DPI throttling a long-lived UDP flow) — raise `bot.waitForResponse`-style timeouts, change server port/IP |
| Works, then dies after minutes | another device using the same key; or time jumped backwards (fixed by the built-in NVS monotonic guard) |
| `assert failed: netif_add ... lock TCPIP core` | old library build on arduino-esp32 3.x — use this fork (it locks the core) |

## Limitations

- ESP32 / arduino-esp32 3.x (the C core is lwIP-based; other ports need work).
- Single peer, single instance, IPv4 inside the tunnel.
- Client never sends `RandomTrailers` and does not obfuscate cookie replies
  (servers with `DisableCookies=on` never send cookies; otherwise a cookie
  reply from a 3.x server would not be recognized — recommend keeping
  `DisableCookies=on`).
- `I1…I5` signature packets are not implemented.

## Credits & license

- WireGuard-lwIP core: Daniel Hope (www.floorsense.nz), BSD-3-Clause.
- ESP32 Arduino port: Kenta Ida; esp_netif/IDF5 patch: Felipe Dadison.
- AmneziaWG obfuscation layer (`awg.c/h`, PSK/plumbing in the wrapper):
  xISPx ([github.com/xISPx](https://github.com/xISPx)). Wire format
  reverse-engineered from [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)
  sources.

BSD-3-Clause — see [LICENSE](LICENSE).
