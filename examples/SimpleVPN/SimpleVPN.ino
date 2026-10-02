// ============================================================
// AmneziaWG-ESP32 example: bring up an AWG tunnel and verify the
// exit IP through it (should show your VPS address, not your home IP).
//
// !!! Replace every YOUR_* placeholder below. NEVER commit real
// !!! keys - keep them in a gitignored header or enter them another way.
// ============================================================
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WireGuard-ESP32.h>   // or <AmneziaWG-ESP32.h>
#include "lwip/dns.h"          // dns_setserver (LOCK_TCPIP_CORE below)
#include "lwip/tcpip.h"        // LOCK_TCPIP_CORE / UNLOCK_TCPIP_CORE

// ---------------- WiFi ----------------
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// ---------------- AmneziaWG ----------------
// Copy the values from your server's AmneziaWG config (Amnezia app export,
// .conf file, or vpn:// link - see tools/parse_vpn_config.py in the repo).
// Every obfuscation parameter MUST match the server exactly.

static IPAddress AWG_LOCAL(10, 8, 1, 100);   // free client IP in the VPN subnet
static const char* AWG_PRIVATE_KEY = "YOUR_PRIVATE_KEY_BASE64";        // [Interface] PrivateKey
static const char* AWG_ENDPOINT    = "203.0.113.10";                   // [Peer] Endpoint host (IP literal is most reliable)
static uint16_t    AWG_PORT        = 51820;                            // [Peer] Endpoint port
static const char* AWG_SERVER_PUB  = "YOUR_SERVER_PUBLIC_KEY_BASE64";  // [Peer] PublicKey
static const char* AWG_PSK         = nullptr;                          // [Peer] PresharedKey (base64) or nullptr
static const char* AWG_HP_KEY      = nullptr;                          // HeaderProtectionKey (AWG 3.x, base64) or nullptr

// Obfuscation parameters (MUST match the server). Zeros = plain WireGuard.
static uint16_t AWG_JC   = 5;
static uint16_t AWG_JMIN = 10, AWG_JMAX = 50;
static uint16_t AWG_S1 = 108, AWG_S2 = 79, AWG_S3 = 40, AWG_S4 = 12;

static WireGuard wg;

void setup() {
  Serial.begin(115200);

  // 1. WiFi
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);  // modem sleep adds 100ms+ latency spikes
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\n[NET] connected, IP %s\n", WiFi.localIP().toString().c_str());

  // 2. Time. The AWG handshake carries TAI64N timestamps: if the clock is not
  // synced (or jumps backwards), the server SILENTLY rejects every handshake.
  // The library also keeps its own monotonic timestamp in NVS as a safety net.
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  struct tm timeinfo;
  if (getLocalTime(&timeinfo, 15000)) {
    Serial.println(&timeinfo, "[NTP] synced: %Y-%m-%d %H:%M:%S");
  } else {
    Serial.println("[NTP] FAILED - handshakes will likely be rejected!");
  }

  // 3. Tunnel. After beginAWG() the wg interface becomes the lwIP default
  // route: ALL TCP/UDP/DNS traffic of the device goes through the VPN,
  // while the tunnel's own UDP packets keep using the WiFi interface.
  if (!wg.beginAWG(AWG_LOCAL, AWG_PRIVATE_KEY, AWG_ENDPOINT, AWG_SERVER_PUB, AWG_PORT,
                   AWG_PSK, 25,  // preshared key, persistent keepalive seconds
                   AWG_JC, AWG_JMIN, AWG_JMAX,
                   AWG_S1, AWG_S2, AWG_S3, AWG_S4,
                   AWG_HP_KEY)) {
    Serial.println("[VPN] init FAILED");
    return;
  }
  Serial.println("[VPN] tunnel up, default route switched to VPN");

  // 4. DNS must be reachable through the tunnel (the WiFi-side DNS server
  // is no longer on the default route).
  LOCK_TCPIP_CORE();
  ip_addr_t dns = IPADDR4_INIT(static_cast<uint32_t>(IPAddress(1, 1, 1, 1)));
  dns_setserver(0, &dns);
  UNLOCK_TCPIP_CORE();
  Serial.println("[VPN] DNS set to 1.1.1.1 (via tunnel)");
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last >= 15000) {
    last = millis();
    HTTPClient http;
    http.begin("http://api.ipify.org/");  // returns the exit IP
    int code = http.GET();
    Serial.printf("[VPN] exit IP (%d): %s\n", code,
                  (code == 200) ? http.getString().c_str() : "FAIL");
    http.end();
  }
  delay(200);
}
