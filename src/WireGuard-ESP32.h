/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

class WireGuard
{
private:
    bool _is_initialized = false;
public:
    bool begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    // AmneziaWG variant: preshared key + obfuscation parameters.
    // presharedKey and headerProtectionKey are base64 (32 bytes decoded), may be nullptr.
    // jc/jmin/jmax = junk packets, s1..s4 = message prefixes, headerProtectionKey enables HP.
    bool beginAWG(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort,
                  const char* presharedKey, uint16_t keepAlive,
                  uint16_t jc, uint16_t jmin, uint16_t jmax,
                  uint16_t s1, uint16_t s2, uint16_t s3, uint16_t s4,
                  const char* headerProtectionKey);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
};
