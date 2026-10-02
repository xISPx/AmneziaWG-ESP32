/*
 * AmneziaWG 3.x obfuscation layer for WireGuard-ESP32.
 *
 * Implements the wire format of AmneziaWG (amnezia-vpn/amneziawg-go, protocol
 * used by AmneziaVPN "amnezia-awg2" containers, protocol_version 3.1):
 *   - Junk packets: Jc UDP datagrams of random length [Jmin, Jmax-1] sent
 *     immediately before every handshake initiation.
 *   - S1/S2/S3/S4: random prefixes prepended to handshake initiation /
 *     handshake response / cookie reply / transport data datagrams. MACs are
 *     computed over the unpadded message (as in standard WireGuard); the
 *     prefix is not authenticated. Prefix must be >= 12 bytes when header
 *     protection is on: its first 12 bytes serve as the ChaCha20 nonce.
 *   - H1..H4: message type constants (we only support single values, not the
 *     UintRange form; values must not overlap).
 *   - HeaderProtectionKey: raw RFC 8439 ChaCha20 keystream (counter = 0,
 *     no Poly1305) XORed over the whole handshake message, or over the first
 *     16 bytes (the transport header) of transport datagrams.
 *   - ContentPaddingAddition: zero padding appended to the plaintext inside
 *     the encrypted transport payload (client-side, optional on our side).
 *
 * RandomTrailers and DisableCookies are receive-side/behavioural: we never
 * send trailers (the server accepts exact-size datagrams) and never rely on
 * cookie replies.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _AWG_H_
#define _AWG_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AWG_HP_NONCE_LEN (12) // first 12 bytes of the Sx prefix carry the ChaCha20 nonce

// Forward declarations (full definitions live in wireguard.h)
struct wireguard_device;
struct wireguard_peer;

struct awg_config {
	bool enabled;    // any obfuscation configured at all
	bool hp_enabled; // header protection active (key present and all S >= 12)
	uint16_t jc, jmin, jmax;
	uint16_t s1, s2, s3, s4;
	uint32_t h1, h2, h3, h4;
	uint8_t hp_key[32];
};

// XOR buf with raw ChaCha20 keystream (RFC 8439 block function, counter 0..).
void awg_xor_keystream(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len);

// Send Jc junk UDP datagrams to the peer endpoint (call right before an initiation).
void awg_send_junk_packets(struct wireguard_device *device, struct wireguard_peer *peer);

// Determine the AWG message type of a datagram, unmasking it in place.
// Returns one of MESSAGE_* and sets *msg_offset to the Sx prefix length.
// Falls back to standard (vanilla) WireGuard detection when obfuscation is off.
uint8_t awg_classify_packet(struct wireguard_device *device, uint8_t *data, size_t len, size_t *msg_offset);

#endif /* _AWG_H_ */
