/*
 * AmneziaWG 3.x obfuscation layer - see awg.h for the wire format notes.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "awg.h"
#include "wireguard.h"
#include "crypto.h"

#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include <string.h>

// ------------------------------------------------------------------
// RFC 8439 ChaCha20 block function (raw keystream, no Poly1305)
// ------------------------------------------------------------------

#define CHACHA20_ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
	x[a] += x[b]; x[d] ^= x[a]; x[d] = CHACHA20_ROTL(x[d], 16); \
	x[c] += x[d]; x[b] ^= x[c]; x[b] = CHACHA20_ROTL(x[b], 12); \
	x[a] += x[b]; x[d] ^= x[a]; x[d] = CHACHA20_ROTL(x[d], 8);  \
	x[c] += x[d]; x[b] ^= x[c]; x[b] = CHACHA20_ROTL(x[b], 7);

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
	uint32_t state[16];
	uint32_t x[16];
	int i;

	state[0] = 0x61707865; // "expa"
	state[1] = 0x3320646e; // "nd 3"
	state[2] = 0x79622d32; // "2-by"
	state[3] = 0x6b206574; // "te k"
	for (i = 0; i < 8; i++) {
		state[4 + i] = U8TO32_LITTLE(key + 4 * i);
	}
	state[12] = counter;
	state[13] = U8TO32_LITTLE(nonce + 0);
	state[14] = U8TO32_LITTLE(nonce + 4);
	state[15] = U8TO32_LITTLE(nonce + 8);

	memcpy(x, state, sizeof(x));
	for (i = 0; i < 10; i++) {
		CHACHA20_QUARTERROUND(x, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(x, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(x, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(x, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(x, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(x, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(x, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(x, 3, 4, 9, 14)
	}
	for (i = 0; i < 16; i++) {
		U32TO8_LITTLE(out + 4 * i, x[i] + state[i]);
	}
}

void awg_xor_keystream(const uint8_t key[32], const uint8_t nonce[12], uint8_t *buf, size_t len) {
	uint8_t ks[64];
	size_t off = 0;
	uint32_t counter = 0;
	while (off < len) {
		size_t n = len - off;
		if (n > 64) {
			n = 64;
		}
		chacha20_block(key, nonce, counter++, ks);
		for (size_t i = 0; i < n; i++) {
			buf[off + i] ^= ks[i];
		}
		off += n;
	}
}

// ------------------------------------------------------------------
// Junk packets
// ------------------------------------------------------------------

void awg_send_junk_packets(struct wireguard_device *device, struct wireguard_peer *peer) {
	struct awg_config *a = &device->awg;
	int i;

	if (!a->enabled || (a->jc == 0) || (a->jmax <= a->jmin)) {
		return;
	}
	for (i = 0; i < a->jc; i++) {
		// AWG 3.x size formula: [Jmin, Jmax-1]
		uint8_t r;
		wireguard_random_bytes(&r, 1);
		uint16_t len = a->jmin + (r % (a->jmax - a->jmin));
		struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
		if (!p) {
			continue;
		}
		wireguard_random_bytes(p->payload, len);
		udp_sendto_if(device->udp_pcb, p, &peer->ip, peer->port, device->underlying_netif);
		pbuf_free(p);
	}
}

// ------------------------------------------------------------------
// Receive-side classification with in-place unmasking
// ------------------------------------------------------------------

uint8_t awg_classify_packet(struct wireguard_device *device, uint8_t *data, size_t len, size_t *msg_offset) {
	struct awg_config *a = &device->awg;
	uint8_t type_hash[4];
	int i;

	*msg_offset = 0;
	if (!a->enabled || !a->hp_enabled) {
		return wireguard_get_message_type(data, len);
	}
	if (len < AWG_HP_NONCE_LEN + 4) {
		return MESSAGE_INVALID;
	}

	// typeHash = keystream[0:4] (XOR of 4 zero bytes)
	memset(type_hash, 0, sizeof(type_hash));
	awg_xor_keystream(a->hp_key, data, type_hash, sizeof(type_hash));

	// Candidates ordered handshake-first; each: (prefix, message size, header type value)
	const struct {
		uint16_t pad;
		uint16_t size;
		uint32_t h;
		uint8_t type;
	} cands[] = {
		{ a->s1, 148, a->h1, MESSAGE_HANDSHAKE_INITIATION },
		{ a->s2, 92, a->h2, MESSAGE_HANDSHAKE_RESPONSE },
		{ a->s3, 64, a->h3, MESSAGE_COOKIE_REPLY },
		{ a->s4, 16, a->h4, MESSAGE_TRANSPORT_DATA },
	};
	const size_t cand_count = sizeof(cands) / sizeof(cands[0]);

	for (i = 0; i < (int)cand_count; i++) {
		size_t pad = cands[i].pad;
		size_t min_len;
		if (cands[i].type == MESSAGE_TRANSPORT_DATA) {
			// 16-byte header + at least the 16-byte auth tag
			min_len = pad + 16 + WIREGUARD_AUTHTAG_LEN;
		} else {
			// The server runs with RandomTrailers on, so accept padded datagrams too
			min_len = pad + cands[i].size;
		}
		if (len < min_len) {
			continue;
		}
		uint32_t type = U8TO32_LITTLE(data + pad) ^ U8TO32_LITTLE(type_hash);
		if (type != cands[i].h) {
			continue;
		}
		// Match: unmask in place - handshake messages entirely, transport header only
		size_t mask_len = (cands[i].type == MESSAGE_TRANSPORT_DATA) ? 16 : cands[i].size;
		awg_xor_keystream(a->hp_key, data, data + pad, mask_len);
		*msg_offset = pad;
		return cands[i].type;
	}
	return MESSAGE_INVALID;
}
