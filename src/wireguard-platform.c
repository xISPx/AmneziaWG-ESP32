/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "wireguard-platform.h"

#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "lwip/sys.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs.h"

static struct mbedtls_ctr_drbg_context random_context;
static struct mbedtls_entropy_context entropy_context;
static bool is_platform_initialized = false;

static int entropy_hw_random_source( void *data, unsigned char *output, size_t len, size_t *olen ) {
    esp_fill_random(output, len);
	*olen = len;
    return 0;
}

// ---------------------------------------------------------------
// Монотонный TAI64N-таймштамп.
//
// Пир отвергает handshake, если таймштамп МЕНЬШЕ максимального из
// когда-либо приходивших с этого ключа (защита от replay). Поэтому:
//  - в NVS храним МАКСИМУМ когда-либо выданного таймштампа (записываем
//    только растущие значения, переживает перезагрузку);
//  - если системное время не синхронизировано (до NTP) или скакнуло
//    назад (SNTP-коррекция) - выдаём сохранённый максимум + прирост,
//    а не время из 1970-го.
// ---------------------------------------------------------------
#define TAI_EPOCH_1970_MS 0x400000000000000aULL * 1000ULL
// Системное время "реалистично", если позже 2024-01-01 (unix ms)
#define UNIX_MS_REALISTIC_MIN 1704067200000ULL
static const char *TAI_TAG = "[WG-time]";
static uint64_t s_lastTaiMs = 0;   // максимальный выданный таймштамп, мс TAI
static bool s_taiRestored = false;

static void tai_restore_from_nvs(void) {
	if (s_taiRestored) return;
	nvs_handle_t h;
	if (nvs_open("wgtime", NVS_READONLY, &h) == ESP_OK) {
		uint64_t stored = 0;
		if (nvs_get_u64(h, "taims", &stored) == ESP_OK) {
			// Отбрасываем мусорные значения (из эпохи 1970 - до первого NTP)
			if (stored > TAI_EPOCH_1970_MS + UNIX_MS_REALISTIC_MIN) {
				s_lastTaiMs = stored;
				ESP_LOGI(TAI_TAG, "из NVS восстановлен максимум таймштампа");
			} else {
				ESP_LOGW(TAI_TAG, "в NVS нереалистичный таймштамп - игнорирую");
			}
		}
		nvs_close(h);
	}
	s_taiRestored = true;
}

static void tai_persist_if_greater(uint64_t taiMs) {
	static uint64_t persisted = 0;
	if (taiMs <= persisted) return;
	nvs_handle_t h;
	if (nvs_open("wgtime", NVS_READWRITE, &h) == ESP_OK) {
		if (nvs_set_u64(h, "taims", taiMs) == ESP_OK) {
			nvs_commit(h);
			persisted = taiMs;
		}
		nvs_close(h);
	}
}

void wireguard_platform_init() {
	if( is_platform_initialized ) return;

	mbedtls_entropy_init(&entropy_context);
	mbedtls_ctr_drbg_init(&random_context);
	mbedtls_entropy_add_source(&entropy_context, entropy_hw_random_source, NULL, 134, MBEDTLS_ENTROPY_SOURCE_STRONG);
	mbedtls_ctr_drbg_seed(&random_context, mbedtls_entropy_func, &entropy_context, NULL, 0);

	tai_restore_from_nvs();

	is_platform_initialized = true;
}

void wireguard_random_bytes(void *bytes, size_t size) {
	uint8_t *out = (uint8_t *)bytes;
	mbedtls_ctr_drbg_random(&random_context, bytes, size);
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

void wireguard_tai64n_now(uint8_t *output) {
	// 64 bit seconds (TAI, смещение 0x400000000000000a от 1970) + 32 bit nanos
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t unixMs = (tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL));
	uint64_t taiMs = TAI_EPOCH_1970_MS + unixMs;

	tai_restore_from_nvs();

	if (unixMs >= UNIX_MS_REALISTIC_MIN) {
		// Системное время синхронизировано - берём его (или максимум с NVS)
		if (taiMs <= s_lastTaiMs) {
			taiMs = s_lastTaiMs + 1;
		}
	} else {
		// Время не синхронизировано (1970+uptime): выдаём максимум+1.
		// Если и максимума нет (первый запуск без NTP) - handshake обречён,
		// но vpnInit не поднимает туннель до успешного NTP, так что это
		// защитный путь.
		ESP_LOGW(TAI_TAG, "системное время не синхронизировано - выдаю максимум из NVS");
		taiMs = s_lastTaiMs + 1;
	}
	s_lastTaiMs = taiMs;

	uint64_t seconds = taiMs / 1000;
	uint32_t nanos = (uint32_t)((taiMs % 1000) * 1000000ULL);
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);

	// Пишем только растущие значения (раз в ~2 мин, при rekey-handshake)
	tai_persist_if_greater(taiMs);
}

bool wireguard_is_under_load() {
	return false;
}
