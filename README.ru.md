# AmneziaWG-ESP32

**Клиент AmneziaWG VPN для ESP32** (Arduino / PlatformIO): обфусцированный
WireGuard (протокол AmneziaWG 3.x) поверх ядра WireGuard-lwIP. Создаёт
lwIP-интерфейс, переключает на него маршрут по умолчанию и направляет **весь
трафик устройства** (TCP/UDP/DNS — например HTTPS к любому API) через туннель,
при этом UDP-пакеты самого туннеля идут напрямую через WiFi-интерфейс.

> 🇬🇧 English documentation: [README.md](README.md).

Протестировано на самохранящемся сервере `amneziawg-go` 3.x (контейнеры
AmneziaVPN `amnezia-awg`, `protocol_version 3.1`) на ESP32-CAM с ядром
`arduino-esp32` 3.2.1 (ESP-IDF 5.4).

Реальное применение: Telegram-бот на ESP32-CAM, весь Telegram-трафик которого
идёт через туннель.

---

## Что реализовано

| Возможность | Статус |
|---|---|
| Мусорные пакеты (`Jc`, `Jmin`, `Jmax`) перед каждым handshake | ✅ (формула размеров 3.x: `[Jmin, Jmax-1]`) |
| Префиксы `S1`/`S2`/`S3`/`S4` для initiation/response/cookie/transport | ✅ |
| Защита заголовка (`HeaderProtectionKey`, сырая гамма ChaCha20) | ✅ |
| Preshared key | ✅ |
| `ContentPaddingAddition` (нулевое дополнение внутри шифропакета) | ✅ |
| Монотонные таймстампы handshake (переживают ребут и скачки NTP, хранятся в NVS) | ✅ |
| `RandomTrailers` на приёме / серверы с `DisableCookies` | ✅ (принимаются пассивно) |
| Сигнатурные пакеты `I1…I5` (AWG 1.5+) | ❌ |
| Отправка трейлеров, cookie-ответов с маскировкой `S3` | ❌ (редко нужно: серверы с `DisableCookies=on` cookie не шлют) |
| Пиров на устройство / экземпляров | 1 / 1 |
| IPv6 внутри туннеля | ❌ (только IPv4) |

Обычные WireGuard-серверы тоже поддерживаются: передайте нули / `nullptr` для
параметров обфускации.

## Требования

- Плата ESP32, Arduino framework (`arduino-esp32` 3.x / ESP-IDF 5.x).
- Доступный NTP-сервер **до** поднятия туннеля (handshake несёт TAI64N-таймстампы
  — устройство с часами 1970 года сервер молча отвергнет).
- Конфиг AmneziaWG-сервера: приватный ключ, IP клиента в подсети, публичный
  ключ сервера, endpoint, PSK (если включена) и параметры обфускации
  (`Jc…H4`, `HeaderProtectionKey`) — **каждый параметр должен буквально
  совпадать с сервером**, иначе сервер молча отбрасывает пакеты.

## Установка (PlatformIO)

Скопируйте библиотеку в проект:

```
your_project/
├── lib/AmneziaWG-ESP32/   <- эта папка
├── src/main.cpp
└── platformio.ini
```

или держите отдельно и укажите путь в `platformio.ini`:

```ini
lib_extra_dirs = C:/path/to/AmneziaWG-ESP32
```

(Для git-репозитория работает и `lib_deps = https://github.com/xISPx/AmneziaWG-ESP32.git`.)

## Быстрый старт

Полный скетч: [`examples/SimpleVPN/SimpleVPN.ino`](examples/SimpleVPN/SimpleVPN.ino).
Минимальная последовательность:

```cpp
#include <WiFi.h>
#include <WireGuard-ESP32.h>     // или <AmneziaWG-ESP32.h>
#include "lwip/dns.h"
#include "lwip/tcpip.h"

static WireGuard wg;

void setup() {
  // 1. WiFi ...
  // 2. Время (обязательно — см. «Диагностика»):
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  struct tm t;
  getLocalTime(&t, 15000);

  // 3. Туннель: становится маршрутом по умолчанию в lwIP
  wg.beginAWG(
      IPAddress(10, 8, 1, 100),     // IP клиента внутри VPN-подсети
      "YOUR_PRIVATE_KEY_BASE64",    // [Interface] PrivateKey
      "203.0.113.10",               // [Peer] Endpoint (лучше IP-литерал)
      "YOUR_SERVER_PUBLIC_KEY",     // [Peer] PublicKey
      51820,                        // [Peer] порт endpoint
      "YOUR_PSK_OR_nullptr",        // [Peer] PresharedKey (base64) / nullptr
      25,                           // persistent keepalive, секунд
      5, 10, 50,                    // Jc, Jmin, Jmax   (0 = выключено)
      108, 79, 40, 12,              // S1, S2, S3, S4   (0 = выключено)
      "YOUR_HP_KEY_OR_nullptr");    // HeaderProtectionKey (base64) / nullptr

  // 4. DNS, доступный через туннель (WiFi-сервер DNS больше не на маршруте)
  LOCK_TCPIP_CORE();
  ip_addr_t dns = IPADDR4_INIT(static_cast<uint32_t>(IPAddress(1, 1, 1, 1)));
  dns_setserver(0, &dns);
  UNLOCK_TCPIP_CORE();
}
```

Доступен и `wg.begin(...)` (без `AWG`): чистый WireGuard, без PSK.

## Справочник параметров

| Параметр `beginAWG` | Смысл | Где взять |
|---|---|---|
| `localIP` | IP клиента внутри VPN-подсети | сервер (`client_ip`) |
| `privateKey` | Приватный ключ клиента, base64 | `[Interface] PrivateKey` |
| `endpointHost` | Адрес сервера (лучше IP-литерал: имена резолвятся ДО включения туннеля) | `[Peer] Endpoint` |
| `serverPublicKey` | Публичный ключ сервера, base64 | `[Peer] PublicKey` |
| `remotePeerPort` | UDP-порт сервера | `[Peer] Endpoint` |
| `presharedKey` | PSK, base64, или `nullptr` | `[Peer] PresharedKey` |
| `keepAlive` | Persistent keepalive, секунд (0 → 10 с) | `PersistentKeepalive` |
| `jc, jmin, jmax` | Мусорные датаграммы перед каждым handshake | `Jc/Jmin/Jmax` |
| `s1, s2, s3, s4` | Размеры случайных префиксов: init / response / cookie / transport | `S1/S2/S3/S4` |
| `headerProtectionKey` | Ключ защиты заголовка, base64, или `nullptr` | `HeaderProtectionKey` |

`H1…H4` фиксированы стандартными `1/2/3/4` (так настроено большинство
серверов Amnezia). MTU netif выставляется автоматически: `1420 − S4`.

Ссылку `vpn://…` из приложения Amnezia можно расшифровать в читаемые
параметры скриптом:

```sh
python tools/parse_vpn_config.py "vpn://AAAMMXja..."
```

## Заметки по интеграции

- **Сначала время.** `configTime(...)` + дождаться `getLocalTime()` до
  `beginAWG()`. Библиотека дополнительно хранит монотонный таймстамп в NVS
  (namespace `wgtime`), так что ребуты и коррекции NTP не задевают replay-защиту
  сервера — но хотя бы одна успешная NTP-синхронизация нужна для старта.
- **DNS.** После переключения маршрута по умолчанию на туннель укажите DNS,
  доступный *через туннель* (например `1.1.1.1`), либо резолвите имена до
  включения туннеля.
- **Блокировка ядра ESP-IDF 5** обрабатывается внутри (`LOCK_TCPIP_CORE`
  вокруг `netif_add` и т.п.) — в скетче ничего делать не нужно.
- **Один ключ = одно устройство.** Два устройства с одним приватным ключом
  будут воровать сессию друг у друга (симптом: работает несколько минут,
  потом «фризы»). Берите отдельный peer/конфиг клиента на каждое устройство.
- Интеграция с Telegram-ботом (keep-alive TLS, особенности long-poll)
  описана в проекте, который обкатывал эту библиотеку.

## Диагностика

Соберите с `-DCORE_DEBUG_LEVEL=3`, чтобы видеть логи `[WireGuard]`:
`start handshake` → `HANDSHAKE_RESPONSE` → `good handshake from IP:port`.

| Симптом | Вероятная причина |
|---|---|
| Бесконечные `start handshake`, `good handshake` не приходит | время не синхронизировано (сервер отвергает таймстампы как replay); тот же ключ работает на другом устройстве; рассинхрон `Jc/Sx/HP` с сервером; сервер недоступен / UDP заблокирован |
| `DNS Failed ... error -54`, `Host is unreachable` | туннель не поднялся (см. выше) или DNS-сервер недоступен через него |
| Циклы по 1.5–2 с, потом восстанавливается | деградация канала (частое: DPI-провайдера душит долгоживущий UDP-поток) — увеличьте таймауты уровня `bot.waitForResponse`, смените порт/IP сервера |
| Работает, потом умирает через минуты | другое устройство с тем же ключом; или время прыгнуло назад (лечится встроенной NVS-защитой монотонности) |
| `assert failed: netif_add ... lock TCPIP core` | старая сборка библиотеки на arduino-esp32 3.x — используйте этот форк (он блокирует ядро) |

## Ограничения

- ESP32 / arduino-esp32 3.x (C-ядро построено на lwIP; другие порты требуют работы).
- Один peer, один экземпляр, IPv4 внутри туннеля.
- Клиент не отправляет `RandomTrailers` и не маскирует cookie-ответы
  (серверы с `DisableCookies=on` cookie не шлют; иначе cookie-ответ от
  сервера 3.x не распознается — рекомендуется держать `DisableCookies=on`).
- Сигнатурные пакеты `I1…I5` не реализованы.

## Авторы и лицензия

- Ядро WireGuard-lwIP: Daniel Hope (www.floorsense.nz), BSD-3-Clause.
- ESP32 Arduino-порт: Kenta Ida; патч esp_netif/IDF5: Felipe Dadison.
- Слой обфускации AmneziaWG (`awg.c/h`, PSK/обвязка в обёртке):
  xISPx ([github.com/xISPx](https://github.com/xISPx)). Формат пакетов
  реверс-инжинирен из исходников
  [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).

BSD-3-Clause — см. [LICENSE](LICENSE).
