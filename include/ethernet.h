#ifndef NET_COURSE_ETHERNET_H
#define NET_COURSE_ETHERNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Разбор и сериализация Ethernet-кадра (Ethernet II / IEEE 802.3).
 *
 * Формат кадра на проводе (без преамбулы/SFD и без FCS — контрольную сумму
 * обычно отбрасывает сетевой адаптер, поэтому в API её нет):
 *
 *   +-------------+-------------+----------------+----------------------+
 *   | dst MAC (6) | src MAC (6) | EtherType (2)  | payload (46..1500)   |
 *   +-------------+-------------+----------------+----------------------+
 *
 * EtherType 0x0800 (IPv4) и ограничение полезной нагрузки 46..1500 байт
 * определены в RFC 894. Реестр EtherType — RFC 7042; ARP — RFC 826;
 * IPv6 over Ethernet — RFC 2464.
 *
 * Если значение поля меньше 0x0600, это не EtherType, а длина полезной
 * нагрузки по IEEE 802.3 — такой кадр тоже разбирается (см. length_field).
 *
 * VLAN-тег IEEE 802.1Q (4 байта) вставляется между MAC-адресами и EtherType:
 *
 *   +---------+---------+----------+---------+---------+-----------------+
 *   | dst (6) | src (6) | TPID (2) | TCI (2) | Type(2) | payload ...     |
 *   +---------+---------+----------+---------+---------+-----------------+
 *
 * Раскладка TCI: PCP (3 бита) | DEI (1 бит) | VID (12 бит).
 * Поддерживается ровно один тег; вложенные теги (QinQ, IEEE 802.1ad)
 * отвергаются.
 *
 * Все многобайтовые поля передаются в сетевом порядке байт (big-endian).
 */

/* Длина MAC-адреса в октетах (48 бит). */
#define ETH_ADDR_LEN 6

/* Размер заголовка Ethernet II без тега: dst + src + EtherType. */
#define ETH_HEADER_LEN 14

/* Размер VLAN-тега: TPID + TCI. */
#define ETH_VLAN_TAG_LEN 4

/* Размер заголовка кадра с VLAN-тегом: 18 байт. */
#define ETH_VLAN_HEADER_LEN (ETH_HEADER_LEN + ETH_VLAN_TAG_LEN)

/* Минимальная длина полезной нагрузки (RFC 894, IEEE 802.3). */
#define ETH_MIN_PAYLOAD 46

/* Максимальная длина полезной нагрузки (MTU Ethernet, RFC 894). */
#define ETH_MAX_PAYLOAD 1500

/* Минимальный кадр без FCS: 60 байт. */
#define ETH_FRAME_MIN_LEN (ETH_HEADER_LEN + ETH_MIN_PAYLOAD)

/* Максимальный кадр без FCS: 1514 байт. */
#define ETH_FRAME_MAX_LEN (ETH_HEADER_LEN + ETH_MAX_PAYLOAD)

/* Минимальный кадр с VLAN-тегом без FCS: 64 байта. */
#define ETH_VLAN_FRAME_MIN_LEN (ETH_VLAN_HEADER_LEN + ETH_MIN_PAYLOAD)

/* Максимальный кадр с VLAN-тегом без FCS: 1518 байт. */
#define ETH_VLAN_FRAME_MAX_LEN (ETH_VLAN_HEADER_LEN + ETH_MAX_PAYLOAD)

/* Длина FCS (CRC-32). В API не входит: адаптер отбрасывает её сам. */
#define ETH_FCS_LEN 4

/* EtherType: IPv4 (RFC 894). */
#define ETH_TYPE_IPV4 0x0800

/* EtherType: ARP (RFC 826). */
#define ETH_TYPE_ARP 0x0806

/* EtherType: IPv6 (RFC 2464). */
#define ETH_TYPE_IPV6 0x86DD

/* TPID VLAN-тега IEEE 802.1Q. */
#define ETH_TYPE_VLAN 0x8100

/* TPID сервисного тега IEEE 802.1ad (QinQ). */
#define ETH_TYPE_QINQ 0x88A8

/* Граница Ethernet II и IEEE 802.3: значения < 0x0600 — это длина. */
#define ETH_TYPE_MIN 0x0600

/* VLAN TCI: сдвиг и маска PCP (3 бита). */
#define ETH_VLAN_PCP_SHIFT 13
#define ETH_VLAN_PCP_MASK 0x0007

/* VLAN TCI: маска DEI (1 бит). */
#define ETH_VLAN_DEI_MASK 0x1000

/* VLAN TCI: маска VID (12 бит). */
#define ETH_VLAN_VID_MASK 0x0FFF

/*
 * MAC-адрес устройства — последовательность из ETH_ADDR_LEN октетов.
 * octets[0] — старший октет (как в записи "AA:BB:CC:DD:EE:FF").
 */
typedef struct eth_mac {
  uint8_t octets[ETH_ADDR_LEN];
} eth_mac_t;

/*
 * Разобранный VLAN-тег IEEE 802.1Q / 802.1ad.
 */
typedef struct eth_vlan_tag {
  uint16_t tpid; /* 0x8100 (802.1Q) или 0x88A8 (802.1ad). */
  uint8_t pcp;   /* Priority Code Point, 0..7. */
  bool dei;      /* Drop Eligible Indicator (ранее CFI). */
  uint16_t vid;  /* VLAN Identifier, 0..0x0FFF. */
} eth_vlan_tag_t;

/*
 * Ethernet-кадр.
 *
 * payload после успешного разбора указывает внутрь входного буфера, поэтому
 * буфер должен жить, пока используется структура. При сериализации payload —
 * входные данные, принадлежащие вызывающему коду. Структура памятью не владеет.
 */
typedef struct eth_frame {
  eth_mac_t dst;          /* MAC-адрес назначения. */
  eth_mac_t src;          /* MAC-адрес источника. */
  bool vlan_present;      /* true, если в кадре был VLAN-тег. */
  eth_vlan_tag_t vlan;    /* Значим только при vlan_present; иначе обнулён. */
  uint16_t ether_type;    /* EtherType (Ethernet II) или длина (IEEE 802.3). */
  bool length_field;      /* true, если ether_type < ETH_TYPE_MIN (802.3). */
  const uint8_t *payload; /* Полезная нагрузка без FCS. */
  size_t payload_len; /* Длина нагрузки: ETH_MIN_PAYLOAD..ETH_MAX_PAYLOAD. */
} eth_frame_t;

/*
 * Разбирает Ethernet-кадр из buf длиной len байт.
 *
 * Ожидается кадр без преамбулы/SFD и без FCS. Поддерживаются:
 *   - Ethernet II: EtherType >= 0x0600;
 *   - IEEE 802.3: поле < 0x0600 (выставляется length_field);
 *   - один VLAN-тег IEEE 802.1Q/802.1ad (TPID 0x8100/0x88A8).
 *
 * При успехе заполняет *out, выставляет out->payload внутрь buf и
 * возвращает 0.
 *
 * Возвращает -1 (и не изменяет *out), если:
 *   - buf == NULL или out == NULL;
 *   - len < ETH_HEADER_LEN;
 *   - для кадра с тегом len < ETH_VLAN_HEADER_LEN;
 *   - payload_len < ETH_MIN_PAYLOAD или payload_len > ETH_MAX_PAYLOAD;
 *   - внутренний EtherType тегированного кадра снова 0x8100/0x88A8
 *     (вложенные теги QinQ не поддерживаются).
 *
 * TODO(student): реализуйте в src/ethernet.c. Изменять этот заголовок нельзя.
 */
int eth_frame_parse(const uint8_t *buf, size_t len, eth_frame_t *out);

/*
 * Сериализует кадр в буфер out размером out_size байт (без FCS).
 *
 * Поля dst, src и ether_type записываются в сетевом порядке байт.
 * Если vlan_present, между MAC-адресами и ether_type вставляется тег:
 * TPID, затем TCI = (pcp << ETH_VLAN_PCP_SHIFT) |
 * (dei ? ETH_VLAN_DEI_MASK : 0) | (vid & ETH_VLAN_VID_MASK).
 *
 * Поле length_field при сериализации не используется: ether_type пишется
 * как есть.
 *
 * Возвращает количество записанных байт
 * (ETH_HEADER_LEN + payload_len или ETH_VLAN_HEADER_LEN + payload_len)
 * или -1 (не изменяя out), если:
 *   - frame == NULL или out == NULL;
 *   - frame->payload == NULL;
 *   - payload_len < ETH_MIN_PAYLOAD или payload_len > ETH_MAX_PAYLOAD;
 *   - vlan_present и (tpid не 0x8100/0x88A8, pcp > 7 или vid > 0x0FFF);
 *   - out_size меньше требуемого размера кадра.
 *
 * TODO(student): реализуйте в src/ethernet.c. Изменять этот заголовок нельзя.
 */
int eth_frame_serialize(const eth_frame_t *frame, uint8_t *out,
                        size_t out_size);

#endif /* NET_COURSE_ETHERNET_H */
