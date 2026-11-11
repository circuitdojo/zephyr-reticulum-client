/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * The radio thread: reassembles RNode frames into packets for the
 * transport, and transmits queued packets after a random backoff, never
 * while the second half of a split packet is due.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "gateway.h"
#include "radio.h"
#include "ret_crypto.h"
#include "ret_rnode_air.h"

LOG_MODULE_REGISTER(radio_task, LOG_LEVEL_INF);

/*
 * Low data rate optimisation is not configurable in Zephyr's driver, which
 * turns it on for symbols over 16 ms. RNode decides with integer division,
 * so settings just over the line (e.g. SF11 at 125 kHz) would not interoperate.
 */
#define SYMBOL_OVER_16MS ((BIT(CONFIG_RET_LORA_SF) * 1000) > (16 * CONFIG_RET_LORA_BW_HZ))
#define RNODE_LDRO       ((BIT(CONFIG_RET_LORA_SF) / (CONFIG_RET_LORA_BW_HZ / 1000)) > 16)
BUILD_ASSERT(SYMBOL_OVER_16MS == RNODE_LDRO,
	     "these LoRa settings set low data rate optimisation differently from RNode");

#define RX_QUEUE_DEPTH  4
#define STACK_SIZE      3072
#define SPLIT_MARGIN_MS 500

struct rx_frame {
	uint8_t len;
	uint8_t data[RET_RNODE_FRAME_MAX];
};

struct tx_packet {
	uint16_t len;
	uint8_t data[RET_RNODE_MTU];
};

K_MSGQ_DEFINE(rx_q, sizeof(struct rx_frame), RX_QUEUE_DEPTH, 1);
K_MSGQ_DEFINE(tx_q, sizeof(struct tx_packet), CONFIG_RET_LORA_TX_QUEUE, 1);

static K_THREAD_STACK_DEFINE(stack, STACK_SIZE);
static struct k_thread thread;

uint32_t radio_task_bitrate(void)
{
	/* sf * (4 / cr) / (2^sf / bw_khz) kbit/s */
	return (uint32_t)(((uint64_t)CONFIG_RET_LORA_SF * 4 * CONFIG_RET_LORA_BW_HZ) /
			  ((uint64_t)CONFIG_RET_LORA_CR * BIT(CONFIG_RET_LORA_SF)));
}

/* Possibly on a system thread: copy and return. */
static void on_radio_frame(const uint8_t *data, size_t len)
{
	struct rx_frame f;

	if (len == 0 || len > sizeof(f.data)) {
		return;
	}
	f.len = (uint8_t)len;
	memcpy(f.data, data, len);
	if (k_msgq_put(&rx_q, &f, K_NO_WAIT) != 0) {
		LOG_WRN("radio queue full, frame dropped");
	}
}

int radio_task_send(const uint8_t *pkt, size_t len)
{
	static struct tx_packet p;

	if (len == 0 || len > sizeof(p.data)) {
		return -EMSGSIZE;
	}
	p.len = (uint16_t)len;
	memcpy(p.data, pkt, len);
	if (k_msgq_put(&tx_q, &p, K_NO_WAIT) != 0) {
		LOG_WRN("radio busy, packet dropped");
		return -ENOBUFS;
	}
	return 0;
}

/*
 * Wait for the second half of a split packet: a whole frame's airtime, by
 * the formula in the SX126x datasheet, assuming low data rate optimisation
 * and a long preamble, and a margin for the driver.
 */
static uint32_t split_timeout_ms(void)
{
	const uint32_t sf = CONFIG_RET_LORA_SF;
	const uint32_t bits = 8 * RET_RNODE_FRAME_MAX + 44 - 4 * sf;
	const uint32_t symbols = 36 + 8 + DIV_ROUND_UP(bits, 4 * (sf - 2)) * CONFIG_RET_LORA_CR;

	return (uint32_t)(((uint64_t)symbols * BIT(sf) * MSEC_PER_SEC) / CONFIG_RET_LORA_BW_HZ) +
	       SPLIT_MARGIN_MS;
}

static k_timeout_t until(int64_t deadline)
{
	int64_t left = deadline - k_uptime_get();

	return left > 0 ? K_MSEC(left) : K_NO_WAIT;
}

static int64_t backoff_deadline(void)
{
	uint32_t wait = 0;

	if (CONFIG_RET_LORA_BACKOFF_MS > 0) {
		uint8_t r[4];

		if (ret_random(r, sizeof(r)) == 0) {
			memcpy(&wait, r, sizeof(wait));
			wait %= CONFIG_RET_LORA_BACKOFF_MS + 1;
		}
	}
	return k_uptime_get() + wait;
}

static void transmit(const struct tx_packet *p)
{
	static uint8_t frame[2][RET_RNODE_FRAME_MAX];
	struct radio_frame frames[2];
	uint8_t random = 0;
	int count = ret_rnode_frames(p->len);
	int err = count < 0 ? count : 0;

	/* Without randomness the sequence is just less varied. */
	(void)ret_random(&random, 1);
	if (!err) {
		uint8_t header = ret_rnode_header(p->len, random);

		for (int i = 0; i < count; i++) {
			int n = ret_rnode_frame(header, p->data, p->len, i, frame[i]);

			frames[i].data = frame[i];
			frames[i].len = (size_t)n;
		}
		err = radio_send(frames, (size_t)count);
	}
	if (err) {
		LOG_WRN("transmit of %u bytes failed: %d", p->len, err);
	} else {
		LOG_INF("air tx %u bytes", p->len);
	}
}

static void radio_thread(void *a, void *b, void *c)
{
	static struct ret_rnode_rx rx;
	static struct rx_frame f;
	static struct tx_packet tx;
	struct k_poll_event events[2];
	int64_t partial_deadline = 0;
	int64_t tx_at = 0;
	const uint32_t split_timeout = split_timeout_ms();
	bool have_tx = false;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	ret_rnode_rx_reset(&rx);
	k_poll_event_init(&events[0], K_POLL_TYPE_MSGQ_DATA_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			  &rx_q);
	k_poll_event_init(&events[1], K_POLL_TYPE_MSGQ_DATA_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			  &tx_q);

	for (;;) {
		k_timeout_t timeout = K_FOREVER;

		if (rx.partial) {
			timeout = until(partial_deadline);
		} else if (have_tx) {
			timeout = until(tx_at);
		}
		events[0].state = K_POLL_STATE_NOT_READY;
		events[1].state = K_POLL_STATE_NOT_READY;
		(void)k_poll(events, have_tx ? 1 : 2, timeout);

		while (k_msgq_get(&rx_q, &f, K_NO_WAIT) == 0) {
			const uint8_t *pkt;
			int n = ret_rnode_rx_feed(&rx, f.data, f.len, &pkt);

			if (n > 0) {
				LOG_INF("air rx %d bytes", n);
				if (gw_post(GW_FRAME_LORA, pkt, (size_t)n, K_NO_WAIT)) {
					LOG_WRN("transport busy, packet from the air dropped");
				}
			} else if (n < 0) {
				LOG_DBG("air frame dropped: %d", n);
			}
			if (rx.partial) {
				partial_deadline = k_uptime_get() + split_timeout;
			}
			if (have_tx) {
				tx_at = backoff_deadline();
			}
		}
		if (!have_tx && k_msgq_get(&tx_q, &tx, K_NO_WAIT) == 0) {
			have_tx = true;
			tx_at = backoff_deadline();
		}
		if (rx.partial && k_uptime_get() >= partial_deadline) {
			LOG_DBG("second half of a split packet never came");
			ret_rnode_rx_reset(&rx);
		}
		/* Not during a split packet: we would collide with its second half. */
		if (have_tx && !rx.partial && k_uptime_get() >= tx_at) {
			transmit(&tx);
			have_tx = false;
		}
	}
}

int radio_task_start(void)
{
	int err = radio_init(on_radio_frame);

	if (err) {
		return err;
	}
	k_thread_create(&thread, stack, K_THREAD_STACK_SIZEOF(stack), radio_thread, NULL, NULL,
			NULL, K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(&thread, "radio");
	return 0;
}
