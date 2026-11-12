/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * The SX1262 through Zephyr's LoRa API (native SX126x driver), set up as an
 * RNode: explicit header, CRC on, no IQ inversion, the private sync word
 * (0x1424), and a long preamble. Configured once: lora_config() fails with
 * -EBUSY while receiving. A send stops reception, sends the frames back to
 * back and starts receiving again; if that restart fails, it is retried
 * every second until it works, so the gateway is never left deaf.
 */

#include <errno.h>
#include <stdbool.h>

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "radio.h"

LOG_MODULE_REGISTER(radio_lora, LOG_LEVEL_INF);

/* RNode sends at least 18 preamble symbols; 24 covers its usual figure. */
#define PREAMBLE_SYMBOLS 24

/*
 * The native driver gives every transmission 10 s on the chip
 * (sx126x_set_tx(dev, 10000)): a longer frame is cut off on the air. The
 * worst case is a full 255-byte frame, by the SX126x datasheet formula
 * (low data rate optimisation assumed, 4.25 preamble symbols rounded up).
 * At SF12 / 125 kHz / CR 4/8 it is about 14.6 s.
 */
#define FRAME_MAX_BYTES   255
#define FRAME_PAYLOAD_SYM                                                                          \
	(DIV_ROUND_UP(8 * FRAME_MAX_BYTES + 44 - 4 * CONFIG_RET_LORA_SF,                           \
		      4 * (CONFIG_RET_LORA_SF - 2)) *                                              \
	 CONFIG_RET_LORA_CR)
#define FRAME_AIRTIME_MS                                                                           \
	(((uint64_t)(PREAMBLE_SYMBOLS + 5 + 8 + FRAME_PAYLOAD_SYM) * BIT(CONFIG_RET_LORA_SF) *     \
	  MSEC_PER_SEC) /                                                                          \
	 CONFIG_RET_LORA_BW_HZ)
#define DRIVER_TX_TIMEOUT_MS 10000
BUILD_ASSERT(FRAME_AIRTIME_MS < DRIVER_TX_TIMEOUT_MS,
	     "a full LoRa frame takes longer than the driver allows a transmission (10 s): "
	     "raise the bandwidth or lower the spreading factor or coding rate");

#define RX_RETRY_MS      1000
/* While a send holds the radio: try again shortly after. */
#define RX_BUSY_RETRY_MS 100

static const struct device *const lora = DEVICE_DT_GET(DT_NODELABEL(lora0));
static radio_rx_cb rx_cb;

/* Held by radio_send(); the retry work only ever tries it. */
static K_MUTEX_DEFINE(radio_lock);
/* Under radio_lock: the last attempt to receive failed. */
static bool rx_down;
static void rx_retry(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(rx_retry_work, rx_retry);

/* On the driver's work queue: radio_task.c's callback copies and returns. */
static void on_rx(const struct device *dev, uint8_t *data, uint16_t size, int16_t rssi,
		  int8_t snr, void *user)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(rssi);
	ARG_UNUSED(snr);
	ARG_UNUSED(user);
	if (size > 0) {
		rx_cb(data, size);
	}
}

static int receive(void)
{
	return lora_recv_async(lora, on_rx, NULL);
}

/*
 * Receive again, retrying from the system work queue until it works.
 * Logged when reception stops and when it comes back, not every retry.
 */
static int receive_or_retry(void)
{
	int err = receive();

	if (err && !rx_down) {
		LOG_ERR("receive: %d, retrying every %d ms", err, RX_RETRY_MS);
	} else if (!err && rx_down) {
		LOG_INF("receiving again");
	}
	rx_down = err != 0;
	if (rx_down) {
		k_work_reschedule(&rx_retry_work, K_MSEC(RX_RETRY_MS));
	}
	return err;
}

/*
 * On the system work queue, which also runs the driver's IRQ work (TX
 * done): never wait for radio_send() here, it may be waiting for that.
 */
static void rx_retry(struct k_work *work)
{
	ARG_UNUSED(work);
	if (k_mutex_lock(&radio_lock, K_NO_WAIT) != 0) {
		k_work_reschedule(&rx_retry_work, K_MSEC(RX_BUSY_RETRY_MS));
		return;
	}
	/* A send since may have restarted reception already. */
	if (rx_down) {
		(void)receive_or_retry();
	}
	k_mutex_unlock(&radio_lock);
}

int radio_init(radio_rx_cb cb)
{
	struct lora_modem_config cfg = {
		.frequency = CONFIG_RET_LORA_FREQ_HZ,
		.bandwidth = (enum lora_signal_bandwidth)(CONFIG_RET_LORA_BW_HZ / 1000),
		.datarate = (enum lora_datarate)CONFIG_RET_LORA_SF,
		.coding_rate = (enum lora_coding_rate)(CONFIG_RET_LORA_CR - 4),
		.preamble_len = PREAMBLE_SYMBOLS,
		.tx_power = CONFIG_RET_LORA_TX_POWER_DBM,
		.tx = false,
		.iq_inverted = false,
		.public_network = false,
	};
	int err;

	if (!device_is_ready(lora)) {
		LOG_ERR("SX1262 not ready");
		return -ENODEV;
	}
	rx_cb = cb;
	err = lora_config(lora, &cfg);
	if (err) {
		LOG_ERR("config: %d", err);
		return err;
	}
	/* No retry at boot: a radio that can't receive from the start fails
	 * the gateway's start, loudly.
	 */
	err = receive();
	if (err) {
		LOG_ERR("receive: %d", err);
	}
	return err;
}

int radio_send(const struct radio_frame *frames, size_t count)
{
	int err;
	int rx_err;

	k_mutex_lock(&radio_lock, K_FOREVER);
	/* Not needed with the lock held, but no point in it firing. */
	k_work_cancel_delayable(&rx_retry_work);
	err = lora_recv_async(lora, NULL, NULL);
	for (size_t i = 0; !err && i < count; i++) {
		err = lora_send(lora, (uint8_t *)frames[i].data, (uint32_t)frames[i].len);
	}
	if (err) {
		LOG_WRN("send: %d", err);
	}
	/* Always back to receiving, even after a failed send. */
	rx_err = receive_or_retry();
	k_mutex_unlock(&radio_lock);
	return err ? err : rx_err;
}
