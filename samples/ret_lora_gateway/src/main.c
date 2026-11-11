/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * LoRa gateway: a Reticulum transport node with two interfaces, the LoRa
 * radio (RNode framing, gateway mode) and a TCP uplink to a stock rnsd.
 * It routes LoRa to LoRa itself and LoRa to the hub's network, so the hub
 * needs no special configuration. This thread owns all routing state
 * (src/ret_transport.c); the radio and uplink threads post frames to it.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include "gateway.h"
#include "network.h"
#include "ret_crypto.h"
#include "ret_identity.h"
#include "ret_ifac.h"
#include "ret_rnode_air.h"
#include "ret_transport.h"

LOG_MODULE_REGISTER(gateway, LOG_LEVEL_INF);

#define LORA_QUEUE_DEPTH   4
#define UPLINK_QUEUE_DEPTH 6
/* A hub that keeps sending could otherwise starve the timers. */
#define MAX_EVENTS_PER_JOB 8

struct gw_msg {
	uint8_t type;
	uint16_t len;
	uint8_t data[RET_TRANSPORT_FRAME_MAX];
};

/* LoRa frames, and the uplink's frames and events, queued apart: the radio
 * thread can't wait (it would miss frames), the uplink thread can.
 */
K_MSGQ_DEFINE(lora_q, sizeof(struct gw_msg), LORA_QUEUE_DEPTH, 4);
K_MSGQ_DEFINE(uplink_q, sizeof(struct gw_msg), UPLINK_QUEUE_DEPTH, 4);

static struct ret_transport tp;
static struct ret_local_identity identity;
static struct ret_ifac lora_ifac;
static struct ret_ifac uplink_ifac;

/* Settings: gw/id (the transport identity's private key), gw/boot. */
static uint8_t stored_prv[RET_PRVKEY_LEN];
static bool have_id;
static uint32_t boot;
static int settings_err;

static int gw_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
	if (strcmp(name, "id") == 0) {
		if (len != sizeof(stored_prv) ||
		    read_cb(cb_arg, stored_prv, sizeof(stored_prv)) != (ssize_t)len) {
			settings_err = -EBADMSG;
			return 0;
		}
		have_id = true;
	} else if (strcmp(name, "boot") == 0) {
		if (len != sizeof(boot) || read_cb(cb_arg, &boot, sizeof(boot)) != (ssize_t)len) {
			settings_err = -EBADMSG;
		}
	}
	/* Noted rather than returned: an error would stop the load there. */
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(gw, "gw", NULL, gw_set, NULL, NULL);

/* The transport identity is the node's transport ID: keep it across boots. */
static int load_identity(void)
{
	int err = settings_subsys_init();

	if (!err) {
		err = settings_load_subtree("gw");
	}
	if (!err) {
		err = settings_err;
	}
	if (err) {
		/* Never replace an unreadable identity: paths others hold through us use it. */
		LOG_ERR("settings unreadable: %d", err);
		return err;
	}
	if (!have_id && boot > 0) {
		/* Booted before but the identity is gone: the settings file was damaged. */
		LOG_ERR("identity missing after %u boots", boot);
		return -ENOENT;
	}
	if (have_id) {
		err = ret_local_identity_load(&identity, stored_prv);
	} else {
		err = ret_local_identity_generate(&identity, stored_prv);
		if (!err) {
			err = settings_save_one("gw/id", stored_prv, sizeof(stored_prv));
		}
	}
	ret_wipe(stored_prv, sizeof(stored_prv));
	if (err) {
		return err;
	}
	boot++;
	return settings_save_one("gw/boot", &boot, sizeof(boot));
}

static int lora_send(struct ret_transport_iface *iface, const uint8_t *frame, size_t len)
{
	ARG_UNUSED(iface);
	return radio_task_send(frame, len);
}

static int uplink_tx(struct ret_transport_iface *iface, const uint8_t *frame, size_t len)
{
	ARG_UNUSED(iface);
	return uplink_send(frame, len);
}

static struct ret_transport_iface lora = {
	.name = "LoRa",
	/* Path requests from LoRa nodes for unknown destinations go upstream. */
	.mode = RET_IFACE_MODE_GATEWAY,
	.hw_mtu = RET_RNODE_MTU,
	/* As an RNode: no link MTU signalling onto the radio. */
	.mtu_signalling = false,
	.announce_cap = CONFIG_RET_LORA_ANNOUNCE_CAP * 100,
	.send = lora_send,
};

static struct ret_transport_iface uplink = {
	.name = "uplink",
	.mode = RET_IFACE_MODE_FULL,
	/* TCPClientInterface's figure. */
	.bitrate = 10 * 1000 * 1000,
	/* Nothing larger can go anywhere from here, and links through us
	 * then signal what LoRa can carry.
	 */
	.hw_mtu = RET_RNODE_MTU,
	.mtu_signalling = true,
	.announce_cap = CONFIG_RET_GATEWAY_ANNOUNCE_CAP * 100,
	.send = uplink_tx,
};

static struct ret_transport_iface *const ifaces[] = { &lora, &uplink };

static int setup_ifac(struct ret_ifac *f, const char *name, const char *pass, uint8_t size,
		      const struct ret_ifac **out)
{
	int err;

	if (name[0] == '\0' && pass[0] == '\0') {
		*out = NULL;
		return 0;
	}
	err = ret_ifac_init(f, name, pass, size);
	*out = err ? NULL : f;
	return err;
}

int gw_post(enum gw_event type, const uint8_t *data, size_t len, k_timeout_t timeout)
{
	struct gw_msg m = { .type = (uint8_t)type, .len = (uint16_t)len };

	if (len > sizeof(m.data)) {
		return -EMSGSIZE;
	}
	if (len) {
		memcpy(m.data, data, len);
	}
	return k_msgq_put(type == GW_FRAME_LORA ? &lora_q : &uplink_q, &m, timeout);
}

static void handle(const struct gw_msg *m)
{
	int64_t now = k_uptime_get();
	uint8_t hash[RET_HASH_LEN];

	switch (m->type) {
	case GW_FRAME_LORA:
		ret_transport_inbound(&tp, &lora, m->data, m->len, now);
		break;
	case GW_FRAME_UPLINK:
		ret_transport_inbound(&tp, &uplink, m->data, m->len, now);
		break;
	case GW_UPLINK_UP:
		ret_transport_iface_online(&tp, &uplink, true, now);
		uplink_iface_hash(hash);
		if (ret_transport_synthesize_tunnel(&tp, &uplink, hash, now)) {
			LOG_WRN("tunnel synthesis not sent");
		}
		break;
	case GW_UPLINK_DOWN:
		ret_transport_iface_online(&tp, &uplink, false, now);
		break;
	default:
		break;
	}
}

static void log_identity(void)
{
	char hex[2 * RET_TRUNC_HASH_LEN + 1];

	for (int i = 0; i < RET_TRUNC_HASH_LEN; i++) {
		snprintf(&hex[2 * i], 3, "%02x", identity.hash[i]);
	}
	LOG_INF("transport node <%s>, boot %u", hex, boot);
}

int main(void)
{
	static struct gw_msg m;
	struct k_poll_event ev[2];
	struct ret_transport_store *store;
	int64_t next;
	int err;

	err = ret_crypto_init();
	if (!err) {
		err = load_identity();
	}
	if (!err) {
		err = store_init(&store);
	}
	if (!err) {
		err = setup_ifac(&lora_ifac, CONFIG_RET_LORA_IFAC_NETWORK_NAME,
				 CONFIG_RET_LORA_IFAC_PASSPHRASE, CONFIG_RET_LORA_IFAC_SIZE,
				 &lora.ifac);
	}
	if (!err) {
		err = setup_ifac(&uplink_ifac, CONFIG_RET_GATEWAY_IFAC_NETWORK_NAME,
				 CONFIG_RET_GATEWAY_IFAC_PASSPHRASE, CONFIG_RET_GATEWAY_IFAC_SIZE,
				 &uplink.ifac);
	}
	if (err) {
		LOG_ERR("start failed: %d", err);
		return 0;
	}
	log_identity();

	lora.bitrate = radio_task_bitrate();
	err = ret_transport_init(&tp, &identity, store, ifaces, ARRAY_SIZE(ifaces), boot,
				 k_uptime_get());
	if (!err) {
		err = radio_task_start();
	}
	if (err) {
		LOG_ERR("start failed: %d", err);
		return 0;
	}
	ret_transport_iface_online(&tp, &lora, true, k_uptime_get());
	LOG_INF("LoRa %d Hz, BW %d Hz, SF%d, CR 4/%d, %d dBm, %u bps", CONFIG_RET_LORA_FREQ_HZ,
		CONFIG_RET_LORA_BW_HZ, CONFIG_RET_LORA_SF, CONFIG_RET_LORA_CR,
		CONFIG_RET_LORA_TX_POWER_DBM, lora.bitrate);

	wait_for_network();
	uplink_start();

	k_poll_event_init(&ev[0], K_POLL_TYPE_MSGQ_DATA_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			  &lora_q);
	k_poll_event_init(&ev[1], K_POLL_TYPE_MSGQ_DATA_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
			  &uplink_q);
	next = k_uptime_get();
	for (;;) {
		int64_t now = k_uptime_get();

		if (now >= next) {
			next = ret_transport_jobs(&tp, now);
		}
		ev[0].state = K_POLL_STATE_NOT_READY;
		ev[1].state = K_POLL_STATE_NOT_READY;
		(void)k_poll(ev, ARRAY_SIZE(ev), K_MSEC(MAX(next - now, 0)));
		/* LoRa first: frames on the air don't wait. */
		for (int handled = 0; handled < MAX_EVENTS_PER_JOB; handled++) {
			if (k_msgq_get(&lora_q, &m, K_NO_WAIT) != 0 &&
			    k_msgq_get(&uplink_q, &m, K_NO_WAIT) != 0) {
				break;
			}
			handle(&m);
		}
	}
	return 0;
}
