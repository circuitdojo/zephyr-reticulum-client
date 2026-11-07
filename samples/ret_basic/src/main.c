/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Waits for an announce from CONFIG_RET_SAMPLE_DEST_NAME, then sends it
 * an encrypted message every CONFIG_RET_SAMPLE_SEND_INTERVAL_S seconds
 * and reports each delivery proof.
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <mpack.h>
#include <ret/ret_client.h>

#include "network.h"

#if defined(CONFIG_ARCH_POSIX)
#include <nsi_main.h>
#endif

LOG_MODULE_REGISTER(ret_basic, LOG_LEVEL_INF);

static uint8_t target_name_hash[10];
static uint8_t target_dest[RET_DEST_HASH_LEN];
static atomic_t target_known;
static K_SEM_DEFINE(target_sem, 0, 1);

static atomic_t delivered;
static atomic_t replies;
static K_SEM_DEFINE(reply_sem, 0, K_SEM_MAX_LIMIT);
static atomic_t resolved;
static K_SEM_DEFINE(resolved_sem, 0, K_SEM_MAX_LIMIT);

static void hex(const uint8_t *b, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) {
		sprintf(&out[2 * i], "%02x", b[i]);
	}
}

static void on_announce(const struct ret_announce_info *info, void *user)
{
	char h[2 * RET_DEST_HASH_LEN + 1];

	ARG_UNUSED(user);
	hex(info->dest_hash, RET_DEST_HASH_LEN, h);

	if (memcmp(info->name_hash, target_name_hash, sizeof(target_name_hash)) != 0) {
		LOG_INF("announce valid (other destination) %s hops %u", h, info->hops);
		return;
	}

	LOG_INF("ANNOUNCE VALID %s %s hops %u%s", CONFIG_RET_SAMPLE_DEST_NAME, h, info->hops,
		info->has_ratchet ? " ratchet" : "");

	if (!atomic_get(&target_known)) {
		memcpy(target_dest, info->dest_hash, RET_DEST_HASH_LEN);
		atomic_set(&target_known, 1);
		k_sem_give(&target_sem);
	}
}

static void on_data(const uint8_t *data, size_t len, void *user)
{
	static const char prefix[] = "echo: ";

	ARG_UNUSED(user);
	LOG_INF("RECEIVED %.*s", (int)len, (const char *)data);
	if (len >= sizeof(prefix) - 1 && memcmp(data, prefix, sizeof(prefix) - 1) == 0) {
		atomic_inc(&replies);
		k_sem_give(&reply_sem);
	}
}

static void on_receipt(const uint8_t packet_hash[RET_PACKET_HASH_LEN],
		       enum ret_receipt_status status, uint32_t rtt_ms, void *user)
{
	char h[2 * 8 + 1];
	int n = (int)(intptr_t)user;

	hex(packet_hash, 8, h);

	switch (status) {
	case RET_RECEIPT_DELIVERED:
		atomic_inc(&delivered);
		LOG_INF("PROOF VALID #%d rtt=%u ms packet %s..", n, rtt_ms, h);
		break;
	case RET_RECEIPT_TIMEOUT:
		LOG_WRN("PROOF TIMEOUT #%d packet %s..", n, h);
		break;
	case RET_RECEIPT_DISCONNECTED:
		LOG_WRN("DISCONNECTED before proof #%d", n);
		break;
	default:
		LOG_ERR("SEND FAILED #%d", n);
		break;
	}
	atomic_inc(&resolved);
	k_sem_give(&resolved_sem);
}

#if defined(CONFIG_RET_SAMPLE_LINK_TEST)
static K_SEM_DEFINE(link_sem, 0, 1);
static atomic_t link_event = ATOMIC_INIT(-1);
static K_SEM_DEFINE(response_sem, 0, 1);
static char response_text[96];
static int response_status;
static bool link_ok;

static void on_link(enum ret_link_event ev, int reason, void *user)
{
	ARG_UNUSED(user);
	LOG_INF("LINK EVENT %d (%d)", ev, reason);
	atomic_set(&link_event, ev);
	k_sem_give(&link_sem);
}

static void on_response(int status, const uint8_t *resp, size_t len, void *user)
{
	mpack_reader_t r;

	ARG_UNUSED(user);
	response_status = status;
	response_text[0] = '\0';
	if (status == 0) {
		mpack_reader_init_data(&r, (const char *)resp, len);
		uint32_t n = mpack_expect_bin_max(&r, sizeof(response_text) - 1);

		mpack_read_bytes(&r, response_text, n);
		mpack_done_bin(&r);
		response_status = mpack_reader_destroy(&r) == mpack_ok ? 0 : -EBADMSG;
		response_text[response_status == 0 ? n : 0] = '\0';
	}
	k_sem_give(&response_sem);
}

static bool wait_link_event(enum ret_link_event want)
{
	if (k_sem_take(&link_sem, K_SECONDS(30)) != 0) {
		return false;
	}
	return atomic_get(&link_event) == want;
}

/* Open, identify, request "/echo", close: logs LINK ACTIVE, LINK RESPONSE
 * <text> and LINK CLOSED for the e2e script.
 */
static void link_test(struct ret_client *client)
{
	static const uint8_t ping[] = { 0xc4, 0x04, 'p', 'i', 'n', 'g' };

	if (ret_client_link_open(client, target_dest, on_link, NULL) != 0 ||
	    !wait_link_event(RET_LINK_EVT_ACTIVE)) {
		LOG_ERR("LINK FAILED to open");
		return;
	}
	LOG_INF("LINK ACTIVE");
	(void)ret_client_link_identify(client);
	if (ret_client_link_request(client, "/echo", ping, sizeof(ping), on_response, NULL) != 0 ||
	    k_sem_take(&response_sem, K_SECONDS(30)) != 0 || response_status != 0) {
		LOG_ERR("LINK FAILED request (%d)", response_status);
		return;
	}
	LOG_INF("LINK RESPONSE %s", response_text);

	/* Idle past the responder's stale time (2 x the 5 s minimum
	 * keepalive): only the client's keepalives keep the link up.
	 */
	k_sleep(K_SECONDS(15));
	if (ret_client_link_request(client, "/echo", ping, sizeof(ping), on_response, NULL) != 0 ||
	    k_sem_take(&response_sem, K_SECONDS(30)) != 0 || response_status != 0) {
		LOG_ERR("LINK FAILED after idle (%d)", response_status);
		return;
	}
	LOG_INF("LINK RESPONSE AFTER IDLE %s", response_text);

	if (ret_client_link_close(client) != 0 || !wait_link_event(RET_LINK_EVT_CLOSED)) {
		LOG_ERR("LINK FAILED to close");
		return;
	}
	LOG_INF("LINK CLOSED");
	link_ok = strncmp(response_text, "pong:ping:", 10) == 0;
}
#endif

static void finish(int sent)
{
	int ok = (int)atomic_get(&delivered);
	bool success = ok == sent;

#if defined(CONFIG_RET_SAMPLE_LINK_TEST)
	success = success && link_ok;
#endif

#if defined(CONFIG_RET_SAMPLE_EXPECT_REPLIES)
	int64_t until = k_uptime_get() + CONFIG_RET_SAMPLE_REPLY_WAIT_S * MSEC_PER_SEC;

	while (atomic_get(&replies) < sent && k_uptime_get() < until) {
		k_sem_take(&reply_sem, K_MSEC(until - k_uptime_get()));
	}
	success = success && atomic_get(&replies) == sent;
	LOG_INF("DONE %d/%d delivered, %d/%d replies", ok, sent, (int)atomic_get(&replies), sent);
#else
	LOG_INF("DONE %d/%d delivered", ok, sent);
#endif
#if defined(CONFIG_ARCH_POSIX)
	k_sleep(K_MSEC(100)); /* let the log thread flush */
	nsi_exit(success ? 0 : 1);
#else
	ARG_UNUSED(success);
#endif
}

int main(void)
{
	static struct ret_client_config cfg = {
		.on_announce = on_announce,
		.on_data = on_data,
	};
	struct ret_client *client;
	char msg[32];
	int err;

	if (strlen(CONFIG_RET_SAMPLE_LOCAL_NAME) > 0) {
		cfg.dest_name = CONFIG_RET_SAMPLE_LOCAL_NAME;
	}
	client = ret_client_create(&cfg);

	wait_for_network();

	/* Before start: an announce may arrive as soon as the thread runs. */
	err = ret_client_name_hash(CONFIG_RET_SAMPLE_DEST_NAME, target_name_hash);
	if (err) {
		LOG_ERR("name hash failed: %d", err);
		return err;
	}

	err = ret_client_start(client);
	if (err) {
		LOG_ERR("ret_client_start failed: %d", err);
		return err;
	}

	uint8_t own[RET_DEST_HASH_LEN];
	char own_hex[2 * RET_DEST_HASH_LEN + 1];

	if (ret_client_dest_hash(client, own) == 0) {
		hex(own, sizeof(own), own_hex);
		LOG_INF("OWN ADDRESS %s %s", CONFIG_RET_SAMPLE_LOCAL_NAME, own_hex);
	}

	if (strlen(CONFIG_RET_SAMPLE_DEST_HASH) > 0) {
		if (hex2bin(CONFIG_RET_SAMPLE_DEST_HASH, strlen(CONFIG_RET_SAMPLE_DEST_HASH),
			    target_dest, sizeof(target_dest)) != sizeof(target_dest)) {
			LOG_ERR("RET_SAMPLE_DEST_HASH must be 32 hex digits");
			return -EINVAL;
		}
		atomic_set(&target_known, 1);
		LOG_INF("sending to %s (path requested on demand)", CONFIG_RET_SAMPLE_DEST_HASH);
	} else {
		LOG_INF("waiting for announce from %s", CONFIG_RET_SAMPLE_DEST_NAME);
		k_sem_take(&target_sem, K_FOREVER);
	}

#if defined(CONFIG_RET_SAMPLE_LINK_TEST)
	link_test(client);
#endif

	for (int n = 1; CONFIG_RET_SAMPLE_MESSAGE_COUNT == 0 || n <= CONFIG_RET_SAMPLE_MESSAGE_COUNT;
	     n++) {
		int len = snprintf(msg, sizeof(msg), "hello #%d", n);

		err = ret_client_send(client, target_dest, (const uint8_t *)msg, len, on_receipt,
				      (void *)(intptr_t)n);
		if (err) {
			LOG_ERR("send #%d not queued: %d", n, err);
			atomic_inc(&resolved);
		} else {
			LOG_INF("SENT %s", msg);
		}
		k_sleep(K_SECONDS(CONFIG_RET_SAMPLE_SEND_INTERVAL_S));
	}

	/* Wait for the remaining receipts to resolve (proof or timeout). */
	while (atomic_get(&resolved) < CONFIG_RET_SAMPLE_MESSAGE_COUNT) {
		k_sem_take(&resolved_sem, K_FOREVER);
	}
	finish(CONFIG_RET_SAMPLE_MESSAGE_COUNT);
	return 0;
}
