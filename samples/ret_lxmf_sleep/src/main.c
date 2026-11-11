/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * A sleepy LXMF node, modelled on lion-client/samples/lion_sleep. Each
 * wake:
 *
 *   resume peripherals and the client (it reconnects and announces)
 *   -> collect mail from the propagation node (ret_lxmf_sync)
 *   -> answer it, and message the contact
 *   -> wait for the delivery proofs
 *   -> suspend the client (socket closed: the modem can enter PSM, rnsd
 *      probes nothing), suspend peripherals, sleep.
 *
 * Mail sent while it sleeps waits at the propagation node.
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_THREAD_ANALYZER)
#include <zephyr/debug/thread_analyzer.h>
#endif

#include <ret/ret_client.h>

#include "network.h"
#include "peripherals.h"

#if defined(CONFIG_ARCH_POSIX)
#include <nsi_main.h>
#endif

LOG_MODULE_REGISTER(ret_lxmf_sleep, LOG_LEVEL_INF);

#define REPLY_PREFIX "re: "
#define WAKE_TIMEOUT K_SECONDS(CONFIG_RET_SLEEP_WAKE_TIMEOUT_S)

static struct ret_client *client;
static K_SEM_DEFINE(connected_sem, 0, 1);
static K_SEM_DEFINE(suspended_sem, 0, 1);
static K_SEM_DEFINE(sync_sem, 0, 1);
static K_SEM_DEFINE(receipt_sem, 0, K_SEM_MAX_LIMIT);
static int sync_status;
static unsigned int sync_received;

/* Replies are sent from the main thread, after the sync. One quoting a
 * message longer than one packet goes DIRECT.
 */
#define REPLY_MAX MIN(1024, RET_LXMF_DIRECT_MAX_CONTENT)
struct reply {
	uint8_t to[RET_DEST_HASH_LEN];
	uint16_t len;
	char text[REPLY_MAX];
};
K_MSGQ_DEFINE(reply_q, sizeof(struct reply), 4, 4);

static void hex(const uint8_t *b, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) {
		sprintf(&out[2 * i], "%02x", b[i]);
	}
}

static void on_state(enum ret_client_state state, void *user)
{
	ARG_UNUSED(user);
	if (state == RET_STATE_CONNECTED) {
		k_sem_give(&connected_sem);
	} else if (state == RET_STATE_SUSPENDED) {
		k_sem_give(&suspended_sem);
	}
}

static void on_lxmf(const struct ret_lxmf_message *m, void *user)
{
	char src[2 * RET_DEST_HASH_LEN + 1];

	ARG_UNUSED(user);
	hex(m->source, RET_DEST_HASH_LEN, src);
	char title[65];
	char content[65];

	/* Copies, zero-terminated: deferred logging copies a %s argument up
	 * to its terminator, whatever the precision, and LXMF fields have none.
	 */
	snprintf(title, sizeof(title), "%.*s", (int)MIN(m->title_len, 64), (const char *)m->title);
	snprintf(content, sizeof(content), "%.*s", (int)MIN(m->content_len, 64),
		 (const char *)m->content);
	LOG_INF("LXMF RECEIVED %s from %s: %s|%s (%u bytes)", m->verified ? "verified" : "UNVERIFIED",
		src, title, content, (unsigned int)m->content_len);

	/* Only verified (a forged source would have us message anyone), and
	 * never a reply (two auto-repliers would talk forever).
	 */
	if (!IS_ENABLED(CONFIG_RET_SLEEP_REPLY) || !m->verified ||
	    (m->content_len >= strlen(REPLY_PREFIX) &&
	     memcmp(m->content, REPLY_PREFIX, strlen(REPLY_PREFIX)) == 0)) {
		return;
	}

	/* static: the client thread's only, and kept off its stack. */
	static struct reply r;
	size_t room = sizeof(r.text) - strlen(REPLY_PREFIX);

	memcpy(r.to, m->source, sizeof(r.to));
	memcpy(r.text, REPLY_PREFIX, strlen(REPLY_PREFIX));
	memcpy(&r.text[strlen(REPLY_PREFIX)], m->content, MIN(m->content_len, room));
	r.len = (uint16_t)(strlen(REPLY_PREFIX) + MIN(m->content_len, room));
	if (k_msgq_put(&reply_q, &r, K_NO_WAIT) != 0) {
		LOG_WRN("reply queue full");
	}
}

static void on_sync(int status, unsigned int received, void *user)
{
	ARG_UNUSED(user);
	sync_status = status;
	sync_received = received;
	k_sem_give(&sync_sem);
}

static void on_receipt(const uint8_t packet_hash[RET_PACKET_HASH_LEN],
		       enum ret_receipt_status status, uint32_t rtt_ms, void *user)
{
	ARG_UNUSED(packet_hash);
	ARG_UNUSED(user);
	if (status == RET_RECEIPT_DELIVERED) {
		LOG_INF("LXMF DELIVERED rtt=%u ms", rtt_ms);
	} else {
		LOG_WRN("LXMF NOT DELIVERED (%d)", status);
	}
	k_sem_give(&receipt_sem);
}

static bool parse_hash(const char *s, uint8_t out[RET_DEST_HASH_LEN])
{
	return hex2bin(s, strlen(s), out, RET_DEST_HASH_LEN) == RET_DEST_HASH_LEN;
}

/* Send what this wake owes (replies, the contact's message) and wait for
 * each delivery proof: suspending earlier would fail them.
 */
static void send_and_confirm(const uint8_t *contact, int wake)
{
	static struct reply r; /* main thread only */
	int pending = 0;
	char msg[32];

	while (k_msgq_get(&reply_q, &r, K_NO_WAIT) == 0) {
		if (ret_lxmf_send(client, r.to, NULL, 0, (const uint8_t *)r.text, r.len, on_receipt,
				  NULL) == 0) {
			char text[65];

			snprintf(text, sizeof(text), "%.*s", (int)MIN(r.len, 64), r.text);
			LOG_INF("REPLY SENT %s (%u bytes)", text, r.len);
			pending++;
		}
	}
	if (contact != NULL) {
		int len = snprintf(msg, sizeof(msg), "wake #%d", wake);

		if (ret_lxmf_send(client, contact, NULL, 0, (const uint8_t *)msg, len, on_receipt,
				  NULL) == 0) {
			LOG_INF("LXMF SENT %s", msg);
			pending++;
		}
	}
	int64_t until = k_uptime_get() + CONFIG_RET_SLEEP_WAKE_TIMEOUT_S * MSEC_PER_SEC;

	while (pending > 0 && k_uptime_get() < until &&
	       k_sem_take(&receipt_sem, K_MSEC(until - k_uptime_get())) == 0) {
		pending--;
	}
}

/* One wake. @return true if it connected and the sync succeeded. */
static bool wake(const uint8_t node[RET_DEST_HASH_LEN], const uint8_t *contact, int n)
{
	bool ok = false;

	LOG_INF("WAKE %d", n);
	if (k_sem_take(&connected_sem, WAKE_TIMEOUT) != 0) {
		LOG_WRN("no connection this wake");
		return false;
	}

	k_sem_reset(&sync_sem);
	if (ret_lxmf_sync(client, node, on_sync, NULL) == 0 &&
	    k_sem_take(&sync_sem, WAKE_TIMEOUT) == 0) {
		LOG_INF("SYNC DONE %d %u", sync_status, sync_received);
		ok = sync_status == 0;
	} else {
		LOG_WRN("sync did not complete");
	}

	send_and_confirm(contact, n);
#if defined(CONFIG_THREAD_ANALYZER)
	thread_analyzer_print(0);
#endif
	return ok;
}

int main(void)
{
	static const struct ret_client_config cfg = {
		.on_state = on_state,
		.on_lxmf = on_lxmf,
		.lxmf_display_name = CONFIG_RET_SLEEP_DISPLAY_NAME,
	};
	uint8_t node[RET_DEST_HASH_LEN];
	uint8_t contact[RET_DEST_HASH_LEN];
	bool has_contact = strlen(CONFIG_RET_SLEEP_CONTACT) > 0;
	uint8_t own[RET_DEST_HASH_LEN];
	char own_hex[2 * RET_DEST_HASH_LEN + 1];
	int good = 0;
	int n;
	int err;

	if (!parse_hash(CONFIG_RET_SLEEP_PROPAGATION_NODE, node)) {
		LOG_ERR("RET_SLEEP_PROPAGATION_NODE must be 32 hex digits");
		return -EINVAL;
	}
	if (has_contact && !parse_hash(CONFIG_RET_SLEEP_CONTACT, contact)) {
		LOG_ERR("RET_SLEEP_CONTACT must be 32 hex digits");
		return -EINVAL;
	}

	client = ret_client_create(&cfg);
	wait_for_network();
	err = ret_client_start(client);
	if (err) {
		LOG_ERR("ret_client_start failed: %d", err);
		return err;
	}
	if (ret_client_dest_hash(client, own) == 0) {
		hex(own, sizeof(own), own_hex);
		LOG_INF("LXMF ADDRESS %s (%s)", own_hex, CONFIG_RET_SLEEP_DISPLAY_NAME);
	}

	for (n = 1; CONFIG_RET_SLEEP_CYCLES == 0 || n <= CONFIG_RET_SLEEP_CYCLES; n++) {
		if (n > 1) {
			peripherals_resume();
			/* No tokens left over from the last wake (a reconnect, a
			 * proof that came after we stopped waiting).
			 */
			k_sem_reset(&connected_sem);
			k_sem_reset(&receipt_sem);
			k_sem_reset(&suspended_sem);
			(void)ret_client_resume(client);
		}
		if (wake(node, has_contact ? contact : NULL, n)) {
			good++;
		}

		/* The client goes first: it writes settings (to the NOR). */
		(void)ret_client_suspend(client);
		if (k_sem_take(&suspended_sem, WAKE_TIMEOUT) != 0) {
			/* It may still be writing settings: keep the NOR up. */
			LOG_ERR("client did not suspend; staying awake");
			continue;
		}
		if (CONFIG_RET_SLEEP_CYCLES != 0 && n == CONFIG_RET_SLEEP_CYCLES) {
			break;
		}
		LOG_INF("SLEEPING %d s", CONFIG_RET_SLEEP_INTERVAL_S);
		peripherals_suspend();
		k_sleep(K_SECONDS(CONFIG_RET_SLEEP_INTERVAL_S));
	}

	LOG_INF("DONE %d/%d wakes synced", good, CONFIG_RET_SLEEP_CYCLES);
#if defined(CONFIG_ARCH_POSIX)
	k_sleep(K_MSEC(100));
	nsi_exit(good == CONFIG_RET_SLEEP_CYCLES ? 0 : 1);
#endif
	return 0;
}
