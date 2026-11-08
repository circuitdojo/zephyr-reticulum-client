/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * An always-connected LXMF node: announces its lxmf.delivery address,
 * logs every message it receives (answering each when
 * CONFIG_RET_LXMF_SAMPLE_REPLY is set), and messages
 * CONFIG_RET_LXMF_SAMPLE_CONTACT periodically. ret_lxmf_send() picks the
 * method: opportunistic (one encrypted packet) when a message fits, DIRECT
 * (over a link to the recipient) when it does not, as a reply quoting a
 * long message does.
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <ret/ret_client.h>

#include "network.h"

#if defined(CONFIG_ARCH_POSIX)
#include <nsi_main.h>
#endif

LOG_MODULE_REGISTER(ret_lxmf, LOG_LEVEL_INF);

#define ECHO_PREFIX  "echo: hello #"
#define REPLY_PREFIX "re: "
/* A reply quotes up to this much: longer than one packet, so it goes
 * DIRECT.
 */
#define REPLY_MAX MIN(1024, RET_LXMF_DIRECT_MAX_CONTENT)

static struct ret_client *client;
static K_SEM_DEFINE(connected_sem, 0, 1);

static uint8_t node[RET_DEST_HASH_LEN];
static bool has_node;
static K_SEM_DEFINE(sync_sem, 0, 1);
static int sync_status;
static void sync_work_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(sync_work, sync_work_fn);

static atomic_t delivered;
static atomic_t resolved;
static K_SEM_DEFINE(resolved_sem, 0, K_SEM_MAX_LIMIT);
static atomic_t echoes;
static K_SEM_DEFINE(echo_sem, 0, K_SEM_MAX_LIMIT);

/* Replies are sent from the main thread: on_lxmf runs on the client
 * thread, and packing and signing want their own stack.
 */
struct reply {
	uint8_t to[RET_DEST_HASH_LEN];
	uint16_t len;
	char text[REPLY_MAX];
};
K_MSGQ_DEFINE(reply_q, sizeof(struct reply), 2, 4);

static void hex(const uint8_t *b, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) {
		sprintf(&out[2 * i], "%02x", b[i]);
	}
}

static void on_sync(int status, unsigned int received, void *user)
{
	ARG_UNUSED(user);
	LOG_INF("SYNC DONE %d %u", status, received);
	sync_status = status;
	k_sem_give(&sync_sem);
	if (CONFIG_RET_LXMF_SAMPLE_SYNC_INTERVAL_S > 0) {
		k_work_reschedule(&sync_work, K_SECONDS(CONFIG_RET_LXMF_SAMPLE_SYNC_INTERVAL_S));
	}
}

static void sync_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	int err = ret_lxmf_sync(client, node, on_sync, NULL);

	if (err == -EAGAIN) {
		k_work_reschedule(&sync_work, K_SECONDS(1)); /* queue full: try again */
	} else if (err) {
		LOG_WRN("sync not started: %d", err);
	}
}

static void on_state(enum ret_client_state state, void *user)
{
	ARG_UNUSED(user);
	if (state == RET_STATE_CONNECTED) {
		LOG_INF("-> CONNECTED");
		k_sem_give(&connected_sem);
		/* Collect what arrived at the node while we were away. */
		if (has_node) {
			k_work_reschedule(&sync_work, K_NO_WAIT);
		}
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

	if (m->verified && m->content_len >= strlen(ECHO_PREFIX) &&
	    memcmp(m->content, ECHO_PREFIX, strlen(ECHO_PREFIX)) == 0) {
		atomic_inc(&echoes);
		k_sem_give(&echo_sem);
	}

	/* Answer verified messages only (a forged source would have us
	 * message any address), and never a reply: two auto-repliers would
	 * otherwise talk forever.
	 */
	if (IS_ENABLED(CONFIG_RET_LXMF_SAMPLE_REPLY) && m->verified &&
	    !(m->content_len >= strlen(REPLY_PREFIX) &&
	      memcmp(m->content, REPLY_PREFIX, strlen(REPLY_PREFIX)) == 0)) {
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
}

static void on_receipt(const uint8_t packet_hash[RET_PACKET_HASH_LEN],
		       enum ret_receipt_status status, uint32_t rtt_ms, void *user)
{
	int n = (int)(intptr_t)user;

	ARG_UNUSED(packet_hash);
	switch (status) {
	case RET_RECEIPT_DELIVERED:
		LOG_INF("LXMF DELIVERED #%d rtt=%u ms", n, rtt_ms);
		if (n > 0) {
			atomic_inc(&delivered);
		}
		break;
	case RET_RECEIPT_TIMEOUT:
		LOG_WRN("LXMF NOT PROVED #%d", n);
		break;
	case RET_RECEIPT_REJECTED:
		LOG_WRN("LXMF REJECTED #%d", n);
		break;
	default:
		LOG_WRN("LXMF FAILED #%d (%d)", n, status);
		break;
	}
	if (n > 0) {
		atomic_inc(&resolved);
		k_sem_give(&resolved_sem);
	}
}

/* Send queued replies (receipt user 0), waiting up to @p timeout for one. */
static void send_replies(k_timeout_t timeout)
{
	static struct reply r; /* main thread only */

	while (k_msgq_get(&reply_q, &r, timeout) == 0) {
		int err = ret_lxmf_send(client, r.to, NULL, 0, (const uint8_t *)r.text, r.len,
					on_receipt, (void *)(intptr_t)0);

		if (err) {
			LOG_ERR("reply not sent: %d", err);
		} else {
			char text[65];

			snprintf(text, sizeof(text), "%.*s", (int)MIN(r.len, 64), r.text);
			LOG_INF("REPLY SENT %s (%u bytes)", text, r.len);
		}
		timeout = K_NO_WAIT;
	}
}

static void finish(int sent)
{
	int ok = (int)atomic_get(&delivered);
	int64_t until = k_uptime_get() + CONFIG_RET_LXMF_SAMPLE_REPLY_WAIT_S * MSEC_PER_SEC;

	while (atomic_get(&echoes) < sent && k_uptime_get() < until) {
		send_replies(K_NO_WAIT);
		k_sem_take(&echo_sem, K_MSEC(MIN(until - k_uptime_get(), 200)));
	}
	/* Answer the last echoes too, and give their proofs a moment. */
	send_replies(K_NO_WAIT);
	k_sleep(K_SECONDS(3));

	bool success = ok == sent && atomic_get(&echoes) == sent;

	LOG_INF("DONE %d/%d delivered, %d/%d echoes", ok, sent, (int)atomic_get(&echoes), sent);
#if defined(CONFIG_ARCH_POSIX)
	k_sleep(K_MSEC(100)); /* let the log thread flush */
	nsi_exit(success ? 0 : 1);
#else
	ARG_UNUSED(success);
#endif
}

int main(void)
{
	static const struct ret_client_config cfg = {
		.on_state = on_state,
		.on_lxmf = on_lxmf,
		.lxmf_display_name = CONFIG_RET_LXMF_SAMPLE_DISPLAY_NAME,
	};
	uint8_t contact[RET_DEST_HASH_LEN];
	bool has_contact = strlen(CONFIG_RET_LXMF_SAMPLE_CONTACT) > 0;
	uint8_t own[RET_DEST_HASH_LEN];
	char own_hex[2 * RET_DEST_HASH_LEN + 1];
	char msg[32];
	int err;

	if (has_contact &&
	    hex2bin(CONFIG_RET_LXMF_SAMPLE_CONTACT, strlen(CONFIG_RET_LXMF_SAMPLE_CONTACT), contact,
		    sizeof(contact)) != sizeof(contact)) {
		LOG_ERR("RET_LXMF_SAMPLE_CONTACT must be 32 hex digits");
		return -EINVAL;
	}

	has_node = strlen(CONFIG_RET_LXMF_SAMPLE_PROPAGATION_NODE) > 0;
	if (has_node && hex2bin(CONFIG_RET_LXMF_SAMPLE_PROPAGATION_NODE,
				strlen(CONFIG_RET_LXMF_SAMPLE_PROPAGATION_NODE), node,
				sizeof(node)) != sizeof(node)) {
		LOG_ERR("RET_LXMF_SAMPLE_PROPAGATION_NODE must be 32 hex digits");
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
		LOG_INF("LXMF ADDRESS %s (%s)", own_hex, CONFIG_RET_LXMF_SAMPLE_DISPLAY_NAME);
	}
	k_sem_take(&connected_sem, K_FOREVER);

#if defined(CONFIG_RET_LXMF_SAMPLE_SYNC_AND_EXIT)
	k_sem_take(&sync_sem, K_FOREVER);
	/* Path responses for unverified senders, whose keys are then kept. */
	k_sleep(K_SECONDS(1));
#if defined(CONFIG_ARCH_POSIX)
	nsi_exit(sync_status == 0 ? 0 : 1);
#endif
	return 0;
#endif

	if (!has_contact) {
		for (;;) {
			send_replies(K_FOREVER);
		}
	}

	for (int n = 1; CONFIG_RET_LXMF_SAMPLE_MESSAGE_COUNT == 0 ||
			n <= CONFIG_RET_LXMF_SAMPLE_MESSAGE_COUNT;
	     n++) {
		int len = snprintf(msg, sizeof(msg), "hello #%d", n);
		int64_t next = k_uptime_get() + CONFIG_RET_LXMF_SAMPLE_SEND_INTERVAL_S * MSEC_PER_SEC;

		err = ret_lxmf_send(client, contact, NULL, 0, (const uint8_t *)msg, len, on_receipt,
				    (void *)(intptr_t)n);
		if (err) {
			LOG_ERR("message #%d not sent: %d", n, err);
			atomic_inc(&resolved);
		} else {
			LOG_INF("LXMF SENT %s", msg);
		}
		while (k_uptime_get() < next) {
			send_replies(K_MSEC(next - k_uptime_get()));
		}
	}

	while (atomic_get(&resolved) < CONFIG_RET_LXMF_SAMPLE_MESSAGE_COUNT) {
		send_replies(K_NO_WAIT);
		k_sem_take(&resolved_sem, K_MSEC(200));
	}
	finish(CONFIG_RET_LXMF_SAMPLE_MESSAGE_COUNT);
	return 0;
}
