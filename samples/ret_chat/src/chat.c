/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/util.h>

#include "chat.h"
#include "network.h"

LOG_MODULE_REGISTER(chat, LOG_LEVEL_INF);

/* Guards everything below: the client thread (announces, messages,
 * receipts) and the front end (shell) both use it.
 */
static K_MUTEX_DEFINE(lock);

static struct ret_client *client;
static atomic_t state = ATOMIC_INIT(RET_STATE_DISCONNECTED);
static uint8_t lxmf_name_hash[10];
static uint8_t node[RET_DEST_HASH_LEN];
static bool has_node;
/* Contacts loaded: until then the shell (up before main) must not read or
 * write them, or 'contact add' could take a stored contact's slot.
 */
static atomic_t ready;

/* --- Contacts (settings chat/ct/<n>: name[16] | address[16]) ------------- */

#define CONTACT_RECORD_LEN (CHAT_NAME_MAX + RET_DEST_HASH_LEN)

static struct {
	bool used;
	struct chat_contact c;
} contacts[CONFIG_CHAT_CONTACTS];

/* --- Heard lxmf.delivery announces, in the order first heard ------------- */

static struct chat_heard heard[CONFIG_CHAT_HEARD];
static size_t n_heard;

/* --- Inbox: message headers in a ring, their bytes in a byte ring -------- */

#define TITLE_KEEP 64

static struct {
	struct chat_message m;
	uint32_t off; /* title then content, contiguous in inbox_buf */
} inbox[CONFIG_CHAT_INBOX_MESSAGES];
static size_t inbox_head;
static size_t inbox_count;
static size_t inbox_used; /* bytes held by live messages */
static uint32_t inbox_seq;
static uint8_t inbox_buf[CONFIG_CHAT_INBOX_BYTES];

/* --- Outbox: who each pending send went to, for its delivery line -------- */

static struct {
	uint32_t id;
	char label[CHAT_HEX_LEN + 1];
} outbox[16];
static uint32_t outbox_id;

static void hex(const uint8_t *b, size_t n, char *out)
{
	bin2hex(b, n, out, 2 * n + 1);
}

/* Callers hold the lock. */
static void label_locked(const uint8_t addr[RET_DEST_HASH_LEN], char *out, size_t cap)
{
	for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
		if (contacts[i].used && memcmp(contacts[i].c.addr, addr, RET_DEST_HASH_LEN) == 0) {
			snprintf(out, cap, "%s", contacts[i].c.name);
			return;
		}
	}
	for (size_t i = 0; i < n_heard; i++) {
		if (memcmp(heard[i].addr, addr, RET_DEST_HASH_LEN) == 0 && heard[i].display[0]) {
			snprintf(out, cap, "%s", heard[i].display);
			return;
		}
	}
	if (cap > CHAT_HEX_LEN) {
		hex(addr, RET_DEST_HASH_LEN, out);
	} else if (cap > 0) {
		out[0] = '\0';
	}
}

void chat_label(const uint8_t addr[RET_DEST_HASH_LEN], char *out, size_t cap)
{
	k_mutex_lock(&lock, K_FOREVER);
	label_locked(addr, out, cap);
	k_mutex_unlock(&lock);
}

/* One line for the log: control characters (newlines too) as spaces, cut
 * at @p cap. Deferred logging copies a %s argument up to its terminator,
 * so the copy must be terminated.
 */
static void preview(const uint8_t *p, size_t len, char *out, size_t cap)
{
	size_t n = MIN(len, cap - 1);

	for (size_t i = 0; i < n; i++) {
		out[i] = p[i] < 0x20 || p[i] == 0x7f ? ' ' : (char)p[i];
	}
	out[n] = '\0';
}

/* --- Client callbacks (client thread) ------------------------------------ */

static void sync_work_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(sync_work, sync_work_fn);

static void on_state(enum ret_client_state s, void *user)
{
	ARG_UNUSED(user);
	atomic_set(&state, s);
	if (s == RET_STATE_CONNECTED) {
		LOG_INF("connected");
		/* Collect what arrived at the node while we were away. */
		if (has_node) {
			k_work_reschedule(&sync_work, K_NO_WAIT);
		}
	} else if (s == RET_STATE_RECONNECTING) {
		LOG_WRN("connection lost: reconnecting");
	}
}

static void on_announce(const struct ret_announce_info *a, void *user)
{
	struct chat_heard h = { .hops = a->hops, .uptime_ms = k_uptime_get() };
	size_t at;

	ARG_UNUSED(user);
	if (memcmp(a->name_hash, lxmf_name_hash, sizeof(lxmf_name_hash)) != 0) {
		return;
	}
	memcpy(h.addr, a->dest_hash, RET_DEST_HASH_LEN);
	/* No name, or one LXMF could not display either: listed without. */
	if (ret_lxmf_display_name(a->app_data, a->app_data_len, h.display, sizeof(h.display)) < 0) {
		h.display[0] = '\0';
	}
	/* It is printed to a terminal: no control characters from the network. */
	for (char *p = h.display; *p; p++) {
		if ((uint8_t)*p < 0x20 || *p == 0x7f) {
			*p = '?';
		}
	}

	/* Entries stay where they are, so "#n" means the same address from
	 * one 'heard' to the next: a repeat updates in place, a newcomer takes
	 * a free entry, or the one heard least recently.
	 */
	k_mutex_lock(&lock, K_FOREVER);
	for (at = 0; at < n_heard; at++) {
		if (memcmp(heard[at].addr, h.addr, RET_DEST_HASH_LEN) == 0) {
			break;
		}
	}
	if (at == n_heard && n_heard < ARRAY_SIZE(heard)) {
		n_heard++;
	} else if (at == n_heard) {
		at = 0;
		for (size_t i = 1; i < n_heard; i++) {
			if (heard[i].uptime_ms < heard[at].uptime_ms) {
				at = i;
			}
		}
	}
	heard[at] = h;
	k_mutex_unlock(&lock);
}

static void inbox_evict(void)
{
	inbox_used -= inbox[inbox_head].m.title_len + inbox[inbox_head].m.stored_len;
	inbox_head = (inbox_head + 1) % ARRAY_SIZE(inbox);
	inbox_count--;
}

/* Where @p need bytes go, evicting the oldest messages until they fit. */
static uint32_t inbox_place(size_t need)
{
	for (;;) {
		if (inbox_count == ARRAY_SIZE(inbox)) {
			inbox_evict();
			continue;
		}
		/* Nothing live holds bytes (none, or only empty messages, such
		 * as ones carrying fields alone): start over at 0.
		 */
		if (inbox_used == 0) {
			return 0;
		}

		size_t newest = (inbox_head + inbox_count - 1) % ARRAY_SIZE(inbox);
		size_t start = inbox[inbox_head].off;
		size_t end = inbox[newest].off + inbox[newest].m.title_len + inbox[newest].m.stored_len;

		if (start < end) {
			/* Not wrapped: free space after the newest, then before the oldest. */
			if (sizeof(inbox_buf) - end >= need) {
				return end;
			}
			if (start >= need) {
				return 0;
			}
		} else if (start > end && start - end >= need) {
			return end; /* wrapped: the gap between newest and oldest */
		}
		inbox_evict();
	}
}

static void on_lxmf(const struct ret_lxmf_message *m, void *user)
{
	size_t title_len = MIN(m->title_len, TITLE_KEEP);
	size_t stored = MIN(m->content_len, sizeof(inbox_buf) - title_len);
	char who[CHAT_HEX_LEN + 1];
	char text[41];
	uint32_t seq;

	ARG_UNUSED(user);

	k_mutex_lock(&lock, K_FOREVER);
	uint32_t off = inbox_place(title_len + stored);
	size_t slot = (inbox_head + inbox_count) % ARRAY_SIZE(inbox);

	seq = ++inbox_seq;
	inbox[slot].off = off;
	inbox[slot].m = (struct chat_message){
		.seq = seq,
		.timestamp = m->timestamp,
		.verified = m->verified,
		.title_len = (uint16_t)title_len,
		.content_len = (uint32_t)m->content_len,
		.stored_len = (uint32_t)stored,
	};
	memcpy(inbox[slot].m.source, m->source, RET_DEST_HASH_LEN);
	memcpy(&inbox_buf[off], m->title, title_len);
	memcpy(&inbox_buf[off + title_len], m->content, stored);
	inbox_count++;
	inbox_used += title_len + stored;
	label_locked(m->source, who, sizeof(who));
	k_mutex_unlock(&lock);

	preview(m->content, m->content_len, text, sizeof(text));
	LOG_INF("new message #%u from %s%s: %s%s", seq, who, m->verified ? "" : " (unverified)",
		text, m->content_len > sizeof(text) - 1 ? "..." : "");
}

static void on_receipt(const uint8_t packet_hash[RET_PACKET_HASH_LEN],
		       enum ret_receipt_status status, uint32_t rtt_ms, void *user)
{
	uint32_t id = (uint32_t)(uintptr_t)user;
	char who[CHAT_HEX_LEN + 1] = "?";

	ARG_UNUSED(packet_hash);
	k_mutex_lock(&lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(outbox); i++) {
		if (outbox[i].id == id) {
			memcpy(who, outbox[i].label, sizeof(who));
		}
	}
	k_mutex_unlock(&lock);

	switch (status) {
	case RET_RECEIPT_DELIVERED:
		LOG_INF("sent #%u to %s: delivered (%u ms)", id, who, rtt_ms);
		break;
	case RET_RECEIPT_TIMEOUT:
		LOG_WRN("sent #%u to %s: not confirmed (no delivery proof)", id, who);
		break;
	case RET_RECEIPT_REJECTED:
		LOG_WRN("sent #%u to %s: rejected by the recipient", id, who);
		break;
	case RET_RECEIPT_DISCONNECTED:
		LOG_WRN("sent #%u to %s: connection dropped before delivery", id, who);
		break;
	default:
		LOG_WRN("sent #%u to %s: failed (no path to it, or not connected)", id, who);
		break;
	}
}

static void on_sync(int status, unsigned int received, void *user)
{
	ARG_UNUSED(user);
	if (status == 0) {
		LOG_INF("sync: %u new", received);
	} else {
		LOG_WRN("sync failed: %d", status);
	}
}

static void sync_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	int err = chat_sync();

	if (err == -EAGAIN) {
		k_work_reschedule(&sync_work, K_SECONDS(1)); /* request queue full */
	} else if (err) {
		LOG_WRN("sync not started: %d", err);
	}
}

/* --- Setup ---------------------------------------------------------------- */

static int contact_load_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
			   void *param)
{
	uint8_t rec[CONTACT_RECORD_LEN];
	char *end;
	unsigned long slot = strtoul(key, &end, 10);

	ARG_UNUSED(param);
	if (key[0] < '0' || key[0] > '9' || *end != '\0' || slot >= ARRAY_SIZE(contacts) ||
	    len != sizeof(rec) || read_cb(cb_arg, rec, sizeof(rec)) != sizeof(rec)) {
		/* Expendable: skipped, and kept for a larger table. Returning
		 * an error would stop the load at this record.
		 */
		LOG_WRN("contact record chat/ct/%s skipped", key);
		return 0;
	}
	contacts[slot].used = true;
	memcpy(contacts[slot].c.name, rec, CHAT_NAME_MAX);
	contacts[slot].c.name[CHAT_NAME_MAX] = '\0';
	memcpy(contacts[slot].c.addr, &rec[CHAT_NAME_MAX], RET_DEST_HASH_LEN);
	return 0;
}

int chat_init(void)
{
	int err = ret_client_name_hash("lxmf.delivery", lxmf_name_hash);

	if (err) {
		return err;
	}
	has_node = strlen(CONFIG_CHAT_PROPAGATION_NODE) > 0;
	if (has_node && hex2bin(CONFIG_CHAT_PROPAGATION_NODE, strlen(CONFIG_CHAT_PROPAGATION_NODE),
				node, sizeof(node)) != sizeof(node)) {
		LOG_ERR("CHAT_PROPAGATION_NODE must be 32 hex digits");
		return -EINVAL;
	}
	err = settings_subsys_init();
	if (!err) {
		err = settings_load_subtree_direct("chat/ct", contact_load_cb, NULL);
	}
	if (err) {
		LOG_ERR("loading contacts failed: %d", err);
		return err;
	}

	size_t n = 0;

	for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
		n += contacts[i].used;
	}
	atomic_set(&ready, 1);
	LOG_INF("%u contact(s) loaded", (unsigned int)n);
	return 0;
}

void chat_client_config(struct ret_client_config *cfg)
{
	cfg->on_state = on_state;
	cfg->on_announce = on_announce;
	cfg->on_lxmf = on_lxmf;
}

void chat_set_client(struct ret_client *c)
{
	client = c;
}

/* --- Front-end calls ------------------------------------------------------- */

int chat_resolve(const char *target, uint8_t addr[RET_DEST_HASH_LEN], char *label,
		 size_t label_cap)
{
	size_t len = strlen(target);
	int err = -ENOENT;

	if (!atomic_get(&ready)) {
		return -EBUSY;
	}
	k_mutex_lock(&lock, K_FOREVER);
	if (target[0] == '#') {
		char *end;
		unsigned long i = strtoul(&target[1], &end, 10);

		if (target[1] == '\0' || *end != '\0') {
			err = -EINVAL;
		} else if (i >= 1 && i <= n_heard) {
			memcpy(addr, heard[i - 1].addr, RET_DEST_HASH_LEN);
			err = 0;
		}
	} else if (len == CHAT_HEX_LEN && hex2bin(target, len, addr, RET_DEST_HASH_LEN) ==
						     RET_DEST_HASH_LEN) {
		err = 0;
	} else {
		for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
			if (contacts[i].used && strcmp(contacts[i].c.name, target) == 0) {
				memcpy(addr, contacts[i].c.addr, RET_DEST_HASH_LEN);
				err = 0;
				break;
			}
		}
	}
	if (!err) {
		label_locked(addr, label, label_cap);
	}
	k_mutex_unlock(&lock);
	return err;
}

int chat_send(const uint8_t addr[RET_DEST_HASH_LEN], const char *text, size_t len, uint32_t *id,
	      bool *was_heard)
{
	char who[CHAT_HEX_LEN + 1];
	int err;

	if (client == NULL) {
		return -ENOTCONN;
	}

	k_mutex_lock(&lock, K_FOREVER);
	label_locked(addr, who, sizeof(who));
	*was_heard = false;
	for (size_t i = 0; i < n_heard; i++) {
		*was_heard |= memcmp(heard[i].addr, addr, RET_DEST_HASH_LEN) == 0;
	}
	*id = ++outbox_id;
	outbox[*id % ARRAY_SIZE(outbox)].id = *id;
	memcpy(outbox[*id % ARRAY_SIZE(outbox)].label, who, sizeof(who));
	k_mutex_unlock(&lock);

	/* Packs and signs here, on the caller's stack (about 1.5 KB). */
	err = ret_lxmf_send(client, addr, NULL, 0, (const uint8_t *)text, len, on_receipt,
			    (void *)(uintptr_t)*id);
	if (err) {
		k_mutex_lock(&lock, K_FOREVER);
		outbox_id--; /* not sent: the next one takes its number */
		k_mutex_unlock(&lock);
	}
	return err;
}

static bool name_ok(const char *name)
{
	size_t len = strlen(name);

	if (len == 0 || len > CHAT_NAME_MAX) {
		return false;
	}
	for (size_t i = 0; i < len; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		      c == '_' || c == '-' || c == '.')) {
			return false;
		}
	}
	return true;
}

int chat_contact_add(const char *name, const uint8_t addr[RET_DEST_HASH_LEN])
{
	uint8_t rec[CONTACT_RECORD_LEN] = { 0 };
	char key[24]; /* "chat/ct/" and any int */
	int slot = -1;
	int err;

	if (!atomic_get(&ready)) {
		return -EBUSY;
	}
	if (!name_ok(name)) {
		return -EINVAL;
	}
	k_mutex_lock(&lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
		if (contacts[i].used && strcmp(contacts[i].c.name, name) == 0) {
			k_mutex_unlock(&lock);
			return -EEXIST;
		}
		if (!contacts[i].used && slot < 0) {
			slot = (int)i;
		}
	}
	if (slot < 0) {
		k_mutex_unlock(&lock);
		return -ENOSPC;
	}
	k_mutex_unlock(&lock);

	/* Written without the lock, so the client thread never waits on
	 * flash. Contacts change only from the front end (one thread).
	 */
	memcpy(rec, name, strlen(name));
	memcpy(&rec[CHAT_NAME_MAX], addr, RET_DEST_HASH_LEN);
	snprintf(key, sizeof(key), "chat/ct/%d", slot);
	err = settings_save_one(key, rec, sizeof(rec));
	if (!err) {
		k_mutex_lock(&lock, K_FOREVER);
		contacts[slot].used = true;
		strcpy(contacts[slot].c.name, name);
		memcpy(contacts[slot].c.addr, addr, RET_DEST_HASH_LEN);
		k_mutex_unlock(&lock);
	}
	return err;
}

int chat_contact_del(const char *name)
{
	char key[24]; /* "chat/ct/" and any int */
	int slot = -1;
	int err;

	if (!atomic_get(&ready)) {
		return -EBUSY;
	}
	k_mutex_lock(&lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
		if (contacts[i].used && strcmp(contacts[i].c.name, name) == 0) {
			slot = (int)i;
			break;
		}
	}
	k_mutex_unlock(&lock);
	if (slot < 0) {
		return -ENOENT;
	}
	snprintf(key, sizeof(key), "chat/ct/%d", slot);
	err = settings_delete(key);
	if (!err) {
		k_mutex_lock(&lock, K_FOREVER);
		contacts[slot].used = false;
		k_mutex_unlock(&lock);
	}
	return err;
}

int chat_contact_get(size_t i, struct chat_contact *out)
{
	int err = -ENOENT;

	if (!atomic_get(&ready)) {
		return -EBUSY;
	}
	k_mutex_lock(&lock, K_FOREVER);
	for (size_t j = 0; j < ARRAY_SIZE(contacts); j++) {
		if (contacts[j].used && i-- == 0) {
			*out = contacts[j].c;
			err = 0;
			break;
		}
	}
	k_mutex_unlock(&lock);
	return err;
}

int chat_heard_get(size_t i, struct chat_heard *out)
{
	int err = -ENOENT;

	k_mutex_lock(&lock, K_FOREVER);
	if (i < n_heard) {
		*out = heard[i];
		err = 0;
	}
	k_mutex_unlock(&lock);
	return err;
}

int chat_inbox_get(size_t i, struct chat_message *out)
{
	int err = -ENOENT;

	k_mutex_lock(&lock, K_FOREVER);
	if (i < inbox_count) {
		*out = inbox[(inbox_head + i) % ARRAY_SIZE(inbox)].m;
		err = 0;
	}
	k_mutex_unlock(&lock);
	return err;
}

int chat_inbox_read(uint32_t seq, size_t offset, struct chat_message *msg, char *title,
		    size_t title_cap, uint8_t *content, size_t content_cap)
{
	int err = -ENOENT;

	k_mutex_lock(&lock, K_FOREVER);
	for (size_t i = 0; i < inbox_count; i++) {
		size_t slot = (inbox_head + i) % ARRAY_SIZE(inbox);
		const struct chat_message *m = &inbox[slot].m;
		const uint8_t *p = &inbox_buf[inbox[slot].off];

		if (m->seq != seq) {
			continue;
		}
		*msg = *m;
		snprintf(title, title_cap, "%.*s", (int)MIN(m->title_len, title_cap - 1),
			 (const char *)p);
		size_t n = offset < m->stored_len ? MIN(m->stored_len - offset, content_cap) : 0;

		memcpy(content, p + m->title_len + offset, n);
		err = (int)n;
		break;
	}
	k_mutex_unlock(&lock);
	return err;
}

void chat_inbox_clear(void)
{
	k_mutex_lock(&lock, K_FOREVER);
	inbox_head = 0;
	inbox_count = 0;
	inbox_used = 0;
	memset(inbox_buf, 0, sizeof(inbox_buf)); /* the plaintext goes too */
	k_mutex_unlock(&lock);
}

int chat_announce(void)
{
	return client == NULL ? -ENOTCONN : ret_client_announce(client);
}

int chat_sync(void)
{
	if (!has_node) {
		return -ENOENT;
	}
	return client == NULL ? -ENOTCONN : ret_lxmf_sync(client, node, on_sync, NULL);
}

void chat_status(struct chat_status *out)
{
	memset(out, 0, sizeof(*out));
	out->state = (enum ret_client_state)atomic_get(&state);
	out->started = client != NULL;
	out->network = network_status();
	out->has_node = has_node;
	memcpy(out->node, node, sizeof(node));
	if (client != NULL) {
		(void)ret_client_dest_hash(client, out->addr);
	}
	k_mutex_lock(&lock, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(contacts); i++) {
		out->contacts += contacts[i].used;
	}
	out->heard = n_heard;
	out->inbox = inbox_count;
	out->newest_seq = inbox_seq;
	k_mutex_unlock(&lock);
}
