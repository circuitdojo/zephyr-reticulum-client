/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * The chat layer: contacts, the addresses heard announcing, the inbox and
 * sending, on top of ret_client. No shell in here: the shell commands
 * (chat_shell.c) are one front end, and buttons or a screen could be
 * another. Calls come from one front-end thread; the client callbacks it
 * installs run on the client thread and never wait on flash.
 */

#ifndef CHAT_H_
#define CHAT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ret/ret_client.h>

#define CHAT_NAME_MAX 16 /* contact names, without the terminator */
#define CHAT_DISPLAY_MAX 32 /* announced display names kept */
#define CHAT_HEX_LEN  (2 * RET_DEST_HASH_LEN)

struct chat_contact {
	char name[CHAT_NAME_MAX + 1];
	uint8_t addr[RET_DEST_HASH_LEN];
};

struct chat_heard {
	uint8_t addr[RET_DEST_HASH_LEN];
	/* "" when it announced none; control characters replaced by '?' */
	char display[CHAT_DISPLAY_MAX + 1];
	uint8_t hops;
	int64_t uptime_ms; /* when last heard */
};

/** An inbox entry, without its text. */
struct chat_message {
	uint32_t seq; /* numbering starts at 1 each boot */
	uint8_t source[RET_DEST_HASH_LEN];
	double timestamp; /* the sender's clock */
	bool verified;
	uint16_t title_len; /* stored */
	uint32_t content_len; /* as received */
	uint32_t stored_len; /* content bytes kept (less when larger than the inbox) */
};

struct chat_status {
	enum ret_client_state state;
	bool started;
	const char *network;
	uint8_t addr[RET_DEST_HASH_LEN];
	bool has_node;
	uint8_t node[RET_DEST_HASH_LEN];
	size_t contacts;
	size_t heard;
	size_t inbox;
	uint32_t newest_seq;
};

/**
 * Load the contacts from settings. Before ret_client_start(); the client
 * then shares the settings backend.
 */
int chat_init(void);

/** The callbacks chat needs, filled into @p cfg (on_state, on_announce, on_lxmf). */
void chat_client_config(struct ret_client_config *cfg);

/** The client is started: commands that need it can run. */
void chat_set_client(struct ret_client *client);

/**
 * Resolve @p target: a contact name, a 32-hex address, or "#<n>" for the
 * n-th entry of the heard list (entries keep their place; a newcomer
 * replaces the one heard least recently when the list is full). @p label
 * (at least CHAT_HEX_LEN + 1 bytes) gets what to call it.
 *
 * Contact calls fail with -EBUSY until chat_init() has loaded them.
 *
 * @retval -ENOENT no such contact or heard entry
 * @retval -EINVAL not a name, address or index
 * @retval -EBUSY contacts not loaded yet
 */
int chat_resolve(const char *target, uint8_t addr[RET_DEST_HASH_LEN], char *label,
		 size_t label_cap);

/**
 * Send @p text to @p addr (from chat_resolve()) with ret_lxmf_send():
 * opportunistic when it fits one packet, otherwise DIRECT. Delivery is
 * logged later as "sent #<id> to <label>: ...".
 *
 * @param id    the outbox number the delivery log line will carry
 * @param heard false when @p addr has not announced since boot: the
 *              client requests its path first
 * @return 0, or the error from ret_lxmf_send() (-ENOTCONN before the
 *         client started)
 */
int chat_send(const uint8_t addr[RET_DEST_HASH_LEN], const char *text, size_t len, uint32_t *id,
	      bool *heard);

/** @retval -ENOSPC table full  -EEXIST name taken  -EINVAL bad name */
int chat_contact_add(const char *name, const uint8_t addr[RET_DEST_HASH_LEN]);
/** @retval -ENOENT no such contact */
int chat_contact_del(const char *name);
/** The @p i-th contact (0-based, in table order). @retval -ENOENT past the end */
int chat_contact_get(size_t i, struct chat_contact *out);

/** The @p i-th heard address (entry n+1 of chat_resolve()'s "#n"). @retval -ENOENT past the end */
int chat_heard_get(size_t i, struct chat_heard *out);

/** The @p i-th inbox message, oldest first. @retval -ENOENT past the end */
int chat_inbox_get(size_t i, struct chat_message *out);

/**
 * Message @p seq: its header, its title into @p title (NUL-terminated, cut
 * to fit), and stored content from byte @p offset into @p content (not
 * terminated), so a front end can show a long message in pieces.
 *
 * @return content bytes copied (0 past the end)
 * @retval -ENOENT no such message (never received, or evicted)
 */
int chat_inbox_read(uint32_t seq, size_t offset, struct chat_message *msg, char *title,
		    size_t title_cap, uint8_t *content, size_t content_cap);

void chat_inbox_clear(void);

/** Name to show for @p addr: its contact name, else its announced name, else hex. */
void chat_label(const uint8_t addr[RET_DEST_HASH_LEN], char *out, size_t cap);

/** @retval -ENOTCONN client not started */
int chat_announce(void);

/**
 * Collect from CONFIG_CHAT_PROPAGATION_NODE; the result is logged.
 *
 * @retval -ENOENT no node configured  -ENOTCONN client not started
 */
int chat_sync(void);

void chat_status(struct chat_status *out);

#endif /* CHAT_H_ */
