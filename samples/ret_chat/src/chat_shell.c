/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Shell commands over chat.h. Each is a thin wrapper: parse, call, print.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include "chat.h"


static const char *state_str(enum ret_client_state s)
{
	switch (s) {
	case RET_STATE_CONNECTING:
		return "connecting";
	case RET_STATE_CONNECTED:
		return "connected";
	case RET_STATE_RECONNECTING:
		return "reconnecting";
	case RET_STATE_SUSPENDED:
		return "suspended";
	default:
		return "disconnected";
	}
}

static void ago(int64_t uptime_ms, char *out, size_t cap)
{
	int64_t s = (k_uptime_get() - uptime_ms) / MSEC_PER_SEC;

	if (s < 60) {
		snprintf(out, cap, "%llds", (long long)s);
	} else if (s < 3600) {
		snprintf(out, cap, "%lldm", (long long)(s / 60));
	} else {
		snprintf(out, cap, "%lldh", (long long)(s / 3600));
	}
}

/* Control characters from the network would drive the terminal: show them
 * as '?' (newlines and tabs stay in message text).
 */
static void sanitize(char *p, size_t n, bool keep_lines)
{
	for (size_t i = 0; i < n; i++) {
		uint8_t c = (uint8_t)p[i];

		if ((c < 0x20 && !(keep_lines && (c == '\n' || c == '\t'))) || c == 0x7f) {
			p[i] = '?';
		}
	}
}

static void print_send_error(const struct shell *sh, int err)
{
	switch (err) {
	case -EBUSY:
		shell_error(sh, "starting up: try again in a moment");
		break;
	case -ENOENT:
		shell_error(sh, "no such contact or heard entry (see 'contact list', 'heard')");
		break;
	case -EINVAL:
		shell_error(sh, "give a contact name, a 32-hex address or #<n> from 'heard'");
		break;
	case -ENOTCONN:
		shell_error(sh, "not started yet (see 'status')");
		break;
	case -ENODATA:
		shell_error(sh, "waiting for network time: LXMF needs the wall clock");
		break;
	case -EAGAIN:
		shell_error(sh, "send queue full: try again shortly");
		break;
	case -EMSGSIZE:
		shell_error(sh, "too long: at most %d bytes", RET_LXMF_DIRECT_MAX_CONTENT > 0
								       ? RET_LXMF_DIRECT_MAX_CONTENT
								       : RET_LXMF_OPPORTUNISTIC_MAX_CONTENT);
		break;
	default:
		shell_error(sh, "not sent: %d", err);
		break;
	}
}

/* msg send <to> <text...>: the text is the rest of the line, as typed. */
static int cmd_msg_send(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t addr[RET_DEST_HASH_LEN];
	char who[CHAT_HEX_LEN + 1];
	uint32_t id;
	bool heard;
	int err;

	if (argc < 3 || argv[2][0] == '\0') {
		shell_error(sh, "usage: msg send <to> <text>");
		return -EINVAL;
	}
	/* Resolved once, and the line below says to whom it went. */
	err = chat_resolve(argv[1], addr, who, sizeof(who));
	if (!err) {
		err = chat_send(addr, argv[2], strlen(argv[2]), &id, &heard);
	}
	if (err) {
		print_send_error(sh, err);
		return err;
	}
	shell_print(sh, "queued #%u to %s (%u bytes)%s", id, who, (unsigned int)strlen(argv[2]),
		    heard ? "" : "; not heard yet: requesting its path");
	return 0;
}

static int cmd_msg_inbox(const struct shell *sh, size_t argc, char **argv)
{
	struct chat_message m;
	char who[CHAT_HEX_LEN + 1];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (chat_inbox_get(0, &m) != 0) {
		shell_print(sh, "inbox empty");
		return 0;
	}
	for (size_t i = 0; chat_inbox_get(i, &m) == 0; i++) {
		chat_label(m.source, who, sizeof(who));
		shell_print(sh, "#%u %s%s, %u bytes", m.seq, who, m.verified ? "" : " (unverified)",
			    m.content_len);
	}
	return 0;
}

static int cmd_msg_read(const struct shell *sh, size_t argc, char **argv)
{
	struct chat_message m;
	char who[CHAT_HEX_LEN + 1];
	char title[65];
	uint8_t part[128];
	char *end;
	unsigned long seq = strtoul(argv[1], &end, 10);
	size_t off = 0;
	int n;

	ARG_UNUSED(argc);
	n = *end == '\0' ? chat_inbox_read((uint32_t)seq, 0, &m, title, sizeof(title), part,
					   sizeof(part))
			 : -ENOENT;
	if (n < 0) {
		shell_error(sh, "no message #%s (see 'msg inbox')", argv[1]);
		return -ENOENT;
	}
	/* The sender's clock, in UTC (no float formatting needed). */
	time_t t = (time_t)m.timestamp;
	struct tm tm;
	char when[24] = "?";

	if (gmtime_r(&t, &tm) != NULL) {
		strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tm);
	}
	chat_label(m.source, who, sizeof(who));
	shell_print(sh, "#%u from %s%s, sent %s UTC", m.seq, who,
		    m.verified ? "" : " (UNVERIFIED: sender's key unknown)", when);
	if (title[0]) {
		sanitize(title, strlen(title), false);
		shell_print(sh, "title: %s", title);
	}
	/* In pieces, so a long message needs no buffer of its own. A message
	 * evicted meanwhile just ends early.
	 */
	while (n > 0) {
		sanitize((char *)part, (size_t)n, true);
		shell_fprintf(sh, SHELL_NORMAL, "%.*s", n, (const char *)part);
		off += (size_t)n;
		n = chat_inbox_read((uint32_t)seq, off, &m, title, sizeof(title), part,
				    sizeof(part));
	}
	shell_print(sh, "");
	if (m.stored_len < m.content_len) {
		shell_print(sh, "[%u of %u bytes kept]", m.stored_len, m.content_len);
	}
	return 0;
}

static int cmd_msg_clear(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	chat_inbox_clear();
	shell_print(sh, "inbox cleared");
	return 0;
}

static int cmd_contact_add(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t addr[RET_DEST_HASH_LEN];
	char label[CHAT_HEX_LEN + 1];
	int err;

	char hex[CHAT_HEX_LEN + 1];

	ARG_UNUSED(argc);
	err = chat_resolve(argv[2], addr, label, sizeof(label));
	if (err == -EBUSY) {
		print_send_error(sh, err);
		return err;
	} else if (err) {
		shell_error(sh, "give a 32-hex address or #<n> from 'heard'");
		return err;
	}
	err = chat_contact_add(argv[1], addr);
	switch (err) {
	case 0:
		/* The address saved, in full: "#n" is resolved once, here. */
		bin2hex(addr, sizeof(addr), hex, sizeof(hex));
		shell_print(sh, "added %s: %s", argv[1], hex);
		break;
	case -EBUSY:
		print_send_error(sh, err);
		break;
	case -EINVAL:
		shell_error(sh, "names are 1-%d of A-Z a-z 0-9 _ - .", CHAT_NAME_MAX);
		break;
	case -EEXIST:
		shell_error(sh, "%s exists", argv[1]);
		break;
	case -ENOSPC:
		shell_error(sh, "contacts full (%d)", CONFIG_CHAT_CONTACTS);
		break;
	default:
		shell_error(sh, "not saved: %d", err);
		break;
	}
	return err;
}

static int cmd_contact_del(const struct shell *sh, size_t argc, char **argv)
{
	int err = chat_contact_del(argv[1]);

	ARG_UNUSED(argc);
	if (err == -ENOENT) {
		shell_error(sh, "no contact %s", argv[1]);
	} else if (err == -EBUSY) {
		print_send_error(sh, err);
	} else if (err) {
		shell_error(sh, "not deleted: %d", err);
	} else {
		shell_print(sh, "deleted %s", argv[1]);
	}
	return err;
}

static int cmd_contact_list(const struct shell *sh, size_t argc, char **argv)
{
	struct chat_contact c;
	char addr[CHAT_HEX_LEN + 1];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	int err = chat_contact_get(0, &c);

	if (err == -EBUSY) {
		print_send_error(sh, err);
		return err;
	} else if (err) {
		shell_print(sh, "no contacts: 'contact add <name> <address|#n>'");
		return 0;
	}
	for (size_t i = 0; chat_contact_get(i, &c) == 0; i++) {
		bin2hex(c.addr, sizeof(c.addr), addr, sizeof(addr));
		shell_print(sh, "%-16s %s", c.name, addr);
	}
	return 0;
}

static int cmd_heard(const struct shell *sh, size_t argc, char **argv)
{
	struct chat_heard h;
	char addr[CHAT_HEX_LEN + 1];
	char when[24];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (chat_heard_get(0, &h) != 0) {
		shell_print(sh, "no LXMF announces heard since boot");
		return 0;
	}
	for (size_t i = 0; chat_heard_get(i, &h) == 0; i++) {
		bin2hex(h.addr, sizeof(h.addr), addr, sizeof(addr));
		ago(h.uptime_ms, when, sizeof(when));
		shell_print(sh, "#%u %s %s, %u hop%s, %s ago", (unsigned int)(i + 1), addr,
			    h.display[0] ? h.display : "(no name)", h.hops, h.hops == 1 ? "" : "s",
			    when);
	}
	return 0;
}

static int cmd_announce(const struct shell *sh, size_t argc, char **argv)
{
	int err = chat_announce();

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (err == -ENOTCONN) {
		shell_error(sh, "not started yet");
	} else if (err) {
		shell_error(sh, "not queued: %d", err);
	} else {
		shell_print(sh, "announce queued");
	}
	return err;
}

static int cmd_sync(const struct shell *sh, size_t argc, char **argv)
{
	int err = chat_sync();

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	if (err == -ENOENT) {
		shell_error(sh, "no propagation node: set CONFIG_CHAT_PROPAGATION_NODE");
	} else if (err == -ENOTCONN) {
		shell_error(sh, "not started yet");
	} else if (err) {
		shell_error(sh, "sync not started: %d", err);
	} else {
		shell_print(sh, "syncing");
	}
	return err;
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	struct chat_status s;
	char hex[CHAT_HEX_LEN + 1];

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	chat_status(&s);
	shell_print(sh, "network:  %s", s.network);
	shell_print(sh, "client:   %s", s.started ? state_str(s.state) : "not started");
	if (s.started) {
		bin2hex(s.addr, sizeof(s.addr), hex, sizeof(hex));
		shell_print(sh, "address:  %s (%s)", hex, CONFIG_CHAT_DISPLAY_NAME);
	}
	if (s.has_node) {
		bin2hex(s.node, sizeof(s.node), hex, sizeof(hex));
		shell_print(sh, "node:     %s", hex);
	}
	shell_print(sh, "contacts: %u, heard: %u, inbox: %u", (unsigned int)s.contacts,
		    (unsigned int)s.heard, (unsigned int)s.inbox);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(msg_cmds,
	SHELL_CMD_ARG(send, NULL, "Send: msg send <contact|address|#n> <text>", cmd_msg_send, 2,
		      SHELL_OPT_ARG_RAW),
	SHELL_CMD(inbox, NULL, "List received messages", cmd_msg_inbox),
	SHELL_CMD_ARG(read, NULL, "Show one: msg read <n>", cmd_msg_read, 2, 0),
	SHELL_CMD(clear, NULL, "Empty the inbox", cmd_msg_clear),
	SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(msg, &msg_cmds, "LXMF messages", NULL);

SHELL_STATIC_SUBCMD_SET_CREATE(contact_cmds,
	SHELL_CMD_ARG(add, NULL, "contact add <name> <address|#n>", cmd_contact_add, 3, 0),
	SHELL_CMD_ARG(del, NULL, "contact del <name>", cmd_contact_del, 2, 0),
	SHELL_CMD(list, NULL, "List contacts", cmd_contact_list),
	SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(contact, &contact_cmds, "Names for LXMF addresses", NULL);

SHELL_CMD_REGISTER(heard, NULL, "LXMF addresses heard announcing since boot", cmd_heard);
SHELL_CMD_REGISTER(announce, NULL, "Announce our LXMF address now", cmd_announce);
SHELL_CMD_REGISTER(sync, NULL, "Collect messages from the propagation node", cmd_sync);
SHELL_CMD_REGISTER(status, NULL, "Connection, address and counts", cmd_status);
