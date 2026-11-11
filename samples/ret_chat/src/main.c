/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * LXMF chat over the console: a shell to message contacts, read the
 * inbox and see who is around (chat_shell.c), over the chat layer
 * (chat.c). The shell runs from boot; the client starts once the network
 * and the wall clock are up, which 'status' shows meanwhile.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/sys/util.h>

#include <ret/ret_client.h>

#include "chat.h"
#include "network.h"

LOG_MODULE_REGISTER(ret_chat, LOG_LEVEL_INF);

int main(void)
{
	static struct ret_client_config cfg = {
		.lxmf_display_name = CONFIG_CHAT_DISPLAY_NAME,
	};
	struct ret_client *client;
	uint8_t own[RET_DEST_HASH_LEN];
	char own_hex[CHAT_HEX_LEN + 1];
	int err;

	/* Logs go through the shell, and ones made before it is up are
	 * dropped: wait for it (briefly), so the boot lines (address,
	 * ratchet) are seen.
	 */
	for (int i = 0; i < 100 && !shell_ready(shell_backend_uart_get_ptr()); i++) {
		k_sleep(K_MSEC(10));
	}

	err = chat_init();
	if (err) {
		return err;
	}
	chat_client_config(&cfg);
	client = ret_client_create(&cfg);

	wait_for_network();
	err = ret_client_start(client);
	if (err) {
		LOG_ERR("ret_client_start failed: %d", err);
		return err;
	}
	chat_set_client(client);
	if (ret_client_dest_hash(client, own) == 0) {
		bin2hex(own, sizeof(own), own_hex, sizeof(own_hex));
		LOG_INF("CHAT ADDRESS %s (%s)", own_hex, CONFIG_CHAT_DISPLAY_NAME);
	}
	return 0;
}
