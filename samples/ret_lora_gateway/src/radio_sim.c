/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * A radio on native_sim: each LoRa frame is one UDP datagram to the
 * simulated air (tools/rns_peer/air.py), which decides who hears it.
 */

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>

#include "radio.h"
#include "ret_rnode_air.h"

LOG_MODULE_REGISTER(radio_sim, LOG_LEVEL_INF);

#define RX_STACK_SIZE 2048

static int sock = -1;
static struct sockaddr_in air;
static radio_rx_cb rx_cb;
static K_THREAD_STACK_DEFINE(rx_stack, RX_STACK_SIZE);
static struct k_thread rx_thread;

static void rx_loop(void *a, void *b, void *c)
{
	static uint8_t buf[RET_RNODE_FRAME_MAX];

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		ssize_t n = zsock_recv(sock, buf, sizeof(buf), 0);

		if (n > 0) {
			rx_cb(buf, (size_t)n);
		} else if (n < 0) {
			LOG_ERR("recv: %d", errno);
			k_sleep(K_MSEC(100));
		}
	}
}

int radio_init(radio_rx_cb cb)
{
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_port = htons(CONFIG_RET_LORA_SIM_LOCAL_PORT),
	};

	rx_cb = cb;
	air.sin_family = AF_INET;
	air.sin_port = htons(CONFIG_RET_LORA_SIM_AIR_PORT);
	zsock_inet_pton(AF_INET, "127.0.0.1", &air.sin_addr);
	zsock_inet_pton(AF_INET, "127.0.0.1", &local.sin_addr);

	sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		return -errno;
	}
	if (zsock_bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
		return -errno;
	}
	k_thread_create(&rx_thread, rx_stack, K_THREAD_STACK_SIZEOF(rx_stack), rx_loop, NULL, NULL,
			NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	return 0;
}

int radio_send(const struct radio_frame *frames, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		if (zsock_sendto(sock, frames[i].data, frames[i].len, 0, (struct sockaddr *)&air,
				 sizeof(air)) < 0) {
			return -errno;
		}
	}
	return 0;
}
