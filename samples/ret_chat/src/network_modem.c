/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <date_time.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/net_mgmt.h>

#include "network.h"

LOG_MODULE_REGISTER(network, LOG_LEVEL_INF);

static K_SEM_DEFINE(l4_up, 0, 1);
static K_SEM_DEFINE(time_known, 0, 1);
static struct net_mgmt_event_callback l4_cb;
static const char *volatile status = "starting";

const char *network_status(void)
{
	return status;
}

static void l4_handler(struct net_mgmt_event_callback *cb, uint64_t event,
		       struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	if (event == NET_EVENT_L4_CONNECTED) {
		LOG_INF("LTE connected");
		k_sem_give(&l4_up);
	} else if (event == NET_EVENT_L4_DISCONNECTED) {
		/* The client notices on its own and reconnects when LTE returns. */
		LOG_WRN("LTE disconnected");
	}
}

static void date_time_handler(const struct date_time_evt *evt)
{
	if (evt->type != DATE_TIME_NOT_OBTAINED) {
		k_sem_give(&time_known);
	}
}

void wait_for_network(void)
{
	net_mgmt_init_event_callback(&l4_cb, l4_handler,
				     NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED);
	net_mgmt_add_event_callback(&l4_cb);
	/* Replays the current state, in case LTE came up before we listened. */
	conn_mgr_mon_resend_status();

	status = "waiting for LTE";
	LOG_INF("waiting for LTE...");
	k_sem_take(&l4_up, K_FOREVER);

	/* LXMF timestamps are wall-clock time: wait until date_time has it. */
	date_time_register_handler(date_time_handler);
	if (!date_time_is_valid()) {
		status = "waiting for network time";
		LOG_INF("waiting for network time...");
		(void)date_time_update_async(date_time_handler);
		k_sem_take(&time_known, K_FOREVER);
	}
	LOG_INF("wall clock set");
	status = "up";
}
