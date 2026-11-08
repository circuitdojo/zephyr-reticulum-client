/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <date_time.h>
#include <modem/lte_lc.h>
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

/* What the modem does between wakes: the point of the sample. */
static void lte_handler(const struct lte_lc_evt *const evt)
{
	switch (evt->type) {
	case LTE_LC_EVT_PSM_UPDATE:
		LOG_INF("PSM: TAU %d s, active time %d s", evt->psm_cfg.tau,
			evt->psm_cfg.active_time);
		break;
	case LTE_LC_EVT_MODEM_SLEEP_ENTER:
		LOG_INF("modem sleep (type %d)", evt->modem_sleep.type);
		break;
	case LTE_LC_EVT_MODEM_SLEEP_EXIT:
		LOG_INF("modem awake");
		break;
	case LTE_LC_EVT_RRC_UPDATE:
		LOG_INF("RRC %s", evt->rrc_mode == LTE_LC_RRC_MODE_CONNECTED ? "connected" : "idle");
		break;
	default:
		break;
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
	lte_lc_register_handler(lte_handler);
	/* Replays the current state, in case LTE came up before we listened. */
	conn_mgr_mon_resend_status();

	LOG_INF("waiting for LTE...");
	k_sem_take(&l4_up, K_FOREVER);

	/* LXMF timestamps are wall-clock time: wait until date_time has it. */
	date_time_register_handler(date_time_handler);
	if (!date_time_is_valid()) {
		LOG_INF("waiting for network time...");
		(void)date_time_update_async(date_time_handler);
		k_sem_take(&time_known, K_FOREVER);
	}
	LOG_INF("wall clock set");
}
