/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <time.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/clock.h>

#include <native_rtc.h>

#include "network.h"

LOG_MODULE_REGISTER(network, LOG_LEVEL_INF);

void wait_for_network(void)
{
	/* Host sockets (NSOS) are usable immediately. The wall clock, which
	 * LXMF timestamps need, comes from the host.
	 */
	uint64_t sec;
	uint32_t nsec;
	struct timespec ts;

	native_rtc_gettime(RTC_CLOCK_PSEUDOHOSTREALTIME, &nsec, &sec);
	ts.tv_sec = (time_t)sec;
	ts.tv_nsec = nsec;
	if (sys_clock_settime(SYS_CLOCK_REALTIME, &ts) != 0) {
		LOG_ERR("could not set the wall clock");
	}
}
