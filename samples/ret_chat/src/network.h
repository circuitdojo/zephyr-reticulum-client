/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#ifndef NETWORK_H_
#define NETWORK_H_

/**
 * Block until the network is up and the wall clock is set (LTE and
 * network time on the modem; the host's clock on native_sim).
 */
void wait_for_network(void);

/** What wait_for_network() is waiting for, or "up". Any thread. */
const char *network_status(void);

#endif /* NETWORK_H_ */
