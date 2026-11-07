/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_H_
#define NETWORK_H_

/** Block until the network is up (LTE on the modem; no-op on native_sim). */
void wait_for_network(void);

#endif /* NETWORK_H_ */
