/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A path store in RAM for ret_transport: a fixed array of paths with their
 * announces. When full, the path written longest ago makes room.
 */

#ifndef RET_TRANSPORT_STORE_RAM_H_
#define RET_TRANSPORT_STORE_RAM_H_

#include "ret_transport.h"

struct ret_transport_store_ram_entry {
	bool used;
	uint32_t seq;
	uint16_t len;
	struct ret_transport_path_meta meta;
	uint8_t announce[RET_MTU];
};

struct ret_transport_store_ram {
	struct ret_transport_store store;
	struct ret_transport_store_ram_entry *entries;
	size_t n;
	uint32_t seq;
};

void ret_transport_store_ram_init(struct ret_transport_store_ram *s,
				  struct ret_transport_store_ram_entry *entries, size_t n);

#endif /* RET_TRANSPORT_STORE_RAM_H_ */
