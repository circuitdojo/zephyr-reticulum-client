/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RET_TCP_H_
#define RET_TCP_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Resolve @p host and open a connected TCP socket with the configured
 * send timeout and (if enabled) keepalive. A socket option the stack
 * rejects fails the attempt rather than leaving it unset.
 *
 * @return fd or -errno
 */
int ret_tcp_connect(const char *host, uint16_t port);

/** Send all of @p buf, retrying partial writes. */
int ret_tcp_send_all(int fd, const uint8_t *buf, size_t len);

#endif /* RET_TCP_H_ */
