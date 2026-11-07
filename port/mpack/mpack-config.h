/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * mpack build configuration for ret-client (used via MPACK_HAS_CONFIG).
 * Fixed caller buffers only: no heap (MPACK_STDLIB 1 would default
 * MPACK_MALLOC to malloc and enable the growable builder), no stdio, no
 * node/tree API, no extension types (RNS/LXMF never emit them).
 *
 * Floats: write them with mpack_write_double only. umsgpack always writes
 * a Python float as float64 (0xcb); mpack_write_float emits float32 (0xca)
 * and the bytes would no longer match what RNS/LXMF hash and sign.
 */

#ifndef RET_MPACK_CONFIG_H_
#define RET_MPACK_CONFIG_H_

#define MPACK_STDLIB 0 /* compiler builtins for memcpy/strlen; no malloc */
#define MPACK_BUILDER 0 /* would allocate; fail loudly if anything re-enables it */
#define MPACK_STDIO 0
#define MPACK_NODE 0
#define MPACK_EXTENSIONS 0
#define MPACK_COMPATIBILITY 0 /* str8 allowed, as umsgpack writes it */
#define MPACK_DEBUG 0
#define MPACK_READ_TRACKING 0
#define MPACK_WRITE_TRACKING 0
#define MPACK_OPTIMIZE_FOR_SIZE 1

#endif /* RET_MPACK_CONFIG_H_ */
