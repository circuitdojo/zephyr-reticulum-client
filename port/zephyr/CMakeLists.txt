# Copyright (c) 2026 Circuit Dojo LLC
# SPDX-License-Identifier: Apache-2.0

if(NOT CONFIG_RET_CORE)
    return()
endif()

# Monocypher provides X25519 and RFC 8032 Ed25519 (neither mbedTLS nor the
# PSA core on native_sim has Ed25519). The west manifests fetch it to
# modules/crypto/monocypher; override with -DRET_MONOCYPHER_DIR=<path>.
set(RET_MONOCYPHER_DIR "${ZEPHYR_BASE}/../modules/crypto/monocypher"
    CACHE PATH "Monocypher source tree")
get_filename_component(RET_MONOCYPHER_DIR "${RET_MONOCYPHER_DIR}" ABSOLUTE)
if(NOT EXISTS "${RET_MONOCYPHER_DIR}/src/optional/monocypher-ed25519.c")
    message(FATAL_ERROR
        "ret-client needs Monocypher at ${RET_MONOCYPHER_DIR} (not found). "
        "Run `west update` with ret-client's manifest, or clone it: "
        "git clone --depth 1 -b 4.0.2 https://github.com/LoupVaillant/Monocypher "
        "${RET_MONOCYPHER_DIR}")
endif()

# The minimal TF-M profile fixes the secure image's crypto to random
# generation and ignores PSA_WANT_*, so every hash/HMAC/AES call would fail
# at runtime with PSA_ERROR_NOT_SUPPORTED. Refuse the build instead.
if(CONFIG_TFM_PROFILE_TYPE_MINIMAL)
    message(FATAL_ERROR
        "ret-client needs SHA-256, HMAC and AES-CBC from TF-M, which the minimal "
        "TF-M profile (CONFIG_TFM_PROFILE_TYPE_MINIMAL) does not provide. Set "
        "CONFIG_TFM_PROFILE_TYPE_NOT_SET=y and size the TF-M slot (slot0_s_partition) "
        "to fit it.")
endif()

# mpack (msgpack): pinned in the west manifests like Monocypher. Configured by
# port/mpack/mpack-config.h, applied everywhere mpack.h is included.
set(RET_MPACK_DIR "${ZEPHYR_BASE}/../modules/lib/mpack" CACHE PATH "mpack source tree")
get_filename_component(RET_MPACK_DIR "${RET_MPACK_DIR}" ABSOLUTE)
if(NOT EXISTS "${RET_MPACK_DIR}/src/mpack/mpack.h")
    message(FATAL_ERROR
        "ret-client needs mpack at ${RET_MPACK_DIR} (not found). Run `west update` "
        "with ret-client's manifest.")
endif()
zephyr_compile_definitions(MPACK_HAS_CONFIG=1)
zephyr_include_directories(../mpack ${RET_MPACK_DIR}/src/mpack)

zephyr_include_directories(../../include)

zephyr_library()

zephyr_library_include_directories(
    ../../src
    ${RET_MONOCYPHER_DIR}/src
    ${RET_MONOCYPHER_DIR}/src/optional
)

zephyr_library_sources(
    ../../src/ret_hdlc.c
    ../../src/ret_packet.c
    ../../src/ret_crypto_psa.c
    ../../src/ret_crypto_common.c
    ../../src/ret_identity.c
    ../../src/ret_announce.c
    ../../src/ret_destinations.c
    ../../src/ret_receipt.c
    ../../src/ret_link.c
    ../../src/ret_mp.c
    ../../src/ret_resource.c
    ../../src/ret_ifac.c
    ../../src/ret_rnode_air.c
    ../../src/ret_lxmf.c
    ../../src/ret_lxmf_seen.c
    ${RET_MONOCYPHER_DIR}/src/monocypher.c
    ${RET_MONOCYPHER_DIR}/src/optional/monocypher-ed25519.c
    ${RET_MPACK_DIR}/src/mpack/mpack-common.c
    ${RET_MPACK_DIR}/src/mpack/mpack-platform.c
    ${RET_MPACK_DIR}/src/mpack/mpack-reader.c
    ${RET_MPACK_DIR}/src/mpack/mpack-expect.c
    ${RET_MPACK_DIR}/src/mpack/mpack-writer.c
)

zephyr_library_sources_ifdef(CONFIG_RET_TRANSPORT
    ../../src/ret_transport.c
    ../../src/ret_transport_store_ram.c
)

# TCP helpers for anything with sockets: the client and gateways.
zephyr_library_sources_ifdef(CONFIG_NET_SOCKETS ../../src/ret_tcp.c)

zephyr_library_sources_ifdef(CONFIG_RET_CLIENT
    ../../src/ret_client.c
    ../../src/ret_client_link.c
    ../../src/ret_client_lxmf.c
    ../../src/ret_client_lxmf_sync.c
    ../../src/ret_client_lxmf_direct.c
    ../../src/ret_storage.c
)

if(CONFIG_MBEDTLS)
    zephyr_library_link_libraries(mbedTLS)
endif()
