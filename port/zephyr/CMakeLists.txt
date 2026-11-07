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
    ${RET_MONOCYPHER_DIR}/src/monocypher.c
    ${RET_MONOCYPHER_DIR}/src/optional/monocypher-ed25519.c
)

zephyr_library_sources_ifdef(CONFIG_RET_CLIENT
    ../../src/ret_tcp.c
    ../../src/ret_client.c
    ../../src/ret_storage.c
)

if(CONFIG_MBEDTLS)
    zephyr_library_link_libraries(mbedTLS)
endif()
