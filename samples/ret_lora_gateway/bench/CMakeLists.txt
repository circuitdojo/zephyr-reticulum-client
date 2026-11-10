cmake_minimum_required(VERSION 3.20.0)

# Register ret-client as a module whether or not the active west manifest
# lists it.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ret_lora_gateway_bench)

# The gateway's own path stores, driven by a fixed workload.
target_sources(app PRIVATE src/main.c)
target_sources_ifdef(CONFIG_RET_GATEWAY_STORE_LFS app PRIVATE ../src/store_lfs.c)
target_sources_ifdef(CONFIG_RET_GATEWAY_STORE_ZMS app PRIVATE ../src/store_zms.c)
target_include_directories(app PRIVATE ../src ../../../src)
