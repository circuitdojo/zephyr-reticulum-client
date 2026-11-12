cmake_minimum_required(VERSION 3.20.0)

# Register ret-client as a module whether or not the active west manifest
# lists it.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ret_lora_gateway)

target_sources(app PRIVATE src/main.c src/radio_task.c src/uplink.c src/store_zms.c)
# A transport node uses the library's internals, not the client API.
target_include_directories(app PRIVATE ../../src)

if(CONFIG_BOARD_NATIVE_SIM)
    target_sources(app PRIVATE src/network_sim.c src/radio_sim.c)
else()
    # The Feather: LTE through the modem, an SX1262 through Zephyr's LoRa API.
    target_sources(app PRIVATE src/network_modem.c src/radio_lora.c)
endif()
