cmake_minimum_required(VERSION 3.20.0)

# Register ret-client as a module whether or not the active west manifest
# lists it. Zephyr keys modules by name, so this is harmless when west
# already provides it.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ret_basic)

target_sources(app PRIVATE src/main.c)

if(CONFIG_NRF_MODEM_LIB)
    target_sources(app PRIVATE src/network_modem.c)
else()
    target_sources(app PRIVATE src/network_sim.c)
endif()
