/*
 * Copyright (c) 2025-2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PERIPHERALS_H_
#define PERIPHERALS_H_

/**
 * Suspend all board peripherals for low-power sleep.
 *
 * Disconnects the button GPIO, suspends the SPI NOR flash and the UART
 * console, and disables PMIC BUCK2 (nRF9151).
 */
void peripherals_suspend(void);

/**
 * Resume board peripherals after low-power sleep.
 *
 * Re-enables PMIC BUCK2 (first, letting the rail settle), the UART
 * console and the SPI NOR flash.
 */
void peripherals_resume(void);

#endif /* PERIPHERALS_H_ */
