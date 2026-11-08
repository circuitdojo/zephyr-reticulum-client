/*
 * Copyright (c) 2025-2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Board peripheral power management for the nRF9151 Feather (from
 * lion-client/samples/lion_sleep).
 * Based on nfed/samples/active_sleep.
 */

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/pm/device.h>

#if IS_ENABLED(CONFIG_REGULATOR_NPM13XX)
#include <zephyr/drivers/mfd/npm13xx.h>
#endif

#include "peripherals.h"

LOG_MODULE_REGISTER(peripherals, LOG_LEVEL_INF);

/* ── NPM1300 PMIC registers ──
 * The regulator framework will not disable BUCK2, so drive the PMIC
 * enable/pulldown registers directly over I2C via the MFD driver.
 * Mirrors nfed/samples/active_sleep.
 */
#if IS_ENABLED(CONFIG_REGULATOR_NPM13XX)
#define NPM1300_BUCK_BASE            0x04U
#define NPM1300_BUCK2_OFFSET_EN_SET  0x02U
#define NPM1300_BUCK2_OFFSET_EN_CLR  0x03U
#define NPM1300_BUCK_BUCKCTRL0       0x15U
#define NPM1300_BUCK2_PULLDOWN_EN    BIT(3)

static const struct device *pmic = DEVICE_DT_GET(DT_NODELABEL(npm1300_pmic));
#endif

/* ── GPIO ── */
static const struct gpio_dt_spec sw0 = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

/* ── SPI NOR Flash ── */

static const struct device *spi_nor = DEVICE_DT_GET(DT_ALIAS(ext_flash));

static void nor_suspend(void)
{
	int err = pm_device_action_run(spi_nor, PM_DEVICE_ACTION_SUSPEND);
	if (err) {
		LOG_WRN("Failed to suspend SPI NOR: %d", err);
	}
}

static void nor_resume(void)
{
	int err = pm_device_action_run(spi_nor, PM_DEVICE_ACTION_RESUME);
	if (err) {
		LOG_WRN("Failed to resume SPI NOR: %d", err);
	}
}

/* ── UART Console ── */

static const struct device *console_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static void uart_suspend(void)
{
	/* The UARTE async PM handler asserts RX is already stopped — it will
	 * NOT stop it. Disable RX explicitly first so the driver state is
	 * consistent before we pull the peripheral down. */
	uart_rx_disable(console_dev);
	k_sleep(K_MSEC(2)); /* wait for RXTO event to settle in the driver */

	int err = pm_device_action_run(console_dev, PM_DEVICE_ACTION_SUSPEND);
	if (err) {
		LOG_WRN("Failed to suspend UART: %d", err);
	}
}

static void uart_resume(void)
{
	int err = pm_device_action_run(console_dev, PM_DEVICE_ACTION_RESUME);
	if (err) {
		LOG_WRN("Failed to resume UART: %d", err);
	}
}

/* ── PMIC (nRF9151/nRF9161 only) ── */

#if IS_ENABLED(CONFIG_REGULATOR_NPM13XX)
static void pmic_suspend(void)
{
	int err;

	/* Enable BUCK2 pulldown so the rail collapses cleanly once disabled */
	err = mfd_npm13xx_reg_update(pmic, NPM1300_BUCK_BASE,
				     NPM1300_BUCK_BUCKCTRL0,
				     NPM1300_BUCK2_PULLDOWN_EN,
				     NPM1300_BUCK2_PULLDOWN_EN);
	if (err) {
		LOG_WRN("Failed to enable BUCK2 pulldown: %d", err);
	}

	/* Disable BUCK2 via the enable-clear register */
	err = mfd_npm13xx_reg_write(pmic, NPM1300_BUCK_BASE,
				    NPM1300_BUCK2_OFFSET_EN_CLR, 0x01);
	if (err) {
		LOG_WRN("Failed to disable BUCK2: %d", err);
	}
}

static void pmic_resume(void)
{
	int err;

	/* Re-enable BUCK2 via the enable-set register */
	err = mfd_npm13xx_reg_write(pmic, NPM1300_BUCK_BASE,
				    NPM1300_BUCK2_OFFSET_EN_SET, 0x01);
	if (err) {
		LOG_WRN("Failed to enable BUCK2: %d", err);
	}

	/* Release the pulldown now that the rail is driven again */
	err = mfd_npm13xx_reg_update(pmic, NPM1300_BUCK_BASE,
				     NPM1300_BUCK_BUCKCTRL0,
				     NPM1300_BUCK2_PULLDOWN_EN, 0);
	if (err) {
		LOG_WRN("Failed to release BUCK2 pulldown: %d", err);
	}
}
#endif /* CONFIG_REGULATOR_NPM13XX */

/* ── Public API ── */

void peripherals_suspend(void)
{
	/* Disconnect switch GPIO to avoid leakage */
	gpio_pin_configure_dt(&sw0, GPIO_DISCONNECTED);

	nor_suspend();
	uart_suspend();

#if IS_ENABLED(CONFIG_REGULATOR_NPM13XX)
	pmic_suspend();
#endif
}

void peripherals_resume(void)
{
	/* Bring BUCK2 back first and let the rail settle before driving the
	 * UART pins or NOR, both of which may sit on that rail. Re-enabling
	 * the console while BUCK2 is still ramping can glitch the supply. */
#if IS_ENABLED(CONFIG_REGULATOR_NPM13XX)
	pmic_resume();
	k_msleep(20);
#endif

	uart_resume();
	nor_resume();
}
