/*
 * (C) Copyright 2008 Texas Insturments
 *
 * (C) Copyright 2002
 * Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Marius Groeger <mgroeger@sysgo.de>
 *
 * (C) Copyright 2002
 * Gary Jennejohn, DENX Software Engineering, <garyj@denx.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/*
 * CPU specific code
 */

#include <common.h>
#include <command.h>
#include <asm/system.h>
#include <asm/cache.h>
#include <asm/armv7.h>
#include <linux/compiler.h>
#include <asm/arch/iomux.h>
#include <asm/arch/mx6-pins.h>
#include <asm/gpio.h>

void __weak cpu_cache_initialization(void){}

int cleanup_before_linux_select(int flags)
{
	/*
	 * this function is called just before we call linux
	 * it prepares the processor for linux
	 *
	 * we turn off caches etc ...
	 */
#ifndef CONFIG_SPL_BUILD
	disable_interrupts();
#endif

	if (flags & CBL_DISABLE_CACHES) {
		/*
		* turn off D-cache
		* dcache_disable() in turn flushes the d-cache and disables MMU
		*/
		dcache_disable();
		v7_outer_cache_disable();

		/*
		* After D-cache is flushed and before it is disabled there may
		* be some new valid entries brought into the cache. We are
		* sure that these lines are not dirty and will not affect our
		* execution. (because unwinding the call-stack and setting a
		* bit in CP15 SCTRL is all we did during this. We have not
		* pushed anything on to the stack. Neither have we affected
		* any static data) So just invalidate the entire d-cache again
		* to avoid coherency problems for kernel
		*/
		invalidate_dcache_all();

		icache_disable();
		invalidate_icache_all();
	} else {
		/*
		 * Turn off I-cache and invalidate it
		 */
		icache_disable();
		invalidate_icache_all();

		flush_dcache_all();
		invalidate_icache_all();
		icache_enable();
	}

	/*
	 * Some CPU need more cache attention before starting the kernel.
	 */
	cpu_cache_initialization();

	return 0;
}

int cleanup_before_linux(void)
{
#if 1
	/* close LCD blacklight */
	gpio_direction_output(IMX_GPIO_NR(1, 21), 0);
	gpio_direction_output(IMX_GPIO_NR(1, 17), 0);
	  /* EIM_A22 - GPIO2[16] for EPD PWR CTL0 */
        imx_iomux_v3_setup_pad(MX6_PAD_EIM_A22__GPIO2_IO16  | MUX_PAD_CTRL(NO_PAD_CTRL)); 
        imx_iomux_v3_setup_pad(MX6_PAD_NANDF_ALE__GPIO6_IO08 | MUX_PAD_CTRL(NO_PAD_CTRL)); 
        /* Set as output */
        gpio_direction_output(IMX_GPIO_NR(2, 16), 0);
        gpio_direction_output(IMX_GPIO_NR(6, 8), 1);
	udelay(2000);
        gpio_direction_output(IMX_GPIO_NR(2, 16), 1);
	udelay(20000);
        gpio_direction_input(IMX_GPIO_NR(6, 8));
	  /* EIM_A22 - GPIO2[16] for EPD PWR CTL0 */
        imx_iomux_v3_setup_pad(MX6_PAD_DI0_PIN4__GPIO4_IO20  | MUX_PAD_CTRL(NO_PAD_CTRL)); 
        imx_iomux_v3_setup_pad(MX6_PAD_NANDF_CLE__GPIO6_IO07 | MUX_PAD_CTRL(NO_PAD_CTRL)); 
        /* Set as output */
        gpio_direction_output(IMX_GPIO_NR(6, 7), 0);
        gpio_direction_output(IMX_GPIO_NR(4, 20), 0);
	udelay(2000);
        gpio_direction_output(IMX_GPIO_NR(6, 7), 1);
	udelay(20000);
        gpio_direction_input(IMX_GPIO_NR(4, 20));
	extern void mipi_dsi_set_mode(int cmd_mode);
	if(strcmp("TRULY-EK79007-WVGA", getenv("panel")) == 0)
		mipi_dsi_set_mode(1);
#endif
	return cleanup_before_linux_select(CBL_ALL);
}
