#
# (C) Copyright 2000-2007
# Wolfgang Denk, DENX Software Engineering, wd@denx.de.
#
# SPDX-License-Identifier:	GPL-2.0+
#

ifdef CONFIG_DM
obj-$(CONFIG_DISPLAY) += display-uclass.o
obj-$(CONFIG_DM_VIDEO) += backlight-uclass.o
obj-$(CONFIG_DM_VIDEO) += panel-uclass.o simple_panel.o
obj-$(CONFIG_DM_VIDEO) += video-uclass.o vidconsole-uclass.o
obj-$(CONFIG_DM_VIDEO) += video_bmp.o
ifdef CONFIG_DM_VIDEO
obj-$(CONFIG_DM_PWM) += pwm_backlight.o
endif
obj-$(CONFIG_CONSOLE_NORMAL) += console_normal.o
obj-$(CONFIG_CONSOLE_ROTATION) += console_rotate.o
obj-$(CONFIG_CONSOLE_TRUETYPE) += console_truetype.o fonts/
endif

obj-$(CONFIG_ATI_RADEON_FB) += ati_radeon_fb.o videomodes.o
obj-$(CONFIG_ATMEL_HLCD) += atmel_hlcdfb.o
obj-$(CONFIG_ATMEL_LCD) += atmel_lcdfb.o
obj-$(CONFIG_CFB_CONSOLE) += cfb_console.o
obj-$(CONFIG_EXYNOS_DP) += exynos_dp.o exynos_dp_lowlevel.o
obj-$(CONFIG_EXYNOS_FB) += exynos_fb.o exynos_fimd.o
obj-$(CONFIG_EXYNOS_MIPI_DSIM) += exynos_mipi_dsi.o exynos_mipi_dsi_common.o \
				exynos_mipi_dsi_lowlevel.o
obj-$(CONFIG_EXYNOS_PWM_BL) += exynos_pwm_bl.o
obj-$(CONFIG_FSL_DIU_FB) += fsl_diu_fb.o videomodes.o
obj-$(CONFIG_FSL_DCU_FB) += fsl_dcu_fb.o videomodes.o
obj-$(CONFIG_L5F31188) += l5f31188.o
obj-$(CONFIG_MPC8XX_LCD) += mpc8xx_lcd.o
obj-$(CONFIG_PXA_LCD) += pxa_lcd.o
obj-$(CONFIG_SCF0403_LCD) += scf0403_lcd.o
obj-$(CONFIG_S6E8AX0) += s6e8ax0.o
obj-$(CONFIG_S6E63D6) += s6e63d6.o
obj-$(CONFIG_LD9040) += ld9040.o
obj-$(CONFIG_SED156X) += sed156x.o
obj-$(CONFIG_VIDEO_BCM2835) += bcm2835.o
obj-$(CONFIG_VIDEO_COREBOOT) += coreboot_fb.o
obj-$(CONFIG_VIDEO_CT69000) += ct69000.o videomodes.o
obj-$(CONFIG_VIDEO_DA8XX) += da8xx-fb.o videomodes.o
obj-$(CONFIG_VIDEO_IMX25LCDC) += imx25lcdc.o videomodes.o
obj-$(CONFIG_VIDEO_LCD_ANX9804) += anx9804.o
obj-$(CONFIG_VIDEO_LCD_HITACHI_TX18D42VM) += hitachi_tx18d42vm_lcd.o
obj-$(CONFIG_VIDEO_LCD_SSD2828) += ssd2828.o
obj-$(CONFIG_VIDEO_MB862xx) += mb862xx.o videomodes.o
obj-$(CONFIG_VIDEO_MX3) += mx3fb.o videomodes.o
obj-$(CONFIG_VIDEO_IPUV3) += mxc_ipuv3_fb.o ipu_common.o ipu_disp.o lcd_config.o
obj-$(CONFIG_VIDEO_MVEBU) += mvebu_lcd.o
obj-$(CONFIG_VIDEO_MXS) += mxsfb.o videomodes.o
obj-$(CONFIG_VIDEO_OMAP3) += omap3_dss.o
obj-$(CONFIG_VIDEO_S3C) += s3c-fb.o videomodes.o
obj-$(CONFIG_VIDEO_SANDBOX_SDL) += sandbox_sdl.o
obj-$(CONFIG_VIDEO_SED13806) += sed13806.o
obj-$(CONFIG_VIDEO_SM501) += sm501.o
obj-$(CONFIG_VIDEO_SMI_LYNXEM) += smiLynxEM.o videomodes.o
obj-$(CONFIG_VIDEO_SUNXI) += sunxi_display.o videomodes.o
obj-$(CONFIG_VIDEO_TEGRA20) += tegra.o
obj-$(CONFIG_VIDEO_VCXK) += bus_vcxk.o
obj-$(CONFIG_VIDEO_VESA) += vesa_fb.o
obj-$(CONFIG_FORMIKE) += formike.o
obj-$(CONFIG_LG4573) += lg4573.o
obj-$(CONFIG_AM335X_LCD) += am335x-fb.o

obj-${CONFIG_VIDEO_TEGRA124} += tegra124/
obj-${CONFIG_VIDEO_ROCKCHIP} += rockchip/
obj-$(CONFIG_MXC_EPDC) += mxc_epdc_fb.o
obj-$(CONFIG_VIDEO_VADC) += mxc_vadc.o
obj-$(CONFIG_VIDEO_CSI) += mxc_csi.o
obj-$(CONFIG_VIDEO_PXP) += mxc_pxp.o
obj-$(CONFIG_VIDEO_GIS) += mxc_gis.o
obj-y                  += modedb.o
obj-y                  += fbcvt.o

obj-y += bridge/
