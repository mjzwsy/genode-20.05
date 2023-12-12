/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <asm/errno.h>
#include <asm/imx-common/video.h>
#include <asm/io.h>

/* ldb */
#define LDB_BGREF_RMODE_MASK            0x00008000
#define LDB_BGREF_RMODE_INT             0x00008000
#define LDB_BGREF_RMODE_EXT             0x0

#define LDB_DI1_VS_POL_MASK             0x00000400
#define LDB_DI1_VS_POL_ACT_LOW          0x00000400
#define LDB_DI1_VS_POL_ACT_HIGH         0x0
#define LDB_DI0_VS_POL_MASK             0x00000200
#define LDB_DI0_VS_POL_ACT_LOW          0x00000200
#define LDB_DI0_VS_POL_ACT_HIGH         0x0

#define LDB_BIT_MAP_CH1_MASK            0x00000100
#define LDB_BIT_MAP_CH1_JEIDA           0x00000100
#define LDB_BIT_MAP_CH1_SPWG            0x0
#define LDB_BIT_MAP_CH0_MASK            0x00000040
#define LDB_BIT_MAP_CH0_JEIDA           0x00000040
#define LDB_BIT_MAP_CH0_SPWG            0x0

#define LDB_DATA_WIDTH_CH1_MASK         0x00000080
#define LDB_DATA_WIDTH_CH1_24           0x00000080
#define LDB_DATA_WIDTH_CH1_18           0x0
#define LDB_DATA_WIDTH_CH0_MASK         0x00000020
#define LDB_DATA_WIDTH_CH0_24           0x00000020
#define LDB_DATA_WIDTH_CH0_18           0x0

#define LDB_CH1_MODE_MASK               0x0000000C
#define LDB_CH1_MODE_EN_TO_DI1          0x0000000C
#define LDB_CH1_MODE_EN_TO_DI0          0x00000004
#define LDB_CH1_MODE_DISABLE            0x0
#define LDB_CH0_MODE_MASK               0x00000003
#define LDB_CH0_MODE_EN_TO_DI1          0x00000003
#define LDB_CH0_MODE_EN_TO_DI0          0x00000001
#define LDB_CH0_MODE_DISABLE            0x0

#define LDB_SPLIT_MODE_EN               0x00000010
/* ldb */

int board_video_skip(void)
{
	int i;
	int ret,reg;
	setenv("splashpos", "m,m");
        char *option = getenv("mxcfb0");
        char *options;
        char panel[32] = {0};
        char dev_option[16] = {0};
        char if_fmt_option[16] = {0};
        char *opt;
	int lvds_num, bpp, lvds_spl, lvds_dul;
	char *lvds_mode = getenv("ldb_mode");
	static int ipu_pix_fmt = IPU_PIX_FMT_RGB24;

        if(strlen(option) < 13) {
                printf("***mxcfb0 is error! don't show logo at boot!\n");
                return -EINVAL;
        }

        /*
        * set fb_videomode from env mxcfb0
        */
        options = strdup(option) + 13;
        /* remove video=mxcfb0: from mxcfb0 env string*/
        /* get char *mode_option, *dev_option, *if_fmt_option */
        while ((opt = strsep(&options, ",")) != NULL) {
                if (!*opt)
                        continue;
                if (!strncmp(opt, "dev=", 4))
                        memcpy(dev_option, opt + 4, strlen(opt) - 4);
                else if (!strncmp(opt, "if=", 3))
                        memcpy(if_fmt_option, opt + 3, strlen(opt) - 3);
                else if (!strncmp(opt, "fbpix=", 6) || !strncmp(opt, "int_clk", 7) || !strncmp(opt, "bpp=", 4))
                        continue;
                else
                        memcpy(panel, opt, strlen(opt));
        }

        if(!strcmp(lvds_mode, "ldb=sin1") || !strcmp(lvds_mode, "ldb=sep1") ||
                                !strcmp(lvds_mode, "ldb=dul1") || !strcmp(lvds_mode, "ldb=spl1"))
                lvds_num = 1;
        else
                lvds_num = 0;
        if(!strcmp(lvds_mode, "ldb=spl0") || !strcmp(lvds_mode, "ldb=spl1"))
                lvds_spl = 1;
        else
                lvds_spl = 0;
        if(!strcmp(lvds_mode, "ldb=dul0") || !strcmp(lvds_mode, "ldb=dul1"))
                lvds_dul = 1;
        else
                lvds_dul = 0;

	if (!panel) {
		printf("No panel detected: default to %s\n", panel);
		i = 0;
	} else {
		for (i = 0; i < display_count; i++) {
			if (!strcmp(panel, displays[i].mode.name))
				break;
		}
	}

        if(i >= display_count) {
                /* set dev */
                if (!strncmp(dev_option, "lcd", 3)) {
                        i = 3;
                        ret = fb_find_mode(panel, &displays[i].mode);
                        if(!ret) {
                                printf("***screen mode is not found! don't show logo at boot!\n");
                                setenv("fb0base",NULL);
                                return EINVAL;
                        }
                }
                if (!strncmp(dev_option, "ldb", 3)) {
                        i = 0;
                        ret = fb_find_mode(panel, &displays[i].mode);
                        if(!ret) {
                                printf("***screen mode is not found! don't show logo at boot!\n");
                                setenv("fb0base",NULL);
                                return EINVAL;
                        }
                        displays[i].mode.sync = FB_SYNC_EXT;

			ipu_pix_fmt = displays[i].pixfmt;

	                reg = (LDB_DI1_VS_POL_ACT_LOW | LDB_DI0_VS_POL_ACT_LOW);
        	        if(lvds_dul) {
                	        if (lvds_num == 1)
                        	        reg |=  (LDB_CH0_MODE_EN_TO_DI1 | LDB_CH1_MODE_EN_TO_DI1);
                        	else
                                	reg |=  (LDB_CH0_MODE_EN_TO_DI0 | LDB_CH1_MODE_EN_TO_DI0);

	                        if(ipu_pix_fmt == IPU_PIX_FMT_RGB24)
        	                        reg |= (LDB_DATA_WIDTH_CH1_24 | LDB_DATA_WIDTH_CH0_24);

                	} else if (lvds_spl) {
                        	if (lvds_num == 1)
                                	reg |= (LDB_CH1_MODE_EN_TO_DI1 | LDB_CH1_MODE_EN_TO_DI1 | LDB_SPLIT_MODE_EN);
	                        else
	                                reg |= (LDB_CH0_MODE_EN_TO_DI0 | LDB_CH1_MODE_EN_TO_DI0 | LDB_SPLIT_MODE_EN);
	
	                        reg |= (LDB_DATA_WIDTH_CH1_24 | LDB_DATA_WIDTH_CH0_24);
	
	                } else  {
	                        if (lvds_num == 1)
	                                if(ipu_pix_fmt == IPU_PIX_FMT_RGB24)
	                                        reg |= (LDB_CH1_MODE_EN_TO_DI1 | LDB_DATA_WIDTH_CH1_24);
	                                else
	                                        reg |= LDB_CH1_MODE_EN_TO_DI1;
	                        else
	                                if(ipu_pix_fmt == IPU_PIX_FMT_RGB24)
	                                        reg |= (LDB_CH0_MODE_EN_TO_DI0 | LDB_DATA_WIDTH_CH0_24);
	                                else
	                                        reg |= LDB_CH0_MODE_EN_TO_DI0;
	                }

        	        writel(reg, IOMUXC_BASE_ADDR + 0x8);

                }
                if (!strncmp(dev_option, "mipi_dsi", 8)) {
                        printf("***screen mode is not found! don't show logo at boot!\n");
                        setenv("fb0base",NULL);
                        return EINVAL;
                }
        }

	if (i < display_count) {
#if defined(CONFIG_VIDEO_IPUV3)
		ret = ipuv3_fb_init(&displays[i].mode, 0,
				    displays[i].pixfmt);
#elif defined(CONFIG_VIDEO_MXS)
		ret = mxs_lcd_panel_setup(displays[i].mode,
					displays[i].pixfmt,
				    displays[i].bus);
#endif
		if (!ret) {
			if (displays[i].enable)
				displays[i].enable(displays + i);

			printf("Display: %s (%ux%u)\n",
			       displays[i].mode.name,
			       displays[i].mode.xres,
			       displays[i].mode.yres);
		} else
			printf("LCD %s cannot be configured: %d\n",
			       displays[i].mode.name, ret);
	}

	return 0;
}

#ifdef CONFIG_IMX_HDMI
#include <asm/arch/mxc_hdmi.h>
#include <asm/io.h>
int detect_hdmi(struct display_info_t const *dev)
{
	struct hdmi_regs *hdmi	= (struct hdmi_regs *)HDMI_ARB_BASE_ADDR;
	return readb(&hdmi->phy_stat0) & HDMI_DVI_STAT;
}
#endif
