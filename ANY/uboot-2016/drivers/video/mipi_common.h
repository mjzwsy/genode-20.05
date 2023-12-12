/* Copyright (C) 2012-2013 Freescale Semiconductor, Inc.
 * This file is the header file for MIPI DSI, the addr of MIPI DSI regs
 */

#define    MIPI_DSI_IPS_BASE_ADDR                  0x21e0000
#define    OFFSET_DSI_VERSION                      0x000
#define    OFFSET_DSI_PWR_UP                       0x004
#define    OFFSET_DSI_CLKMGR_CFG                   0x008
#define    OFFSET_DSI_DPI_CFG                      0x00c
#define    OFFSET_DSI_DBI_CFG                      0x010
#define    OFFSET_DSI_DBI_CMDSIZE                  0x014
#define    OFFSET_DSI_PCKHDL_CFG                   0x018
#define    OFFSET_DSI_VID_MODE_CFG                 0x01c
#define    OFFSET_DSI_VID_PKT_CFG                  0x020
#define    OFFSET_DSI_CMD_MODE_CFG                 0x024
#define    OFFSET_DSI_TMR_LINE_CFG                 0x028
#define    OFFSET_DSI_VTIMING_CFG                  0x02c
#define    OFFSET_DSI_TMR_CFG                      0x030
#define    OFFSET_DSI_GEN_HDR                      0x034
#define    OFFSET_DSI_GEN_PLD_DATA                 0x038
#define    OFFSET_DSI_CMD_PKT_STATUS               0x03c
#define    OFFSET_DSI_TO_CNT_CFG                   0x040
#define    OFFSET_DSI_ERROR_ST0                    0x044
#define    OFFSET_DSI_ERROR_ST1                    0x048
#define    OFFSET_DSI_ERROR_MSK0                   0x04c
#define    OFFSET_DSI_ERROR_MSK1                   0x050
#define    OFFSET_DSI_PHY_RSTZ                     0x054
#define    OFFSET_DSI_PHY_IF_CFG                   0x058
#define    OFFSET_DSI_PHY_IF_CTRL                  0x05c
#define    OFFSET_DSI_PHY_STATUS                   0x060
#define    OFFSET_DSI_PHY_TST_CTRL0                0x064
#define    OFFSET_DSI_PHY_TST_CTRL1                0x068

#define    OFFSET_DSI_DPHY_CTRL                    0xf00
#define    OFFSET_DSI_DPHY_STATUS                  0xf04
#define    OFFSET_DPHY_TEST_CTRL                   0xf14

#define    DSI_VERSION         (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_VERSION)
#define    DSI_PWR_UP          (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PWR_UP)
#define    DSI_CLKMGR_CFG      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_CLKMGR_CFG)
#define    DSI_DPI_CFG         (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_DPI_CFG)
#define    DSI_DBI_CFG         (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_DBI_CFG)
#define    DSI_DBI_CMDSIZE     (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_DBI_CMDSIZE)
#define    DSI_PCKHDL_CFG      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PCKHDL_CFG)
#define    DSI_VID_MODE_CFG    (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_VID_MODE_CFG)
#define    DSI_VID_PKT_CFG     (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_VID_PKT_CFG)
#define    DSI_CMD_MODE_CFG    (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_CMD_MODE_CFG)
#define    DSI_TMR_LINE_CFG    (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_TMR_LINE_CFG)
#define    DSI_VTIMING_CFG     (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_VTIMING_CFG)
#define    DSI_TMR_CFG         (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_TMR_CFG)
#define    DSI_GEN_HDR         (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_GEN_HDR)
#define    DSI_GEN_PLD_DATA    (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_GEN_PLD_DATA)
#define    DSI_CMD_PKT_STATUS  (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_CMD_PKT_STATUS)
#define    DSI_TO_CNT_CFG      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_TO_CNT_CFG)
#define    DSI_ERROR_ST0       (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_ERROR_ST0)
#define    DSI_ERROR_ST1       (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_ERROR_ST1)
#define    DSI_ERROR_MSK0      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_ERROR_MSK0)
#define    DSI_ERROR_MSK1      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_ERROR_MSK1)
#define    DSI_PHY_RSTZ        (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_RSTZ)
#define    DSI_PHY_IF_CFG      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_IF_CFG)
#define    DSI_PHY_IF_CTRL     (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_IF_CTRL)
#define    DSI_PHY_STATUS      (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_STATUS)
#define    DSI_PHY_TST_CTRL0   (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_TST_CTRL0)
#define    DSI_PHY_TST_CTRL1   (MIPI_DSI_IPS_BASE_ADDR + \
                                               OFFSET_DSI_PHY_TST_CTRL1)
#define    MIPI_DPHY_TEST_DSI_CTRL       (MIPI_DSI_IPS_BASE_ADDR + \
                                                       OFFSET_DSI_DPHY_CTRL)
#define    MIPI_DPHY_TEST_DSI_STATUS     (MIPI_DSI_IPS_BASE_ADDR + \
                                                       OFFSET_DSI_DPHY_STATUS)
#define    MIPI_DPHY_TEST_CTRL            (MIPI_DSI_IPS_BASE_ADDR + \
                                                       OFFSET_DPHY_TEST_CTRL)

int LCD_ICINIT(void);

#ifdef CONFIG_VIDEO_MX5
#if MIPI_DSI
extern unsigned char fsl_bmp_reversed_mipi_480x800[];
extern int fsl_bmp_reversed_mipi_480x800_size;
#endif
#endif
