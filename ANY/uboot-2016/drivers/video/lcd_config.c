/*
 * (C) Copyright 2012-2013 Freescale Semiconductor, Inc.
 */

#include "mipi_common.h"
#include <asm/io.h>
#include <common.h>
#define MIPI_DSI_MAX_RET_PACK_SIZE                              (0x4)
#define MIPI_DSI_SET_MAXIMUM_RETURN_PACKET_SIZE                 (0x37)

#define EK79007BL_MAX_BRIGHT     (255)
#define EK79007BL_DEF_BRIGHT     (255)

#define EK79007_MAX_DPHY_CLK                                    (680)
#define EK79007_TWO_DATA_LANE                                   (0x2)

#define EK79007_CMD_CTRL_RESET                  (0x01)
#define EK79007_CMD_CTRL_RESET_PARAM_1          (0x00)

#define EK79007_CMD_GETPOWER_MODE                           (0x0A)
#define EK79007_CMD_GETPOWER_MODE_LEN                   (0x1)

#define EK79007_CMD_SETGAMMA0                                   (0x80)
#define EK79007_CMD_SETGAMMA0_PARAM_1           (0x47)

#define EK79007_CMD_SETGAMMA1                   (0x81)
#define EK79007_CMD_SETGAMMA1_PARAM_1           (0x40)

#define EK79007_CMD_SETGAMMA2                   (0x82)
#define EK79007_CMD_SETGAMMA2_PARAM_1           (0x04)

#define EK79007_CMD_SETGAMMA3                   (0x83)
#define EK79007_CMD_SETGAMMA3_PARAM_1           (0x77)

#define EK79007_CMD_SETGAMMA4                   (0x84)
#define EK79007_CMD_SETGAMMA4_PARAM_1           (0x0f)

#define EK79007_CMD_SETGAMMA5                   (0x85)
#define EK79007_CMD_SETGAMMA5_PARAM_1           (0x70)

#define EK79007_CMD_SETGAMMA6                   (0x86)
#define EK79007_CMD_SETGAMMA6_PARAM_1           (0x70)

#define EK79007_CMD_SETPANEL1                                   (0xB2)
#define EK79007_CMD_SETPANEL1_TWOLANE           (0x1 << 4)


#define CHECK_RETCODE(ret)                                     \
do {                                                           \
       if (ret < 0) {                                          \
                       printf("%s ERR: ret:%d, line:%d.\n",            \
                       __func__, ret, __LINE__);               \
               return ret;                                     \
       }                                                       \
} while (0)

#define MIPI_DSI_GEN_PLD_DATA (0x038)
#define MIPI_DSI_CMD_PKT_STATUS (0x03c)
#define MIPI_DSI_GEN_HDR (0x034)
#define DSI_GEN_PLD_DATA_BUF_ENTRY (10)
#define MIPI_DSI_GENERIC_READ_REQUEST_1_PARAM 0x13
#define DSI_CMD_PKT_STATUS_GEN_PLD_R_EMPTY (0x1<<4)
#define DSI_CMD_PKT_STATUS_GEN_RD_CMD_BUSY (0x1<<6)
#define DSI_CMD_PKT_STATUS_GEN_PLD_W_FULL (0x1<<3)
#define DSI_CMD_PKT_STATUS_GEN_CMD_FULL (0x1<<1)
#define DSI_CMD_PKT_STATUS_GEN_CMD_EMPTY (0x1<<0)
#define DSI_CMD_PKT_STATUS_GEN_PLD_W_EMPTY (0x1<<2)
#define DSI_GEN_PLD_DATA_BUF_SIZE (0x4)
#define MIPI_DSI_REG_RW_TIMEOUT (20)
#define DSI_GEN_HDR_DATA_MASK (0xffff)
#define DSI_GEN_HDR_DATA_SHIFT (8)
#define MIPI_DSI_GENERIC_LONG_WRITE (0x29)
#define MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM (0x23)
#define MIPI_DCS_EXIT_SLEEP_MODE (0x11)
#define MIPI_DSI_GENERIC_SHORT_WRITE_1_PARAM (0x13)
#define MIPI_DCS_SET_DISPLAY_ON (0x29)

static void
msleep(int count)
{
       int i;

       for (i = 0; i < count; i++)
               udelay(1000);
}
void
mipi_dsi_write_register(u32 reg, u32 val)
{
       writel(val, MIPI_DSI_IPS_BASE_ADDR + reg);
}

void mipi_dsi_read_register(u32 reg, u32 *val)
{
       *val = readl(MIPI_DSI_IPS_BASE_ADDR + reg);
}
#if 0
int mipi_dsi_pkt_read(u8 data_type, u32 *buf, int len)
{
        u32             val;
        int             read_len = 0;
        uint32_t        timeout = 0;

        if (!len) {
                return -1;
        }

        val = data_type | ((*buf & DSI_GEN_HDR_DATA_MASK)
                << DSI_GEN_HDR_DATA_SHIFT);
        memset(buf, 0, len);
        mipi_dsi_write_register( MIPI_DSI_GEN_HDR, val);

        /* wait for cmd to sent out */
        mipi_dsi_read_register( MIPI_DSI_CMD_PKT_STATUS, &val);
        while ((val & DSI_CMD_PKT_STATUS_GEN_RD_CMD_BUSY) !=
                         DSI_CMD_PKT_STATUS_GEN_RD_CMD_BUSY) {
                msleep(1);
                timeout++;
                if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                        return -1;
                mipi_dsi_read_register( MIPI_DSI_CMD_PKT_STATUS,
                        &val);
        }
        /* wait for entire response stroed in FIFO */
        while ((val & DSI_CMD_PKT_STATUS_GEN_RD_CMD_BUSY) ==
                         DSI_CMD_PKT_STATUS_GEN_RD_CMD_BUSY) {
                msleep(1);
                timeout++;
                if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                        return -2;
                mipi_dsi_read_register( MIPI_DSI_CMD_PKT_STATUS,
                        &val);
        }

        mipi_dsi_read_register( MIPI_DSI_CMD_PKT_STATUS, &val);
        while (!(val & DSI_CMD_PKT_STATUS_GEN_PLD_R_EMPTY)) {
                mipi_dsi_read_register( MIPI_DSI_GEN_PLD_DATA, buf);
                read_len += DSI_GEN_PLD_DATA_BUF_SIZE;
                buf++;
                mipi_dsi_read_register( MIPI_DSI_CMD_PKT_STATUS,
                        &val);
                if (read_len == (DSI_GEN_PLD_DATA_BUF_ENTRY *
                                        DSI_GEN_PLD_DATA_BUF_SIZE))
                        break;
        }
   // printk("read mipi lcd reg read_len=%x\n",read_len);
        if ((len <= read_len) &&
                ((len + DSI_GEN_PLD_DATA_BUF_SIZE) >= read_len))
                return 0;
        else {
                return -3;
        }
}
#endif

int mipi_dsi_pkt_write(u8 data_type, const u32 *buf, int len)
{
       u32 val;
       u32 status = 0;
       int write_len = len;
       uint32_t        timeout = 0;

       if (len) {
               /* generic long write command */
               while (len / DSI_GEN_PLD_DATA_BUF_SIZE) {
                       mipi_dsi_write_register(MIPI_DSI_GEN_PLD_DATA, *buf);
                       buf++;
                       len -= DSI_GEN_PLD_DATA_BUF_SIZE;
                       mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS,
                                                               &status);
                       while ((status & DSI_CMD_PKT_STATUS_GEN_PLD_W_FULL) ==
                                        DSI_CMD_PKT_STATUS_GEN_PLD_W_FULL) {
                               msleep(1);
                               timeout++;
                               if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                                       return -1;
                               mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS,
                                                               &status);
                       }
               }
               /* write the remainder bytes */
               if (len > 0) {
                       while ((status & DSI_CMD_PKT_STATUS_GEN_PLD_W_FULL) ==
                                        DSI_CMD_PKT_STATUS_GEN_PLD_W_FULL) {
                               msleep(1);
                               timeout++;
                               if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                                       return -1;
                               mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS,
                                                               &status);
                       }
                       mipi_dsi_write_register(MIPI_DSI_GEN_PLD_DATA, *buf);
               }

               val = data_type | ((write_len & DSI_GEN_HDR_DATA_MASK)
                       << DSI_GEN_HDR_DATA_SHIFT);
       } else {
               /* generic short write command */
               val = data_type | ((*buf & DSI_GEN_HDR_DATA_MASK)
                       << DSI_GEN_HDR_DATA_SHIFT);
       }

       mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS, &status);
       while ((status & DSI_CMD_PKT_STATUS_GEN_CMD_FULL) ==
                        DSI_CMD_PKT_STATUS_GEN_CMD_FULL) {
               msleep(1);
               timeout++;
               if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                       return -1;
               mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS,
                               &status);
       }
       mipi_dsi_write_register(MIPI_DSI_GEN_HDR, val);

       mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS, &status);
       while (!((status & DSI_CMD_PKT_STATUS_GEN_CMD_EMPTY) ==
                        DSI_CMD_PKT_STATUS_GEN_CMD_EMPTY) ||
                       !((status & DSI_CMD_PKT_STATUS_GEN_PLD_W_EMPTY) ==
                       DSI_CMD_PKT_STATUS_GEN_PLD_W_EMPTY)) {
               msleep(1);
               timeout++;
               if (timeout == MIPI_DSI_REG_RW_TIMEOUT)
                       return -1;
               mipi_dsi_read_register(MIPI_DSI_CMD_PKT_STATUS,
                               &status);
       }
       return 0;
}

/************* Initial LCD Driver ****************/
int LCD_ICINIT(void)
{
       	int err;
       	u32 buf[32];

	//reset the panel,other operation must after 50ms 
        buf[0] = EK79007_CMD_CTRL_RESET;
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_1_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
    	msleep(50);
	//set the max size of return packet size.
        buf[0] = MIPI_DSI_MAX_RET_PACK_SIZE;
        err = mipi_dsi_pkt_write(
                                MIPI_DSI_SET_MAXIMUM_RETURN_PACKET_SIZE,
                                buf, 0);
        CHECK_RETCODE(err);

	//set gamma curve related setting
        /* Set gamma curve related setting */
    	buf[0] = EK79007_CMD_SETGAMMA0 |
                ( EK79007_CMD_SETGAMMA0_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA1 |
                ( EK79007_CMD_SETGAMMA1_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA2 |
                ( EK79007_CMD_SETGAMMA2_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA3 |
                ( EK79007_CMD_SETGAMMA3_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA4 |
                ( EK79007_CMD_SETGAMMA4_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA5 |
                ( EK79007_CMD_SETGAMMA5_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        buf[0] = EK79007_CMD_SETGAMMA6 |
                ( EK79007_CMD_SETGAMMA6_PARAM_1 << 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);

	//set the data num lane of the lcd panel
	/*2 lane */
        buf[0] = EK79007_CMD_SETPANEL1 |
                (EK79007_CMD_SETPANEL1_TWOLANE<< 8);
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_2_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
    	msleep(2);
  	/* exit sleep mode and set display on */
        buf[0] = MIPI_DCS_EXIT_SLEEP_MODE;
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_1_PARAM,
                buf, 0);
        CHECK_RETCODE(err);
        /* To allow time for the supply voltages
         * and clock circuits to stabilize.
         */
        msleep(5);
        buf[0] = MIPI_DCS_SET_DISPLAY_ON;
        err = mipi_dsi_pkt_write( MIPI_DSI_GENERIC_SHORT_WRITE_1_PARAM,
                buf, 0);
        CHECK_RETCODE(err);

       return err;
}
