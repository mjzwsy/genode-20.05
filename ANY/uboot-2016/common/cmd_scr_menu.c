#include <common.h>
#include <command.h>

int mxcfb0(void)
{
        char c;

        do
        {
                printf("AAAxAAA-B means Binch screen with AAAxAAA pixels\n");
                printf("---------------------screen type----------------------\n");
                printf("0 -- exit to upper menu\n");
                printf("1 -- 480x272-4.3-LCD\n");
                printf("2 -- 800x480-7-LCD\n");
                printf("3 -- 1024x600-7-LCD\n");
                printf("4 -- 1280x800-10-LVDS\n");
                printf("5 -- 1920x1080M@60-HDMI\n");
#ifdef CONFIG_MAIN_BOARD_IS_C
                printf("6 -- 1024x600-7-mipi\n");
#endif
		printf("O -- Off\n");
                printf("------------------------------------------------------\n");

        HERE:
                printf(":");
                c = getc();

                printf("%c\n",c);

                switch(c)
                {
                case '0':
                        return 0;
                        break;
                case '1':
                        setenv("panel","NHD-4.3-ATXI");
                        setenv("mxcfb0","video=mxcfb0:dev=lcd,NHD-4.3-ATXI,if=RGB24,bpp=16,int_clk");
                        break;
                case '2':
                        setenv("panel","CLAA-WVGA");
                        setenv("mxcfb0","video=mxcfb0:dev=lcd,CLAA-WVGA,if=RGB24,bpp=16,int_clk");
                        break;
                case '3':
                        setenv("panel","CLAA-WVGA-HD");
                        setenv("mxcfb0","video=mxcfb0:dev=lcd,CLAA-WVGA-HD,if=RGB24,bpp=16,int_clk");
                        break;
                case '4':
                        setenv("panel","LDB-WXGA");
                        setenv("mxcfb0","video=mxcfb0:dev=ldb,1280x800M@60,if=RGB24,bpp=16");
                        break;
                case '5':
                        //setenv("panel","HDMI");
                        setenv("mxcfb0","video=mxcfb0:dev=hdmi,1920x1080M@60,if=RGB24,bpp=16");
                        break;
#ifdef CONFIG_MAIN_BOARD_IS_C
                case '6':
                        setenv("panel","TRULY-EK79007-WVGA");
                        setenv("mxcfb0","video=mxcfb0:dev=mipi_dsi,TRULY-EK79007-WVGA,if=RGB24,bpp=16");
                        break;
#endif
                case 'O':
                        setenv("panel","");
                        setenv("mxcfb0","video=mxcfb0:off");
			break;
        default:
                        printf("incorrect number\n");
                        goto HERE;
                }

                if(saveenv())
                        printf("something error occured, please check the nand device!");

        }while(1);
}

int mxcfb1(void)
{
        char c;

        do
        {
                printf("AAAxAAA-B means Binch screen with AAAxAAA pixels\n");
                printf("---------------------screen type----------------------\n");
                printf("0 -- exit to upper menu\n");
		printf("1 -- 480x272-4.3-LCD\n");
                printf("2 -- 800x480-7-LCD\n");
                printf("3 -- 1024x600-7-LCD\n");
                printf("4 -- 1280x800-10-LVDS\n");
                printf("5 -- 1920x1080M@60-HDMI\n");
#ifdef CONFIG_MAIN_BOARD_IS_C
                printf("6 -- 1024x600-7-mipi\n");
#endif
                printf("O -- Off\n");
                printf("------------------------------------------------------\n");

        HERE:
                printf(":");
                c = getc();

                printf("%c\n",c);

                switch(c)
                {
                case '0':
                        return 0;
                        break;
                case '1':
			setenv("mxcfb1","video=mxcfb1:dev=lcd,NHD-4.3-ATXI,if=RGB24,bpp=16,int_clk");
                case '2':
                        setenv("mxcfb1","video=mxcfb1:dev=lcd,CLAA-WVGA,if=RGB24,bpp=16,int_clk");
                        break;
                case '3':
                        setenv("mxcfb1","video=mxcfb1:dev=lcd,CLAA-WVGA-HD,if=RGB24,bpp=16,int_clk");
                        break;
                case '4':
                        setenv("mxcfb1","video=mxcfb1:dev=ldb,LDB-WXGA,if=RGB24,bpp=16");
                        break;
                case '5':
                        setenv("mxcfb1","video=mxcfb1:dev=hdmi,1920x1080M@60,if=RGB24,bpp=16");
                        break;
#ifdef CONFIG_MAIN_BOARD_IS_C
                case '6':
                        setenv("mxcfb1","video=mxcfb1:dev=mipi_dsi,TRULY-EK79007-WVGA,if=RGB24,bpp=16");
#endif
                        break;
                case 'O':
                        setenv("mxcfb1","video=mxcfb1:off");
                        break;
        default:
                        printf("incorrect number\n");
                        goto HERE;
                }

                if(saveenv())
                        printf("something error occured, please check the nand device!");

        }while(1);
}

int ldb_mode()
{
        char c;
        do
        {
                printf("----------------------LVDS MODE Menu-----------------------\n");
                printf("ldb mode current value is `%s`\n",getenv("ldbmode"));
                printf("0 -- exit to upper menu\n");
                printf("1 -- sin0\n");
                printf("2 -- sin1\n");
                printf("3 -- sep0\n");
                printf("4 -- sep1\n");
                printf("5 -- spl0\n");
                printf("6 -- dul0\n");
                printf("------------------------------------------------------\n");

        HERE:
                printf(":");
                c = getc();

                printf("%c\n",c);

                switch(c)
                {
                case '0':
                        return 0;
                        break;
                case '1':
                        setenv("ldbmode","ldb=sin0");
                        break;
                case '2':
                        setenv("ldbmode","ldb=sin1");
                        break;
                case '3':
                        setenv("ldbmode","ldb=sep0");
                        break;
                case '4':
                        setenv("ldbmode","ldb=sep1");
                        break;
                case '5':
                        setenv("ldbmode","ldb=spl0");
                        break;
                case '6':
                        setenv("ldbmode","ldb=dul0");
                        break;
                default:
                        printf("incorrect number\n");
                        goto HERE;

                }
                if(saveenv())
                        printf("something error occured, please check the nand device!");
        }while(1);
}

int boot_mode(void)
{
        char c;
        do
        {
                printf("----------------------BOOT MODE Menu-----------------------\n");
                printf("0 -- exit to upper menu\n");
                printf("1 -- boot from net\n");
		printf("2 -- boot from emmc\n");
                printf("------------------------------------------------------\n");

        HERE:
                printf(":");
                c = getc();

                printf("%c\n",c);

                switch(c)
                {
                case '0':
                        return 0;
                        break;
                case '1':
			setenv("rootfsinfo","setenv bootargs ${bootargs} console=${console},${baudrate} ${smp} root=/dev/nfs ip=${ipaddr} nfsroot=${serverip}:${nfs_rootfs},v3,tcp");
			setenv("bootcmd_net","run rootfsinfo; tftpboot ${image}; tftpboot ${fdt_addr} ${fdt_file}; bootz ${loadaddr} - ${fdt_addr}");
                        setenv("bootcmd","run bootcmd_net");
                        break;
                case '2':
                        setenv("bootcmd","run findfdt;mmc dev ${mmcdev};if mmc rescan; then if run loadbootscript; then run bootscript; else if run loadimage; then run mmcboot; else run netboot; fi; fi; else run netboot; fi");
			setenv("image","zImage");
			setenv("fdt_file","undefined");
                        break;
                default:
                        printf("incorrect number\n");
                        goto HERE;

                }
                if(saveenv())
                        printf("something error occured, please check the nand device!");
        }while(1);
}

int do_scr_menu(cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
        char c;

        if(argc >1)
                goto err;

        do
        {
                printf("----------------------Main Menu-----------------------\n");
                printf("0 -- exit to uboot shell\n");
                printf("1 -- set mxcfb0 parameters\n");
		printf("2 -- set mxcfb1 parameters\n");
                printf("3 -- set ldb mode\n");
                printf("4 -- select boot mode\n");
                printf("------------------------------------------------------\n");

        HERE:
                printf(":");
                c = getc();

                printf("%c\n",c);


                switch(c)
                {
                case '0':
                        return 0;
                        break;
                case '1':
                        mxcfb0();
                        break;
		case '2':
                        mxcfb1();
                        break;
                case '3':
                        ldb_mode();
                        break;
		case '4':
                        boot_mode();
                        break;
                default:
                        printf("incorrect number\n");
                        goto HERE;
                }
        }while(1);

err:
        printf ("wrong argv, see help scr!\n");
        return 1;
}

U_BOOT_CMD(
         scr_menu ,      1,      1,      do_scr_menu,
	      "menu - display a menu, to select the items to do something\n",
 	      " - display a menu, to select the items to do something"
);
