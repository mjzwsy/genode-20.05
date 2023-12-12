/*
 *  linux/drivers/video/modedb.c -- Standard video mode database management
 *
 *	Copyright (C) 1999 Geert Uytterhoeven
 *
 *	2001 - Documented with DocBook
 *	- Brad Douglas <brad@neruo.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */
#include <linux/list.h>
#include <linux/fb.h>

/**
 *	fb_find_mode - finds a valid video mode
 *	@var: frame buffer user defined part of display
 *	@info: frame buffer info structure
 *	@mode_option: string video mode to find
 *	@db: video mode database
 *	@dbsize: size of @db
 *	@default_mode: default video mode to fall back to
 *	@default_bpp: default color depth in bits per pixel
 *
 *	Finds a suitable video mode, starting with the specified mode
 *	in @mode_option with fallback to @default_mode.  If
 *	@default_mode fails, all modes in the video mode database will
 *	be tried.
 *
 *	Valid mode specifiers for @mode_option:
 *
 *	<xres>x<yres>[M][R][-<bpp>][@<refresh>][i][m] or
 *	<name>[-<bpp>][@<refresh>]
 *
 *	with <xres>, <yres>, <bpp> and <refresh> decimal numbers and
 *	<name> a string.
 *
 *      If 'M' is present after yres (and before refresh/bpp if present),
 *      the function will compute the timings using VESA(tm) Coordinated
 *      Video Timings (CVT).  If 'R' is present after 'M', will compute with
 *      reduced blanking (for flatpanels).  If 'i' is present, compute
 *      interlaced mode.  If 'm' is present, add margins equal to 1.8%
 *      of xres rounded down to 8 pixels, and 1.8% of yres. The char
 *      'i' and 'm' must be after 'M' and 'R'. Example:
 *
 *      1024x768MR-8@60m - Reduced blank with margins at 60Hz.
 *
 *	NOTE: The passed struct @var is _not_ cleared!  This allows you
 *	to supply values for e.g. the grayscale and accel_flags fields.
 *
 *	Returns zero for failure, 1 if using specified @mode_option,
 *	2 if using specified @mode_option with an ignored refresh rate,
 *	3 if default mode is used, 4 if fall back to any valid mode.
 *
 */

int fb_find_mode(const char *mode_option, struct fb_videomode *cvt_mode)
{
    int i;
    int ret;
    if (mode_option) {
	const char *name = mode_option;
	unsigned int namelen = strlen(name);
	int res_specified = 0, bpp_specified = 0, refresh_specified = 0;
	unsigned int xres = 0, yres = 0, refresh = 0, bpp = 32;
	int yres_specified = 0, cvt = 0, rb = 0, interlace = 0, margins = 0;
	u32 best, diff, tdiff;
	for (i = namelen-1; i >= 0; i--) {
	    switch (name[i]) {
		case '@':
		    namelen = i;
		    if (!refresh_specified && !bpp_specified &&
			!yres_specified) {
			refresh = simple_strtol(&name[i+1], NULL, 10);
			refresh_specified = 1;
			if (cvt || rb)
			    cvt = 0;
		    } else
			goto done;
		    break;
		case '-':
		    namelen = i;
		    if (!bpp_specified && !yres_specified) {
			bpp = simple_strtol(&name[i+1], NULL, 10);
			bpp_specified = 1;
			if (cvt || rb)
			    cvt = 0;
		    } else
			goto done;
		    break;
		case 'x':
		    if (!yres_specified) {
			yres = simple_strtol(&name[i+1], NULL, 10);
			yres_specified = 1;
		    } else
			goto done;
		    break;
		case '0' ... '9':
		    break;
		case 'M':
		    if (!yres_specified)
			cvt = 1;
		    break;
		case 'R':
		    if (!cvt)
			rb = 1;
		    break;
		case 'm':
		    if (!cvt)
			margins = 1;
		    break;
		case 'i':
		    if (!cvt)
			interlace = 1;
		    break;
		default:
		    goto done;
	    }
	}
	if (i < 0 && yres_specified) {
	    xres = simple_strtol(name, NULL, 10);
	    res_specified = 1;
	}
done:
	if (cvt) {

	    memset(cvt_mode, 0, sizeof(*cvt_mode));
	    cvt_mode->xres = xres;
	    cvt_mode->yres = yres;
	    cvt_mode->refresh = (refresh) ? refresh : 60;

	    if (interlace)
		cvt_mode->vmode |= FB_VMODE_INTERLACED;
	    else
		cvt_mode->vmode &= ~FB_VMODE_INTERLACED;

	    ret = fb_find_mode_cvt(cvt_mode, margins, rb);

	    if (!ret) {
		printf("modedb CVT: CVT mode ok\n");
		return 1;
	    }

	     printf("CVT mode invalid, getting mode from database\n");
	}
    }
    return 0;
}

