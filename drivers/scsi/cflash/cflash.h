/*
 * cflash.h -- driver for IBM Power CAPI Flash Adapter
 *
 * Written By: Manoj Kumar <kumarmn@us.ibm.com>, IBM Corporation
 *
 * Copyright (C) IBM Corporation, 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _CFLASH_H
#define _CFLASH_H


#include <linux/list.h>
#include <linux/types.h>

#define CFLASH_NAME                      "cflash"
#define CFLASH_DRIVER_VERSION           "1.0.0"
#define CFLASH_DRIVER_DATE              "(January 16, 2015)"


#define CFLASH_MAX_REQUESTS_DEFAULT     100
#define CFLASH_MAX_CMDS_PER_LUN         64
#define CFLASH_MAX_SECTORS              0xffffu

#define CFLASH_DBG_CMD(CMD) if (cflash_debug) { CMD; }

#define ENTER CFLASH_DBG_CMD(printk(KERN_INFO CFLASH_NAME": Entering %s\n", __func__))
#define LEAVE CFLASH_DBG_CMD(printk(KERN_INFO CFLASH_NAME": Leaving %s\n", __func__))


#endif
