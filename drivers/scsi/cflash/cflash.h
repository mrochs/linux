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
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>

extern unsigned int cflash_debug;

#define CFLASH_NAME                      "cflash"
#define CFLASH_DRIVER_VERSION           "1.0.1"
#define CFLASH_DRIVER_DATE              "(March 6, 2015)"

#define PCI_DEVICE_ID_IBM_CORSA		0x04F0
#define CFLASH_SUBS_DEV_ID		0x04F0

#define CFLASH_BUS                      0xff
#define CFLASH_TARGET                   0xff
#define CFLASH_LUN                      0x00
#define CFLASH_MAX_CDB_LEN		16

#define CFLASH_MAX_REQUESTS_DEFAULT     100
#define CFLASH_MAX_CMDS_PER_LUN         64
#define CFLASH_MAX_SECTORS              0xffffu
#define CFLASH_MAX_NUM_TARGETS_PER_BUS                     256
#define CFLASH_MAX_NUM_LUNS_PER_TARGET                     256
#define CFLASH_MAX_NUM_VSET_LUNS_PER_TARGET        8

#define CFLASH_PCI_ERROR_RECOVERY_TIMEOUT  (120 * HZ)

#define CFLASH_DBG_CMD(CMD) if (cflash_debug) { CMD; }

/*
 * Error logging macros
 */
#define cflash_err(...) printk(KERN_ERR CFLASH_NAME ": "__VA_ARGS__)
#define cflash_info(...) printk(KERN_INFO CFLASH_NAME ": "__VA_ARGS__)
#define cflash_dbg(...) CFLASH_DBG_CMD(printk(KERN_INFO CFLASH_NAME ": "__VA_ARGS__))

#define ENTER CFLASH_DBG_CMD(printk(KERN_INFO CFLASH_NAME": Entering %s\n", __func__))
#define LEAVE CFLASH_DBG_CMD(printk(KERN_INFO CFLASH_NAME": Leaving %s\n", __func__))


enum open_mode_type {
	MODE_NONE = 0, 
	MODE_VIRTUAL, 
	MODE_PHYSICAL
};

/*
 * Prototypes
 */
extern int cflash_disk_attach(struct scsi_device *sdev, void __user * arg);
extern int cflash_disk_open(struct scsi_device *sdev, void __user * arg, 
			    enum open_mode_type mode);
extern int cflash_disk_detach(struct scsi_device *sdev, void __user * arg);
extern int cflash_vlun_resize(struct scsi_device *sdev, void __user * arg);
extern int cflash_disk_release(struct scsi_device *sdev, void __user * arg);
extern int cflash_disk_clone(struct scsi_device *sdev, void __user * arg);
extern void hexdump(void *data, long len, const char *hdr);

#endif
