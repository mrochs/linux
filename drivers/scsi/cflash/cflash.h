/*
 * CAPI Flash Device Driver
 *
 * Written by: Manoj N. Kumar <manoj@linux.vnet.ibm.com>, IBM Corporation
 *             Matthew R. Ochs <mrochs@linux.vnet.ibm.com>, IBM Corporation
 *
 * Copyright (C) 2015 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _CFLASH_H
#define _CFLASH_H

#include <linux/list.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>

extern u32 cflash_debug;
extern u32 internal_lun;
extern u32 fullqc;

#define CFLASH_NAME                      "cflash"
#define CFLASH_DRIVER_VERSION           "1.0.1"
#define CFLASH_DRIVER_DATE              "(March 6, 2015)"

#define PCI_DEVICE_ID_IBM_CORSA		0x04F0
#define CFLASH_SUBS_DEV_ID		0x04F0

/* Since there is only one target, make it 0 */
#define CFLASH_TARGET                   0x0
#define CFLASH_MAX_CDB_LEN		16

#define CFLASH_MAX_CMDS			16
#define CFLASH_MAX_CMDS_PER_LUN         CFLASH_MAX_CMDS
#define CFLASH_MAX_SECTORS              0xffffu
/* Really only one target per bus since the Texan is directly attached */
#define CFLASH_MAX_NUM_TARGETS_PER_BUS                     1
#define CFLASH_MAX_NUM_LUNS_PER_TARGET                     65536

#define CFLASH_PCI_ERROR_RECOVERY_TIMEOUT  (120 * HZ)

#define CFLASH_DBG_CMD(CMD) if (cflash_debug) { CMD; }

/*
 * Error logging macros
 *
 * These wrappers around pr_* add the function name and newline character
 * automatically, avoiding the need to include them inline with each trace
 * statement and saving line width.
 *
 * The parameters must be split into the format string and variable list of
 * parameters in order to support concatenation of the function format
 * specifier and newline character. The CONFN macro is a helper to simplify
 * the contactenation and make it easier to change the desired format. Lastly,
 * the variable list is passed with a dummy concatenation. This trick is used
 * to support the case where no parameters are passed and the user simply
 * desires a single string trace.
 */
#define CONFN(_s) "%s: "_s"\n"
#define cflash_emerg(_s, ...)	pr_emerg(CONFN(_s), __func__, ##__VA_ARGS__)
#define cflash_alert(_s, ...)	pr_alert(CONFN(_s), __func__, ##__VA_ARGS__)
#define cflash_crit(_s,  ...)	pr_crit(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cflash_err(_s,   ...)	pr_err(CONFN(_s),   __func__, ##__VA_ARGS__)
#define cflash_warn(_s,  ...)	pr_warn(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cflash_info(_s,  ...)	pr_info(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cflash_devel(_s, ...)	pr_devel(CONFN(_s), __func__, ##__VA_ARGS__)

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
extern int cflash_afu_recover(struct scsi_device *sdev, void __user * arg);

#endif
