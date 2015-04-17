/*
 * CXL Flash Device Driver
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

#ifndef _CXLFLASH_H
#define _CXLFLASH_H

#include <linux/list.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>

#include "cflash_ioctl.h"

extern u32 internal_lun;
extern u32 fullqc;
extern u32 checkpid;

#define CXLFLASH_NAME                      "cxlflash"
#define CXLFLASH_ADAPTER_NAME              "IBM POWER CXL Flash Adapter"
#define CXLFLASH_DRIVER_VERSION           "1.0.2"
#define CXLFLASH_DRIVER_DATE              "(April 13, 2015)"

#define PCI_DEVICE_ID_IBM_CORSA		0x04F0
#define CXLFLASH_SUBS_DEV_ID		0x04F0

/* Since there is only one target, make it 0 */
#define CXLFLASH_TARGET                   0x0
#define CXLFLASH_MAX_CDB_LEN		16

#define CXLFLASH_MAX_CMDS			16
#define CXLFLASH_MAX_CMDS_PER_LUN         CXLFLASH_MAX_CMDS
#define CXLFLASH_BLOCK_SIZE		0x1000
/* With a 4ksector, and a 16MB transfer size limit max should be 4k sectors */
#define CXLFLASH_MAX_SECTORS              0x1000
/* Really only one target per bus since the Texan is directly attached */
#define CXLFLASH_MAX_NUM_TARGETS_PER_BUS                     1
#define CXLFLASH_MAX_NUM_LUNS_PER_TARGET                     65536

#define CXLFLASH_PCI_ERROR_RECOVERY_TIMEOUT  (120 * HZ)

/* FC defines */
#define FC_MTIP_CMDCONFIG 0x010
#define FC_MTIP_STATUS 0x018

#define FC_PNAME 0x300
#define FC_CONFIG 0x320
#define FC_CONFIG2 0x328
#define FC_STATUS 0x330
#define FC_ERROR 0x380
#define FC_ERRCAP 0x388
#define FC_ERRMSK 0x390
#define FC_CNT_CRCERR 0x538
#define FC_CRC_THRESH 0x580

#define FC_MTIP_CMDCONFIG_ONLINE    0x20ull
#define FC_MTIP_CMDCONFIG_OFFLINE   0x40ull

#define FC_MTIP_STATUS_MASK         0x30ull
#define FC_MTIP_STATUS_ONLINE       0x20ull
#define FC_MTIP_STATUS_OFFLINE      0x10ull

/* VPD defines */
#define CXLFLASH_VPD_LEN	256
#define WWPN_LEN	16
#define WWPN_BUF_LEN	(WWPN_LEN + 1)

/*
 * Error logging macros
 *
 * These wrappers around pr|dev_* add the function name and newline character
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
#define cxlflash_emerg(_s, ...)	pr_emerg(CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_alert(_s, ...)	pr_alert(CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_crit(_s,  ...)	pr_crit(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cxlflash_err(_s,   ...)	pr_err(CONFN(_s),   __func__, ##__VA_ARGS__)
#define cxlflash_warn(_s,  ...)	pr_warn(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cxlflash_info(_s,  ...)	pr_info(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cxlflash_devel(_s, ...)	pr_devel(CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dbg(_s, ...)	pr_debug(CONFN(_s), __func__, ##__VA_ARGS__)

#define cxlflash_dev_emerg(_d, _s, ...)	\
	dev_emerg(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_alert(_d, _s, ...)	\
	dev_alert(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_crit(_d, _s, ...)	\
	dev_crit(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_err(_d, _s, ...)	\
	dev_err(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_warn(_d, _s, ...)	\
	dev_warn(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_info(_d, _s, ...)	\
	dev_info(_d, CONFN(_s), __func__, ##__VA_ARGS__)
#define cxlflash_dev_dbg(_d, _s, ...)	\
	dev_dbg(_d, CONFN(_s), __func__, ##__VA_ARGS__)

enum open_mode_type {
	MODE_NONE = 0,
	MODE_VIRTUAL,
	MODE_PHYSICAL
};

struct dev_dependent_vals {
	u64 max_sectors;
};

/*
 * Externs and Prototypes
 */
extern const struct file_operations cxlflash_cxl_fops;
extern int cxlflash_ioctl(struct scsi_device *, int, void __user *);

#endif /* _CXLFLASH_H */
