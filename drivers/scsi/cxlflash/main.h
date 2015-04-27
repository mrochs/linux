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

#ifndef _CXLFLASH_MAIN_H
#define _CXLFLASH_MAIN_H

#include <linux/list.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>

typedef unsigned int useconds_t;        /* time in microseconds */

#define CXLFLASH_NAME                      "cxlflash"
#define CXLFLASH_ADAPTER_NAME              "IBM POWER CXL Flash Adapter"
#define CXLFLASH_DRIVER_VERSION           "1.0.2"
#define CXLFLASH_DRIVER_DATE              "(April 13, 2015)"

#define PCI_DEVICE_ID_IBM_CORSA		0x04F0
#define CXLFLASH_SUBS_DEV_ID		0x04F0

/* Since there is only one target, make it 0 */
#define CXLFLASH_TARGET                   0x0
#define CXLFLASH_MAX_CDB_LEN		16

/* Really only one target per bus since the Texan is directly attached */
#define CXLFLASH_MAX_NUM_TARGETS_PER_BUS                     1
#define CXLFLASH_MAX_NUM_LUNS_PER_TARGET                     65536

#define CXLFLASH_PCI_ERROR_RECOVERY_TIMEOUT  (120 * HZ)

#define NUM_FC_PORTS     CXLFLASH_NUM_FC_PORTS  /* ports per AFU */

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

/* TIMEOUT and RETRY definitions */

/* AFU command timeout values */
#define MC_AFU_SYNC_TIMEOUT  5	/* 5 secs */

/* AFU command retry limit */
#define MC_RETRY_CNT         5	/* sufficient for SCSI check and
				   certain AFU errors */

/* AFU command room retry limit */
#define MC_ROOM_RETRY_CNT    10

/* FC CRC clear periodic timer */
#define MC_CRC_THRESH 100	/* threshold in 5 mins */

#define FC_PORT_STATUS_RETRY_CNT 100	/* 100 100ms retries = 10 seconds */
#define FC_PORT_STATUS_RETRY_INTERVAL_US 100000	/* microseconds */

/* VPD defines */
#define CXLFLASH_VPD_LEN	256
#define WWPN_LEN	16
#define WWPN_BUF_LEN	(WWPN_LEN + 1)

/* SCSI Defines                                                          */

struct request_sense_data  {
	uint8_t     err_code;        /* error class and code   */
	uint8_t     rsvd0;
	uint8_t     sense_key;
#define CXLFLASH_VENDOR_UNIQUE         0x09
#define CXLFLASH_EQUAL_CMD             0x0C
	uint8_t     sense_byte0;
	uint8_t     sense_byte1;
	uint8_t     sense_byte2;
	uint8_t     sense_byte3;
	uint8_t     add_sense_length;
	uint8_t     add_sense_byte0;
	uint8_t     add_sense_byte1;
	uint8_t     add_sense_byte2;
	uint8_t     add_sense_byte3;
	uint8_t     add_sense_key;
	uint8_t     add_sense_qualifier;
	uint8_t     fru;
	uint8_t     flag_byte;
	uint8_t     field_ptrM;
	uint8_t     field_ptrL;
};

enum cmd_err {
	CMD_FATAL_ERR      = -1,  /* Fatal command error. No recovery */
	CMD_IGNORE_ERR     = 0,   /* Ignore command error */
	CMD_RETRY_ERR      = 1,   /* Retry command error recovery */
	CMD_DLY_RETRY_ERR  = 2,   /* Retry command with delay error */
	/* recovery */
};

enum undo_level {
	RELEASE_CONTEXT = 0,
	FREE_IRQ,
	UNMAP_ONE,
	UNMAP_TWO,
	UNMAP_THREE,
	UNMAP_FOUR,
	UNDO_START
};

struct dev_dependent_vals {
	u64 max_sectors;
};

struct asyc_intr_info {
	u64 status;
	char *desc;
	u8 port;
	u8 action;
#define CLR_FC_ERROR   0x01
#define LINK_RESET     0x02
};

static inline u64 lun_to_lunid(u64 lun)
{
	u64 lun_id;

	int_to_scsilun(lun, (struct scsi_lun *)&lun_id);
	return swab64(lun_id);
}
/*
 * Externs and Prototypes
 */
int cxlflash_ioctl(struct scsi_device *, int, void __user *);

#endif /* _CXLFLASH_MAIN_H */
