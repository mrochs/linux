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

#ifndef _CFLASHIOCTL_H
#define _CFLASHIOCTL_H

/* Header file to be included in the block library.
 * Contains definitions of structures for ioctls sent from
 * from the block library to the CAPI Flash Adapater Driver
 */

struct dk_capi_path_info {
	u16 path_id;		/* MPIO path identifier  */
	dev_t devno;		/* Device number of the parent adapter */
	u64 reserved[4];	/* Space for future stuff */
};

struct dk_capi_paths {
	u16 version;		/* SCSI_VERSION_0 */
	u8 path_count;		/* Entries in passed in path_info array */
	u8 returned_path_count;	/* Total paths for this disk            */
	struct dk_capi_path_info path_info[1];	/* Info about each path     */
};

struct dk_capi_attach {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* Path number to attach */
	u16 num_interrupts;	/* Requested number of interrupts */
	u16 rsvd[1];
	u64 flags;		/* Input flags for the attach */
	u64 return_flags;	/* Returned flags */
	u64 context_id;		/* Returned context ID */
	void *mmio_start;	/* Returned address of MMIO area */
	u64 mmio_size;		/* Returned size of MMIO area */
	u64 block_size;		/* Returned block size, in bytes */
	u32 adap_fd;		/* Returned adapter file descriptor */
};

struct dk_capi_detach {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* Path number to detach */
	u16 rsvd[2];
	u64 flags;		/* Flags for detach operation */
	u64 return_flags;	/* Returned flags from detach */
	u64 context_id;		/* Context ID to detach */
};

struct dk_capi_udirect {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* MPIO path ID for attach */
	u16 rsvd[2];
	u64 flags;		/* Flags for LUN creation */
	u64 return_flags;	/* Returned flags */
	u64 context_id;		/* Context ID for the attach */
	u64 rsrc_handle;	/* Returned resource handle */
	u64 challenge;		/* Validation cookie */
	u64 block_size;		/* Returned block size, in bytes */
	u64 last_lba;		/* Returned last LBA on the device */
};

struct dk_capi_uvirtual {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* MPIO path ID for attach */
	u16 rsvd[2];
	u64 flags;		/* Flags for virtual LUN create */
	u64 return_flags;	/* Returned flags */
	u64 context_id;		/* Context ID for the attach */
	u64 rsrc_handle;	/* Returned resource handle */
	u64 challenge;		/* Validation cookie */
	u64 block_size;		/* Returned block size, in bytes */
	u64 last_lba;		/* Returned last LBA of LUN */
	u64 lun_size;		/* Requested size, blocks */
};

struct dk_capi_release {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* MPIO path ID */
	u16 rsvd[2];
	u64 flags;		/* Flags for the release op */
	u64 return_flags;	/* Returned flags */
	u64 context_id;		/* Context ID for the attach */
	u64 rsrc_handle;	/* Resource handle to release */
	u64 challenge;		/* Validation cookie */
};

struct dk_capi_resize {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* MPIO path ID */
	u16 rsvd[2];
	u64 flags;		/* Flags for resize */
	u64 return_flags;	/* Returned flags */
	u64 context_id;		/* Context ID of LUN to resize */
	u64 rsrc_handle;	/* Resource handle of LUN to resize */
	u64 challenge;		/* Validation cookie */
	u64 req_size;		/* New requested size, blocks */
	u64 last_lba;		/* Returned last LBA of LUN */
};

struct dk_capi_clone {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* MPIO path ID */
	u16 rsvd[2];
	u64 flags;		/* Flags for clone */
	u64 context_id_src;	/* Context ID to clone from */
	u64 context_id_dst;	/* Context ID to clone to */
	u64 challenge_src;	/* Validation cookie to access source context */
	u64 challenge_dst;	/* Validation cookie to access dest context */
};

struct dk_capi_verify {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* ID of path to verify */
	u16 rsvd[2];
	u64 flags;		/* Flags for verification */
	u64 return_flags;	/* Returned verification flags */
	u64 rsrc_handle;	/* Resource handle of LUN */
	u64 challenge;		/* Validation cookie */
	u64 hint;		/* Reasons for verify */
	u64 last_lba;		/* Returned last LBA of device */
};

struct dk_capi_log {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* Path ID to log error against */
	u16 log_rsvd[2];
	u64 flags;		/* Flags for error log */
	u64 return_flags;	/* Returned flags */
	u64 rsrc_handle;	/* Resource handle to log error against */
	u64 challenge;		/* Validation cookie */
	u64 reason;		/* Reason code for error */
	char sense_data[256];	/* Sense data to include in error */
};

struct dk_capi_recover_afu {
	u16 version;		/* SCSI_VERSION_0 */
	u16 path_id;		/* ID of path to recover */
	u16 ver_rsvd[2];
	u64 flags;		/* Flags for recovery */
	u64 return_flags;	/* Returned flags */
	u64 rsrc_handle;	/* Resource handle for LUN to recover */
	u64 challenge;		/* Validation cookie */
	u64 reason;		/* Reason for recovery request */
};

#define CXL_MAGIC 0xCA

#define DK_CAPI_QUERY_PATH        _IOW(CXL_MAGIC, 0x80, struct dk_capi_paths)
#define DK_CAPI_ATTACH            _IOW(CXL_MAGIC, 0x81, struct dk_capi_attach)
#define DK_CAPI_USER_DIRECT       _IOW(CXL_MAGIC, 0x82, struct dk_capi_udirect)
#define DK_CAPI_USER_VIRTUAL      _IOW(CXL_MAGIC, 0x83, struct dk_capi_uvirtual)
#define DK_CAPI_VLUN_RESIZE       _IOW(CXL_MAGIC, 0x84, struct dk_capi_resize)
#define DK_CAPI_RELEASE           _IOW(CXL_MAGIC, 0x85, struct dk_capi_release)
#define DK_CAPI_DETACH            _IOW(CXL_MAGIC, 0x86, struct dk_capi_detach)
#define DK_CAPI_VERIFY            _IOW(CXL_MAGIC, 0x87, struct dk_capi_verify)
#define DK_CAPI_LOG_EVENT         _IOW(CXL_MAGIC, 0x88, struct dk_capi_log)
#define DK_CAPI_RECOVER_AFU       _IOW(CXL_MAGIC, 0x89, struct dk_capi_recover_afu)
#define DK_CAPI_QUERY_EXCEPTIONS  _IOW(CXL_MAGIC, 0x8A, struct dk_capi_log)
#define DK_CAPI_CLONE		  _IOW(CXL_MAGIC, 0x8B, struct dk_capi_clone)

#define DK_CAPI_BLOCK		  0x1000
#endif /* ifndef _CFLASHIOCTL_H */
