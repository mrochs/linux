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

struct dk_capi_attach {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 num_interrupts;	/* Requested number of interrupts */
	__u16 rsvd[2];		/* Reserved for future use */
	__u64 flags;		/* Input flags for the attach */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Returned context ID */
	__u64 mmio_size;		/* Returned size of MMIO area */
	__u64 block_size;		/* Returned block size, in bytes */
	__u64 adap_fd;		/* Returned adapter file descriptor */
	__u64 last_lba;		/* Returned last LBA on the device */
	__u64 max_xfer;		/* Maximum transfer size, in blocks */
};

struct dk_capi_detach {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for detach operation */
	__u64 return_flags;	/* Returned flags from detach */
	__u64 context_id;		/* Context ID to detach */
};

struct dk_capi_udirect {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for LUN creation */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;	/* Returned resource handle */
	__u64 block_size;		/* Returned block size, in bytes */
	__u64 last_lba;		/* Returned last LBA on the device */
};

struct dk_capi_uvirtual {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for virtual LUN create */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;	/* Returned resource handle */
	__u64 block_size;		/* Returned block size, in bytes */
	__u64 last_lba;		/* Returned last LBA of LUN */
	__u64 lun_size;		/* Requested size, blocks */
};

struct dk_capi_release {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for the release op */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;	/* Resource handle to release */
};

struct dk_capi_resize {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for resize */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID of LUN to resize */
	__u64 rsrc_handle;	/* Resource handle of LUN to resize */
	__u64 req_size;		/* New requested size, blocks */
	__u64 last_lba;		/* Returned last LBA of LUN */
};

struct dk_capi_clone {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for clone */
	__u64 context_id_src;	/* Context ID to clone from */
	__u64 context_id_dst;	/* Context ID to clone to */
};

struct dk_capi_verify {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for verification */
	__u64 return_flags;	/* Returned verification flags */
	__u64 rsrc_handle;	/* Resource handle of LUN */
	__u64 hint;		/* Reasons for verify */
	__u64 last_lba;		/* Returned last LBA of device */
};

struct dk_capi_log {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for error log */
	__u64 return_flags;	/* Returned flags */
	__u64 rsrc_handle;	/* Resource handle to log error against */
	__u64 reason;		/* Reason code for error */
	__u8 sense_data[256];	/* Sense data to include in error */
};

struct dk_capi_recover_afu {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for recovery */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;	/* Context ID of LUN to resize */
	__u64 rsrc_handle;	/* Resource handle for LUN to recover */
	__u64 reason;		/* Reason for recovery request */
};

#define CXL_MAGIC 0xCA

#define DK_CAPI_ATTACH            _IOW(CXL_MAGIC, 0x80, struct dk_capi_attach)
#define DK_CAPI_USER_DIRECT       _IOW(CXL_MAGIC, 0x81, struct dk_capi_udirect)
#define DK_CAPI_USER_VIRTUAL      _IOW(CXL_MAGIC, 0x82, struct dk_capi_uvirtual)
#define DK_CAPI_VLUN_RESIZE       _IOW(CXL_MAGIC, 0x83, struct dk_capi_resize)
#define DK_CAPI_RELEASE           _IOW(CXL_MAGIC, 0x84, struct dk_capi_release)
#define DK_CAPI_DETACH            _IOW(CXL_MAGIC, 0x85, struct dk_capi_detach)
#define DK_CAPI_VERIFY            _IOW(CXL_MAGIC, 0x86, struct dk_capi_verify)
#define DK_CAPI_LOG_EVENT         _IOW(CXL_MAGIC, 0x87, struct dk_capi_log)
#define DK_CAPI_RECOVER_AFU       _IOW(CXL_MAGIC, 0x88, struct dk_capi_recover_afu)
#define DK_CAPI_QUERY_EXCEPTIONS  _IOW(CXL_MAGIC, 0x89, struct dk_capi_log)
#define DK_CAPI_CLONE		  _IOW(CXL_MAGIC, 0x8A, struct dk_capi_clone)

#endif /* ifndef _CFLASHIOCTL_H */
