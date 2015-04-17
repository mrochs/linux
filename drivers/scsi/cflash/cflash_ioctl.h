/*
 * CXLFLASH Flash Device Driver
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
 * from the block library to the CXLFLASH Flash Adapater Driver
 */

struct dk_cxlflash_attach {
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

struct dk_cxlflash_detach {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for detach operation */
	__u64 return_flags;	/* Returned flags from detach */
	__u64 context_id;		/* Context ID to detach */
};

struct dk_cxlflash_udirect {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for LUN creation */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;	/* Returned resource handle */
	__u64 block_size;		/* Returned block size, in bytes */
	__u64 last_lba;		/* Returned last LBA on the device */
};

struct dk_cxlflash_uvirtual {
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

struct dk_cxlflash_release {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for the release op */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;	/* Resource handle to release */
};

struct dk_cxlflash_resize {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for resize */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;		/* Context ID of LUN to resize */
	__u64 rsrc_handle;	/* Resource handle of LUN to resize */
	__u64 req_size;		/* New requested size, blocks */
	__u64 last_lba;		/* Returned last LBA of LUN */
};

struct dk_cxlflash_clone {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for clone */
	__u64 context_id_src;	/* Context ID to clone from */
	__u64 context_id_dst;	/* Context ID to clone to */
};

struct dk_cxlflash_verify {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for verification */
	__u64 return_flags;	/* Returned verification flags */
	__u64 rsrc_handle;	/* Resource handle of LUN */
	__u64 hint;		/* Reasons for verify */
	__u64 last_lba;		/* Returned last LBA of device */
};

struct dk_cxlflash_log {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for error log */
	__u64 return_flags;	/* Returned flags */
	__u64 rsrc_handle;	/* Resource handle to log error against */
	__u64 reason;		/* Reason code for error */
	__u8 sense_data[256];	/* Sense data to include in error */
};

struct dk_cxlflash_recover_afu {
	__u16 version;		/* SCSI_VERSION_0 */
	__u16 rsvd[3];		/* Reserved for future use */
	__u64 flags;		/* Flags for recovery */
	__u64 return_flags;	/* Returned flags */
	__u64 context_id;	/* Context ID of LUN to resize */
	__u64 rsrc_handle;	/* Resource handle for LUN to recover */
	__u64 reason;		/* Reason for recovery request */
};

#define CXL_MAGIC 0xCA

#define DK_CXLFLASH_ATTACH            _IOW(CXL_MAGIC, 0x80, struct dk_cxlflash_attach)
#define DK_CXLFLASH_USER_DIRECT       _IOW(CXL_MAGIC, 0x81, struct dk_cxlflash_udirect)
#define DK_CXLFLASH_USER_VIRTUAL      _IOW(CXL_MAGIC, 0x82, struct dk_cxlflash_uvirtual)
#define DK_CXLFLASH_VLUN_RESIZE       _IOW(CXL_MAGIC, 0x83, struct dk_cxlflash_resize)
#define DK_CXLFLASH_RELEASE           _IOW(CXL_MAGIC, 0x84, struct dk_cxlflash_release)
#define DK_CXLFLASH_DETACH            _IOW(CXL_MAGIC, 0x85, struct dk_cxlflash_detach)
#define DK_CXLFLASH_VERIFY            _IOW(CXL_MAGIC, 0x86, struct dk_cxlflash_verify)
#define DK_CXLFLASH_LOG_EVENT         _IOW(CXL_MAGIC, 0x87, struct dk_cxlflash_log)
#define DK_CXLFLASH_RECOVER_AFU       _IOW(CXL_MAGIC, 0x88, struct dk_cxlflash_recover_afu)
#define DK_CXLFLASH_QUERY_EXCEPTIONS  _IOW(CXL_MAGIC, 0x89, struct dk_cxlflash_log)
#define DK_CXLFLASH_CLONE	      _IOW(CXL_MAGIC, 0x8A, struct dk_cxlflash_clone)


/* These are temporary defines while the name transition occurs */
#define dk_capi_attach		dk_cxlflash_attach
#define dk_capi_detach		dk_cxlflash_detach
#define dk_capi_udirect		dk_cxlflash_udirect
#define dk_capi_uvirtual	dk_cxlflash_uvirtual
#define dk_capi_release		dk_cxlflash_release
#define dk_capi_resize		dk_cxlflash_resize
#define dk_capi_clone		dk_cxlflash_clone
#define dk_capi_verify		dk_cxlflash_verify
#define dk_capi_log		dk_cxlflash_log
#define dk_capi_recover_afu	dk_cxlflash_recover_afu

#define DK_CAPI_ATTACH			DK_CXLFLASH_ATTACH
#define DK_CAPI_USER_DIRECT		DK_CXLFLASH_USER_DIRECT
#define DK_CAPI_USER_VIRTUAL		DK_CXLFLASH_USER_VIRTUAL
#define DK_CAPI_VLUN_RESIZE		DK_CXLFLASH_VLUN_RESIZE
#define DK_CAPI_RELEASE			DK_CXLFLASH_RELEASE
#define DK_CAPI_DETACH			DK_CXLFLASH_DETACH
#define DK_CAPI_VERIFY			DK_CXLFLASH_VERIFY
#define DK_CAPI_LOG_EVENT		DK_CXLFLASH_LOG_EVENT
#define DK_CAPI_RECOVER_AFU		DK_CXLFLASH_RECOVER_AFU
#define DK_CAPI_QUERY_EXCEPTIONS	DK_CXLFLASH_QUERY_EXCEPTIONS
#define DK_CAPI_CLONE			DK_CXLFLASH_CLONE

#endif /* ifndef _CFLASHIOCTL_H */
