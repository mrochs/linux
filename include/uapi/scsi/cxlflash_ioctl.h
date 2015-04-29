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

#ifndef _CXLFLASH_IOCTL_H
#define _CXLFLASH_IOCTL_H

#include <linux/types.h>

/*
 * Structure definitions CXL Flash driver superpipe ioctls
 */

struct dk_cxlflash_hdr {
	__u16 version;			/* Version data */
	__u16 rsvd[3];			/* Reserved for future use */
	__u64 flags;			/* Input flags */
	__u64 return_flags;		/* Returned flags */
};

struct dk_cxlflash_attach {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 num_interrupts;		/* Requested number of interrupts */
	__u64 context_id;		/* Returned context ID */
	__u64 mmio_size;		/* Returned size of MMIO area */
	__u64 block_size;		/* Returned block size, in bytes */
	__u64 adap_fd;			/* Returned adapter file descriptor */
	__u64 last_lba;			/* Returned last LBA on the device */
	__u64 max_xfer;			/* Returned max transfer size, blocks */
};

struct dk_cxlflash_detach {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID to detach */
};

struct dk_cxlflash_udirect {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;		/* Returned resource handle */
	__u64 last_lba;			/* Returned last LBA on the device */
};

struct dk_cxlflash_uvirtual {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID for the attach */
	__u64 lun_size;			/* Requested size, blocks */
	__u64 rsrc_handle;		/* Returned resource handle */
	__u64 last_lba;			/* Returned last LBA of LUN */
};

struct dk_cxlflash_release {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID for the attach */
	__u64 rsrc_handle;		/* Resource handle to release */
};

struct dk_cxlflash_resize {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID of LUN to resize */
	__u64 rsrc_handle;		/* Resource handle of LUN to resize */
	__u64 req_size;			/* New requested size, blocks */
	__u64 last_lba;			/* Returned last LBA of LUN */
};

struct dk_cxlflash_clone {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id_src;		/* Context ID to clone from */
	__u64 context_id_dst;		/* Context ID to clone to */
};

#define DK_HINT_SENSE    0x0000000000000001LL

struct dk_cxlflash_verify {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 rsrc_handle;		/* Resource handle of LUN */
	__u64 hint;			/* Reasons for verify */
	__u64 last_lba;			/* Returned last LBA of device */
	__u8 sense_data[18];		/* Sense data to decode */
};

struct dk_cxlflash_log {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 rsrc_handle;		/* Resource handle to log err against */
	__u64 reason;			/* Reason code for error */
	__u8 sense_data[256];		/* Sense data to include in error */
};

struct dk_cxlflash_recover_afu {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID of LUN to resize */
	__u64 rsrc_handle;		/* Resource handle for LUN to recover */
	__u64 reason;			/* Reason for recovery request */
};

union cxlflash_ioctls {
	struct dk_cxlflash_attach attach;
	struct dk_cxlflash_detach detach;
	struct dk_cxlflash_udirect udirect;
	struct dk_cxlflash_uvirtual uvirtual;
	struct dk_cxlflash_release release;
	struct dk_cxlflash_resize resize;
	struct dk_cxlflash_clone clone;
	struct dk_cxlflash_verify verify;
	struct dk_cxlflash_log log;
	struct dk_cxlflash_recover_afu recover_afu;
};

#define MAX_CXLFLASH_IOCTL_SZ	(sizeof(union cxlflash_ioctls))


#define CXL_MAGIC 0xCA

#define DK_CXLFLASH_ATTACH           _IOW(CXL_MAGIC, 0x80, struct dk_cxlflash_attach)
#define DK_CXLFLASH_USER_DIRECT      _IOW(CXL_MAGIC, 0x81, struct dk_cxlflash_udirect)
#define DK_CXLFLASH_USER_VIRTUAL     _IOW(CXL_MAGIC, 0x82, struct dk_cxlflash_uvirtual)
#define DK_CXLFLASH_VLUN_RESIZE      _IOW(CXL_MAGIC, 0x83, struct dk_cxlflash_resize)
#define DK_CXLFLASH_RELEASE          _IOW(CXL_MAGIC, 0x84, struct dk_cxlflash_release)
#define DK_CXLFLASH_DETACH           _IOW(CXL_MAGIC, 0x85, struct dk_cxlflash_detach)
#define DK_CXLFLASH_VERIFY           _IOW(CXL_MAGIC, 0x86, struct dk_cxlflash_verify)
#define DK_CXLFLASH_LOG_EVENT        _IOW(CXL_MAGIC, 0x87, struct dk_cxlflash_log)
#define DK_CXLFLASH_RECOVER_AFU      _IOW(CXL_MAGIC, 0x88, struct dk_cxlflash_recover_afu)
#define DK_CXLFLASH_QUERY_EXCEPTIONS _IOW(CXL_MAGIC, 0x89, struct dk_cxlflash_log)
#define DK_CXLFLASH_CLONE	     _IOW(CXL_MAGIC, 0x8A, struct dk_cxlflash_clone)

#endif /* ifndef _CXLFLASH_IOCTL_H */
