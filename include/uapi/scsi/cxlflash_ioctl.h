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
 * Structure and flag definitions CXL Flash superpipe ioctls
 */

struct dk_cxlflash_hdr {
	__u16 version;			/* Version data */
	__u16 rsvd[3];			/* Reserved for future use */
	__u64 flags;			/* Input flags */
	__u64 return_flags;		/* Returned flags */
};

/*
 * Note: For DK_CXLFLASH_ATTACH ioctl, user specifies read/write access
 * permissions via the O_RDONLY, O_WRONLY, and O_RDWR flags defined in
 * the fcntl.h header file.
 */
#define DK_CXLFLASH_ATTACH_REUSE_CONTEXT	0x8000000000000000ULL

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
	__u64 adap_fd_src;		/* Source context adapter fd */
};

#define DK_CXLFLASH_VERIFY_SENSE_LEN	18
#define DK_CXLFLASH_VERIFY_HINT_SENSE	0x8000000000000000ULL

struct dk_cxlflash_verify {
	struct dk_cxlflash_hdr hdr;	/* Common fields */
	__u64 context_id;		/* Context ID of LUN to verify */
	__u64 rsrc_handle;		/* Resource handle of LUN */
	__u64 hint;			/* Reasons for verify */
	__u64 last_lba;			/* Returned last LBA of device */
	__u8 sense_data[DK_CXLFLASH_VERIFY_SENSE_LEN]; /* SCSI sense data */
	__u8 pad[6];			/* Pad to next 8-byte boundary */
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
	struct dk_cxlflash_recover_afu recover_afu;
};

#define MAX_CXLFLASH_IOCTL_SZ	(sizeof(union cxlflash_ioctls))


#define CXL_MAGIC 0xCA
#define CXL_IOW(_n, _s)	_IOW(CXL_MAGIC, _n, struct _s)

#define DK_CXLFLASH_ATTACH		CXL_IOW(0x80, dk_cxlflash_attach)
#define DK_CXLFLASH_USER_DIRECT		CXL_IOW(0x81, dk_cxlflash_udirect)
#define DK_CXLFLASH_USER_VIRTUAL	CXL_IOW(0x82, dk_cxlflash_uvirtual)
#define DK_CXLFLASH_VLUN_RESIZE		CXL_IOW(0x83, dk_cxlflash_resize)
#define DK_CXLFLASH_RELEASE		CXL_IOW(0x84, dk_cxlflash_release)
#define DK_CXLFLASH_DETACH		CXL_IOW(0x85, dk_cxlflash_detach)
#define DK_CXLFLASH_VERIFY		CXL_IOW(0x86, dk_cxlflash_verify)
#define DK_CXLFLASH_CLONE		CXL_IOW(0x87, dk_cxlflash_clone)
#define DK_CXLFLASH_RECOVER_AFU		CXL_IOW(0x88, dk_cxlflash_recover_afu)

#endif /* ifndef _CXLFLASH_IOCTL_H */
