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

#ifndef _CXLFLASHMC_H
#define _CXLFLASHMC_H

typedef unsigned int useconds_t;	/* time in microseconds */

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

#define MAX_CONTEXT  CXLFLASH_MAX_CONTEXT       /* num contexts per afu */

struct cxlflash_ctx {
	struct cxl_ioctl_start_work work;
	int lfd;
	pid_t pid;
};

enum cxlflash_lr_state {
	LINK_RESET_INVALID,
	LINK_RESET_REQUIRED,
	LINK_RESET_COMPLETE
};

struct cxlflash {
	struct afu *afu;
	struct cxl_context *mcctx;

	struct pci_dev *dev;
	struct pci_device_id *dev_id;
	struct Scsi_Host *host;

	unsigned long cxlflash_regs_pci;
	void __iomem *cxlflash_regs;

	wait_queue_head_t reset_wait_q;
	wait_queue_head_t msi_wait_q;
	wait_queue_head_t eeh_wait_q;

	struct work_struct work_q ;
	enum cxlflash_lr_state lr_state;
	int lr_port;

	struct cxl_afu *cxl_afu;
	timer_t timer_hb;
	timer_t timer_fc;

	struct pci_pool *cxlflash_cmd_pool;
	struct pci_dev *parent_dev;

	struct cxlflash_ctx per_context[MAX_CONTEXT];
	struct file_operations cxl_fops;

	int last_lun_index;
	int task_set;

        wait_queue_head_t tmf_wait_q;
	u8 context_reset_active:1;
	u8 tmf_active:1;
};

static inline u64 lun_to_lunid(u64 lun)
{
	u64 lun_id;

	int_to_scsilun(lun, (struct scsi_lun *)&lun_id);
	return swab64(lun_id);
}

union cxlflash_ioctls {
	struct dk_capi_attach		attach;
	struct dk_capi_detach		detach;
	struct dk_capi_udirect		udirect;
	struct dk_capi_uvirtual		uvirtual;
	struct dk_capi_release		release;
	struct dk_capi_resize		resize;
	struct dk_capi_clone		clone;
	struct dk_capi_verify		verify;
	struct dk_capi_log		log;
	struct dk_capi_recover_afu	recover_afu;
};

struct ba_lun {
	u64 lun_id;
	u64 wwpn;
	size_t lsize;		/* Lun size in number of LBAs             */
	size_t lba_size;	/* LBA size in number of bytes            */
	size_t au_size;		/* Allocation Unit size in number of LBAs */
	void *ba_lun_handle;
};

void ba_terminate(struct ba_lun *ba_lun);

#define MAX_AUN_CLONE_CNT    0xFF

struct ba_lun_info {
	u64 *lun_alloc_map;
	u32 lun_bmap_size;
	u32 total_aus;
	u64 free_aun_cnt;

	/* indices to be used for elevator lookup of free map */
	u32 free_low_idx;
	u32 free_curr_idx;
	u32 free_high_idx;

	unsigned char *aun_clone_map;
};

#define MAX_CXLFLASH_IOCTL_SZ	(sizeof(union cxlflash_ioctls))

struct afu_cmd *cmd_checkout(struct afu *p_afu);
void cmd_checkin(struct afu_cmd *p_cmd);
void cxlflash_rht_format1(struct sisl_rht_entry *, u64, u32);
int check_status(struct sisl_ioasa_s *);
void cxlflash_send_cmd(struct afu *, struct afu_cmd *);
void cxlflash_wait_resp(struct afu *, struct afu_cmd *);
void cxlflash_scan_luns(struct cxlflash *);
int afu_reset(struct cxlflash *);
#endif /* ifndef _CXLFLASHMC_H */
