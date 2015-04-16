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

#ifndef _CFLASHMC_H
#define _CFLASHMC_H

typedef unsigned int useconds_t;	/* time in microseconds */

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

#define MAX_CONTEXT  CFLASH_MAX_CONTEXT       /* num contexts per afu */

struct cflash_ctx {
	struct cxl_ioctl_start_work work;
	int lfd;
	pid_t pid;
};

enum cflash_lr_state {
	LINK_RESET_INVALID,
	LINK_RESET_REQUIRED,
	LINK_RESET_COMPLETE
};

struct cflash {
	struct afu *afu;
	struct cxl_context *mcctx;

	struct pci_dev *dev;
	struct pci_device_id *dev_id;
	struct Scsi_Host *host;

	unsigned long cflash_regs_pci;
	void __iomem *cflash_regs;

	wait_queue_head_t reset_wait_q;
	wait_queue_head_t msi_wait_q;
	wait_queue_head_t eeh_wait_q;

	struct work_struct work_q ;
	enum cflash_lr_state lr_state;
	int lr_port;

	struct cxl_afu *cxl_afu;
	timer_t timer_hb;
	timer_t timer_fc;

	struct pci_pool *cflash_cmd_pool;
	struct pci_dev *parent_dev;

	struct cflash_ctx per_context[MAX_CONTEXT];
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

union cflash_ioctls {
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

#define MAX_CFLASH_IOCTL_SZ	(sizeof(union cflash_ioctls))

int cflash_init_afu(struct cflash *, bool);
void cflash_term_afu(struct cflash *, bool);
struct afu_cmd *cflash_cmd_cout(struct afu *p_afu);
void cflash_cmd_cin(struct afu_cmd *p_cmd);
int cflash_send_scsi(struct afu *, struct scsi_cmnd *);
int cflash_send_tmf(struct afu *, struct scsi_cmnd *, u64);
struct sisl_rht_entry *cflash_rhte_cout(struct cflash *, u64);
void cflash_rht_format1(struct sisl_rht_entry *, u64, u32);
struct ctx_info *get_validated_context(struct cflash *, u64, bool);
int check_status(struct sisl_ioasa_s *);
void cflash_send_cmd(struct afu *, struct afu_cmd *);
void cflash_wait_resp(struct afu *, struct afu_cmd *);
void cflash_scan_luns(struct cflash *);
int afu_reset(struct cflash *);
#endif /* ifndef _CFLASHMC_H */
