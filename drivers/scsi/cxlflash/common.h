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

#ifndef _CXLFLASH_COMMON_H
#define _CXLFLASH_COMMON_H

#include <linux/list.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>


#define MAX_CONTEXT  CXLFLASH_MAX_CONTEXT       /* num contexts per afu */

#define CXLFLASH_BLOCK_SIZE	4096	/* 4K blocks */
#define CXLFLASH_MAX_XFER_SIZE	16777216	/* 16MB transfer */
#define CXLFLASH_MAX_SECTORS	(CXLFLASH_MAX_XFER_SIZE/CXLFLASH_BLOCK_SIZE)

#define NUM_RRQ_ENTRY    16     /* for master issued cmds */
#define MAX_RHT_PER_CONTEXT 16  /* num resource hndls per context */

/* Command management definitions */
#define CXLFLASH_NUM_CMDS	(2 * CXLFLASH_MAX_CMDS)	/* Must be a pow2 for 
							   alignment and more 
							   efficient array 
							   index derivation 
							 */

#define CXLFLASH_MAX_CMDS               16
#define CXLFLASH_MAX_CMDS_PER_LUN       CXLFLASH_MAX_CMDS

#define NOT_POW2(_x) ((_x) & ((_x) & ((_x) -1)))
#if NOT_POW2(CXLFLASH_NUM_CMDS)
#error "CXLFLASH_NUM_CMDS is not a power of 2!"
#endif

#define AFU_SYNC_INDEX  (CXLFLASH_NUM_CMDS - 1)	/* last cmd rsvd for afu sync */

#define CMD_FREE   0x0
#define CMD_IN_USE 0x1

#define CMD_BUFSIZE     PAGE_SIZE_4K

/* flags in IOA status area for host use */
#define B_DONE       0x01
#define B_ERROR      0x02	/* set with B_DONE */
#define B_TIMEOUT    0x04	/* set with B_DONE & B_ERROR */

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
#define cxlflash_err(_s,   ...)	pr_err(CONFN(_s),   __func__, ##__VA_ARGS__)
#define cxlflash_warn(_s,  ...)	pr_warn(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cxlflash_info(_s,  ...)	pr_info(CONFN(_s),  __func__, ##__VA_ARGS__)
#define cxlflash_dbg(_s, ...)	pr_debug(CONFN(_s), __func__, ##__VA_ARGS__)

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

enum cxlflash_lr_state {
	LINK_RESET_INVALID,
	LINK_RESET_REQUIRED,
	LINK_RESET_COMPLETE
};

struct cxlflash_ctx {
	struct cxl_ioctl_start_work work;
	int lfd;
	pid_t pid;
	struct cxl_context *ctx;
};

/*
 * Each context has its own set of resource handles that is visible
 * only from that context.
 *
 * The rht_info refers to all resource handles of a context and not to
 * a particular RHT entry or a single resource handle.
 */
struct rht_info {
	struct sisl_rht_entry *rht_start;	/* initialized at startup */
	int ref_cnt;		/* num ctx_infos pointing to me */
	u32 perms;		/* User-defined (@attach) permissions for RHT entries */
};

/* Single AFU context can be pointed to by multiple client connections.
 * The client can create multiple endpoints (mc_hndl_t) to the same
 * (context + AFU).
 */
struct ctx_info {
	volatile struct sisl_ctrl_map *ctrl_map;	/* initialized at startup */
	struct rht_info *rht_info;	/* initialized when context created */

	int ref_cnt;		/* num conn_infos pointing to me */
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

	struct work_struct work_q;
	enum cxlflash_lr_state lr_state;
	int lr_port;

	struct cxl_afu *cxl_afu;
	timer_t timer_hb;
	timer_t timer_fc;

	struct pci_pool *cxlflash_cmd_pool;
	struct pci_dev *parent_dev;

	int num_user_contexts;
	struct cxlflash_ctx per_context[MAX_CONTEXT];
	struct file_operations cxl_fops;

	int last_lun_index;
	int task_set;

	wait_queue_head_t tmf_wait_q;
	u8 context_reset_active:1;
	u8 tmf_active:1;
};

struct afu_cmd {
	struct sisl_ioarcb rcb;	/* IOARCB (cache line aligned) */
	struct sisl_ioasa sa;	/* IOASA must follow IOARCB */
	spinlock_t _slock;
	spinlock_t *slock;
	struct timer_list timer;
	char *buf;		/* per command buffer */
	struct afu *back;
	int slot;
	u8 flag:1;
	u8 special:1;
	u8 internal:1;

} __attribute__ ((aligned(cache_line_size())));

struct afu {
	/* Stuff requiring alignment go first. */

	u64 rrq_entry[NUM_RRQ_ENTRY];	/* 128B RRQ (page aligned) */
	/*
	 * Command & data for AFU commands.
	 */
	struct afu_cmd cmd[CXLFLASH_NUM_CMDS];

	/* Housekeeping data */
	struct ctx_info ctx_info[MAX_CONTEXT];
	struct rht_info rht_info[MAX_CONTEXT];
	struct mutex afu_mutex;	/* for anything that needs serialization
				   e. g. to access afu */
	struct mutex err_mutex;	/* for signalling error thread */
	wait_queue_head_t err_cv;
	int err_flag;
#define E_SYNC_INTR   0x1	/* synchronous error interrupt */
#define E_ASYNC_INTR  0x2	/* asynchronous error interrupt */

	/* AFU Shared Data */
	struct sisl_rht_entry rht[MAX_CONTEXT][MAX_RHT_PER_CONTEXT];
	/* LXTs are allocated dynamically in groups */
	/* Beware of alignment till here. Preferably introduce new
	 * fields after this point 
	 */

	/* AFU HW */
	int afu_fd;
	struct cxl_ioctl_start_work work;
	volatile struct cxlflash_afu_map *afu_map;	/* entire MMIO map */
	volatile struct sisl_host_map *host_map;	/* master's sislite host map */
	volatile struct sisl_ctrl_map *ctrl_map;	/* master's control map */

	ctx_hndl_t ctx_hndl;	/* master's context handle */
	u64 *hrrq_start;
	u64 *hrrq_end;
	volatile u64 *hrrq_curr;
	unsigned int toggle;
	u64 room;
	u64 hb;
	u32 cmd_couts;		/* Number of command checkouts */
	u32 internal_lun;	/* User-desired LUN mode for this AFU */

	char version[8];
	u64 interface_version;

	struct list_head luns;	/* list of lun_info structs */
	struct cxlflash *back;	/* Pointer back to parent cxlflash */

} __attribute__ ((aligned(PAGE_SIZE_4K)));

struct ba_lun {
	u64 lun_id;
	u64 wwpn;
	size_t lsize;		/* Lun size in number of LBAs             */
	size_t lba_size;	/* LBA size in number of bytes            */
	size_t au_size;		/* Allocation Unit size in number of LBAs */
	void *ba_lun_handle;
};

/* Block Alocator */
struct blka {
	struct ba_lun ba_lun;
	u64 nchunk;		/* number of chunks */
	struct mutex mutex;
};

/* LUN discovery results are in lun_info */
struct lun_info {
	u64 lun_id;		/* from REPORT_LUNS */
	u64 max_lba;		/* from read cap(16) */
	u32 blk_len;		/* from read cap(16) */
	u32 lun_index;
	enum open_mode_type mode;

	spinlock_t _slock;
	spinlock_t *slock;

	struct blka blka;
	struct scsi_device *sdev;
	struct list_head list;
};

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

void cxlflash_send_cmd(struct afu *, struct afu_cmd *);
void cxlflash_wait_resp(struct afu *, struct afu_cmd *);
int check_status(struct sisl_ioasa *);
int afu_reset(struct cxlflash *);
struct afu_cmd *cxflash_cmd_checkout(struct afu *);
void cxflash_cmd_checkin(struct afu_cmd *);
int afu_sync(struct afu *, ctx_hndl_t, res_hndl_t, u8);
#endif /* ifndef _CXLFLASH_COMMON_H */

