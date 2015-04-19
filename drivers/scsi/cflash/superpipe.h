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
#define MAX_AUN_CLONE_CNT    0xFF
#define MAX_CXLFLASH_IOCTL_SZ	(sizeof(union cxlflash_ioctls))

enum cxlflash_lr_state {
	LINK_RESET_INVALID,
	LINK_RESET_REQUIRED,
	LINK_RESET_COMPLETE
};

struct cxlflash_ctx {
	struct cxl_ioctl_start_work work;
	int lfd;
	pid_t pid;
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

	int num_user_contexts;
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

/*
 * Terminology: use afu (and not adapter) to refer to the HW.
 * Adapter is the entire slot and includes PSL out of which
 * only the AFU is visible to user space.
 */

/* Chunk size parms: note sislite minimum chunk size is
   0x10000 LBAs corresponding to a NMASK or 16.
*/
#define MC_RHT_NMASK      16	/* in bits */
#define MC_CHUNK_SIZE     (1 << MC_RHT_NMASK)	/* in LBAs, see mclient.h */
#define MC_CHUNK_SHIFT    MC_RHT_NMASK	/* shift to go from LBA to chunk# */
#define MC_CHUNK_OFF_MASK (MC_CHUNK_SIZE - 1)	/* apply to LBA get offset
						   into a chunk */
#define LXT_LUNIDX_SHIFT  8     /* LXT entry, shift for LUN index */

#define MAX_RHT_PER_CONTEXT 16	/* num resource hndls per context */
#define NUM_RRQ_ENTRY    16	/* for master issued cmds */
#define NUM_FC_PORTS     CXLFLASH_NUM_FC_PORTS	/* ports per AFU */

/* LXT tables are allocated dynamically in groups. This is done to
   avoid a malloc/free overhead each time the LXT has to grow
   or shrink.

   Based on the current lxt_cnt (used), it is always possible to
   know how many are allocated (used+free). The number of allocated
   entries is not stored anywhere.

   The LXT table is re-allocated whenever it needs to cross into
   another group.
*/
#define LXT_GROUP_SIZE          8
#define LXT_NUM_GROUPS(lxt_cnt) (((lxt_cnt) + 7)/8)	/* alloc'ed groups */

/* flags in IOA status area for host use */
#define B_DONE       0x01
#define B_ERROR      0x02	/* set with B_DONE */
#define B_TIMEOUT    0x04	/* set with B_DONE & B_ERROR */

struct scsi_inquiry_page_83_hdr {
	u8 peri_qual_dev_type;
	u8 page_code;
	u16 adtl_page_length;	/* not counting 4 byte hdr */
	/* Identification Descriptor list */
};

struct scsi_inquiry_p83_id_desc_hdr {
	u8 prot_code;		/* Protocol Identifier & Code Set */
#define TEXAN_PAGE_83_DESC_PROT_CODE             0x01u
	u8 assoc_id;		/* PIV/Association/Identifier type */
#define TEXAN_PAGE_83_ASSC_ID_LUN_WWID           0x03u
	u8 reserved;
	u8 adtl_id_length;
	/* Identifier Data */
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
	int ref_cnt;	/* num ctx_infos pointing to me */
	u32 perms;	/* User-defined (@attach) permissions for RHT entries */
};

/* Single AFU context can be pointed to by multiple client connections.
 * The client can create multiple endpoints (mc_hndl_t) to the same
 * (context + AFU).
 */
struct ctx_info {
	volatile struct sisl_ctrl_map *ctrl_map;/* initialized at startup */
	struct rht_info *rht_info;	/* initialized when context created */

	int ref_cnt;		/* num conn_infos pointing to me */
};

/* Block Alocator */
struct blka {
	struct ba_lun ba_lun;
	u64 nchunk;		/* number of chunks */
	struct mutex mutex;
};

/* LUN discovery results are in lun_info */
struct lun_info {
	u64 lun_id;	/* from REPORT_LUNS */
	u64 max_lba;	/* from read cap(16) */
	u32 blk_len;	/* from read cap(16) */
	u32 lun_index;
	enum open_mode_type mode;

	spinlock_t _slock;
	spinlock_t *slock;

	struct blka blka;
	struct scsi_device *sdev;
	struct list_head list;
};

#define CMD_BUFSIZE 0x1000

struct afu_cmd {
	struct sisl_ioarcb_s rcb;	/* IOARCB (cache line aligned) */
	struct sisl_ioasa_s sa;		/* IOASA must follow IOARCB */
	spinlock_t _slock;
	spinlock_t *slock;
	struct timer_list timer;
	char *buf;                      /* per command buffer */
	int slot;
	u8 flag:1;
	u8 special:1;

} __attribute__ ((aligned(0x80)));

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
	struct cxlflash *back;  /* Pointer back to parent cxlflash */

} __attribute__ ((aligned(0x1000)));

int read_cap16(struct afu *p_afu, struct lun_info *p_lun_info, u32 port_sel);
int afu_sync(struct afu *p_afu, ctx_hndl_t ctx_hndl_u, res_hndl_t res_hndl_u,
	     u8 mode);

struct afu_cmd *cmd_checkout(struct afu *p_afu);
void cmd_checkin(struct afu_cmd *p_cmd);
void cxlflash_rht_format1(struct sisl_rht_entry *, u64, u32);
int check_status(struct sisl_ioasa_s *);
void cxlflash_send_cmd(struct afu *, struct afu_cmd *);
void cxlflash_wait_resp(struct afu *, struct afu_cmd *);
void cxlflash_scan_luns(struct cxlflash *);
int afu_reset(struct cxlflash *);
#endif /* ifndef _CXLFLASHMC_H */
