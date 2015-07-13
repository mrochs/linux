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

#ifndef _CXLFLASH_SUPERPIPE_H
#define _CXLFLASH_SUPERPIPE_H

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

#define MAX_AUN_CLONE_CNT    0xFF

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
#define LXT_LUNIDX_SHIFT  8	/* LXT entry, shift for LUN index */
#define LXT_PERM_SHIFT    4	/* LXT entry, shift for permission bits */

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

#define MC_DISCOVERY_TIMEOUT 5  /* 5 secs */

#define CHAN2PORT(_x)	((_x) + 1)
#define PORT2CHAN(_x)	((_x) - 1)

enum lun_mode {
	MODE_NONE = 0,
	MODE_VIRTUAL,
	MODE_PHYSICAL
};

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

struct ba_lun {
	u64 lun_id;
	u64 wwpn;
	size_t lsize;		/* LUN size in number of LBAs             */
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

	u8 *aun_clone_map;
};

/* Block Allocator */
struct blka {
	struct ba_lun ba_lun;
	u64 nchunk;		/* number of chunks */
	struct mutex mutex;
};

/* Global (entire driver, spans adapters) lun_info structure */
struct glun_info {
	u64 max_lba;		/* from read cap(16) */
	u32 blk_len;		/* from read cap(16) */
	enum lun_mode mode;	/* NONE, VIRTUAL, PHYSICAL */
	int users;		/* Number of users w/ references to LUN */

	u8 wwid[16];

	spinlock_t slock;

	struct blka blka;
	struct list_head list;
};

/* Local (per-adapter) lun_info structure */
struct llun_info {
	u64 lun_id[CXLFLASH_NUM_FC_PORTS]; /* from REPORT_LUNS */
	u32 lun_index;		/* Index in the lun table */
	u32 host_no;		/* host_no from Scsi_host */
	u32 port_sel;		/* What port to use for this LUN */
	bool newly_created;	/* Whether the LUN was just discovered */
	bool in_table;		/* Whether a LUN table entry was created */

	u8 wwid[16];		/* Keep a duplicate copy here? */

	struct glun_info *parent; /* Pointer to entry in global lun structure */
	struct scsi_device *sdev;
	struct list_head list;
};

struct lun_access {
	void *lli;
	struct scsi_device *sdev;
	struct list_head list;
};

enum ctx_ctrl {
	CTX_CTRL_CLONE		= (1 << 1),
	CTX_CTRL_ERR		= (1 << 2),
	CTX_CTRL_ERR_FALLBACK	= (1 << 3),
	CTX_CTRL_NOPID		= (1 << 4),
	CTX_CTRL_FILE		= (1 << 5)
};

#define ENCODE_CTXID(_ctx, _id)	(((((u64)_ctx) & 0xFFFFFFFF0) << 28) | _id)
#define DECODE_CTXID(_val)	(_val & 0xFFFFFFFF)

struct ctx_info {
	struct sisl_ctrl_map *ctrl_map; /* initialized at startup */
	struct sisl_rht_entry *rht_start; /* 1 page (req'd for alignment),
					     alloc/free on attach/detach */
	u32 rht_out;		/* Number of checked out RHT entries */
	u32 rht_perms;		/* User-defined permissions for RHT entries */
	struct llun_info **rht_lun; /* Mapping of RHT entries to LUNs */

	struct cxl_ioctl_start_work work;
	u64 ctxid;
	int lfd;
	pid_t pid;
	atomic_t nrefs;	/* Number of active references, must be 0 for removal */
	bool err_recovery_active;
	struct cxl_context *ctx;
	struct list_head luns;	/* LUNs attached to this context */
	const struct vm_operations_struct *cxl_mmap_vmops;
	struct file *file;
	struct list_head list; /* Link contexts in error recovery */
};

struct cxlflash_global {
	spinlock_t slock;
	struct list_head gluns;/* list of glun_info structs */
	struct page *err_page; /* One page of all 0xF for error notification */
};


int cxlflash_vlun_resize(struct scsi_device *, struct dk_cxlflash_resize *);

int cxlflash_disk_release(struct scsi_device *, struct dk_cxlflash_release *);

int cxlflash_disk_clone(struct scsi_device *, struct dk_cxlflash_clone *);

int cxlflash_disk_virtual_open(struct scsi_device *, void *);

int cxlflash_lun_attach(struct glun_info *, enum lun_mode);
void cxlflash_lun_detach(struct glun_info *);

int cxlflash_check_status(struct afu_cmd *);

struct ctx_info *get_context(struct cxlflash_cfg *, u64, void *, enum ctx_ctrl);

struct sisl_rht_entry *get_rhte(struct ctx_info *, res_hndl_t,
				struct llun_info *);

struct sisl_rht_entry *rhte_checkout(struct ctx_info *, struct llun_info *);
void rhte_checkin(struct ctx_info *, struct sisl_rht_entry *);

void cxlflash_ba_terminate(struct ba_lun *);

#endif /* ifndef _CXLFLASH_SUPERPIPE_H */
