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

typedef unsigned int useconds_t;	/* time in microseconds */
extern u32 checkpid;
extern u32 internal_lun;

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

#define MAX_AUN_CLONE_CNT    0xFF

enum open_mode_type {
	MODE_NONE = 0,
	MODE_VIRTUAL,
	MODE_PHYSICAL
};

static inline u64 lun_to_lunid(u64 lun)
{
	u64 lun_id;

	int_to_scsilun(lun, (struct scsi_lun *)&lun_id);
	return swab64(lun_id);
}

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
#define LXT_LUNIDX_SHIFT  8	/* LXT entry, shift for LUN index */

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

#define CMD_BUFSIZE	PAGE_SIZE_4K


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
#endif /* ifndef _CXLFLASH_SUPERPIPE_H */
