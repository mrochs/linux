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

#include <linux/delay.h>
#include <linux/file.h>
#include <linux/moduleparam.h>
#include <linux/syscalls.h>
#include <misc/cxl.h>
#include <asm/unaligned.h>

#include <scsi/scsi_host.h>
#include <uapi/scsi/cxlflash_ioctl.h>

#include "sislite.h"
#include "common.h"
#include "superpipe.h"

extern struct cxlflash_global global;

static u32 ws = 0;

/*
 * This is a temporary module parameter
 */
module_param_named(ws, ws, uint, 0);
MODULE_PARM_DESC(ws, " 1 = Perform WRITE_SAME16 per chunk on VLUN shrink");

static void marshall_virt_to_resize(struct dk_cxlflash_uvirtual *virt,
				    struct dk_cxlflash_resize *resize)
{
	resize->hdr = virt->hdr;
	resize->context_id = virt->context_id;
	resize->rsrc_handle = virt->rsrc_handle;
	resize->req_size = virt->lun_size;
	resize->last_lba = virt->last_lba;
}

void marshall_rele_to_resize(struct dk_cxlflash_release *release,
				    struct dk_cxlflash_resize *resize)
{
	resize->hdr = release->hdr;
	resize->context_id = release->context_id;
	resize->rsrc_handle = release->rsrc_handle;
}

int ba_init(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info = NULL;
	int lun_size_au = 0, i = 0;
	int last_word_underflow = 0;
	u64 *lam;

	cxlflash_info("Initializing LUN: lun_id = %llX, "
		      "ba_lun->lsize = %lX, ba_lun->au_size = %lX",
		      ba_lun->lun_id, ba_lun->lsize, ba_lun->au_size);

	/* Calculate bit map size */
	lun_size_au = ba_lun->lsize / ba_lun->au_size;
	if (lun_size_au == 0) {
		cxlflash_err("Requested LUN size of 0!");
		return -EINVAL;
	}

	/* Allocate lun information container */
	lun_info = kzalloc(sizeof(struct ba_lun_info), GFP_KERNEL);
	if (unlikely(!lun_info)) {
		cxlflash_err("Failed to allocate lun_info for lun_id %llX",
			     ba_lun->lun_id);
		return -ENOMEM;
	}

	lun_info->total_aus = lun_size_au;
	lun_info->lun_bmap_size = lun_size_au / 64;

	if (lun_size_au % 64)
		lun_info->lun_bmap_size++;

	/* Allocate bitmap space */
	lun_info->lun_alloc_map = kzalloc((lun_info->lun_bmap_size *
					   sizeof(u64)), GFP_KERNEL);
	if (unlikely(!lun_info->lun_alloc_map)) {
		cxlflash_err("Failed to allocate lun allocation map: "
			     "lun_id = %llX", ba_lun->lun_id);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Initialize the bit map size and set all bits to '1' */
	lun_info->free_aun_cnt = lun_size_au;

	for (i = 0; i < lun_info->lun_bmap_size; i++)
		lun_info->lun_alloc_map[i] = (u64) ~ 0;

	/* If the last word not fully utilized, mark extra bits as allocated */
	last_word_underflow = (lun_info->lun_bmap_size * 64) -
	    lun_info->free_aun_cnt;
	if (last_word_underflow > 0) {
		lam = &lun_info->lun_alloc_map[lun_info->lun_bmap_size - 1];
		for (i = (63 - last_word_underflow + 1); i < 64; i++)
			clear_bit(i, (ulong *)lam);
	}

	/* Initialize high elevator index, low/curr already at 0 from kzalloc */
	lun_info->free_high_idx = lun_info->lun_bmap_size;

	/* Allocate clone map */
	lun_info->aun_clone_map = kzalloc((lun_info->total_aus *
					   sizeof(u8)), GFP_KERNEL);
	if (unlikely(!lun_info->aun_clone_map)) {
		cxlflash_err("Failed to allocate clone map: lun_id = %llX",
			     ba_lun->lun_id);
		kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Pass the allocated lun info as a handle to the user */
	ba_lun->ba_lun_handle = (void *)lun_info;

	cxlflash_info("Successfully initialized the LUN: "
		      "lun_id = %llX, bitmap size = %X, free_aun_cnt = %llX",
		      ba_lun->lun_id, lun_info->lun_bmap_size,
		      lun_info->free_aun_cnt);
	return 0;
}

static int find_free_range(u32 low,
			   u32 high,
			   struct ba_lun_info *lun_info, int *bit_word)
{
	int i;
	u64 bit_pos = -1;
	ulong *lam, num_bits;

	for (i = low; i < high; i++)
		if (lun_info->lun_alloc_map[i] != 0) {
			lam = (ulong *)&lun_info->lun_alloc_map[i];
			num_bits = (sizeof(*lam) * BITS_PER_BYTE);
			bit_pos = find_first_bit(lam, num_bits);

			cxlflash_dbg("Found free bit %llX in lun "
				     "map entry %llX at bitmap index = %X",
				     bit_pos, lun_info->lun_alloc_map[i], i);

			*bit_word = i;
			lun_info->free_aun_cnt--;
			clear_bit(bit_pos, lam);
			break;
		}

	return bit_pos;
}

static u64 ba_alloc(struct ba_lun *ba_lun)
{
	u64 bit_pos = -1;
	int bit_word = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	cxlflash_dbg("Received block allocation request: "
		     "lun_id = %llX, free_aun_cnt = %llX",
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	if (lun_info->free_aun_cnt == 0) {
		cxlflash_err("No space left on LUN: lun_id = %llX",
			     ba_lun->lun_id);
		return -1ULL;
	}

	/* Search to find a free entry, curr->high then low->curr */
	bit_pos = find_free_range(lun_info->free_curr_idx,
				  lun_info->free_high_idx, lun_info, &bit_word);
	if (bit_pos == -1) {
		bit_pos = find_free_range(lun_info->free_low_idx,
					  lun_info->free_curr_idx,
					  lun_info, &bit_word);
		if (bit_pos == -1) {
			cxlflash_err
			    ("Could not find an allocation unit on LUN: "
			     "lun_id = %llX", ba_lun->lun_id);
			return -1ULL;
		}
	}

	/* Update the free_curr_idx */
	if (bit_pos == 63)
		lun_info->free_curr_idx = bit_word + 1;
	else
		lun_info->free_curr_idx = bit_word;

	cxlflash_dbg("Allocating AU number %llX, on lun_id %llX, "
		     "free_aun_cnt = %llX", ((bit_word * 64) + bit_pos),
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	return (u64) ((bit_word * 64) + bit_pos);
}

static int validate_alloc(struct ba_lun_info *lun_info, u64 aun)
{
	int idx = 0, bit_pos = 0;

	idx = aun / 64;
	bit_pos = aun % 64;

	if (test_bit(bit_pos, (ulong *)&lun_info->lun_alloc_map[idx]))
		return -1;

	return 0;
}

static int ba_free(struct ba_lun *ba_lun, u64 to_free)
{
	int idx = 0, bit_pos = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_free)) {
		cxlflash_err("The AUN %llX is not allocated on lun_id %llX",
			     to_free, ba_lun->lun_id);
		return -1;
	}

	cxlflash_dbg("Received a request to free AU %llX on lun_id %llX, "
		     "free_aun_cnt = %llX", to_free, ba_lun->lun_id,
		     lun_info->free_aun_cnt);

	if (lun_info->aun_clone_map[to_free] > 0) {
		cxlflash_info("AUN %llX on lun_id %llX has been cloned. Clone "
			      "count = %X",
			      to_free, ba_lun->lun_id,
			      lun_info->aun_clone_map[to_free]);
		lun_info->aun_clone_map[to_free]--;
		return 0;
	}

	idx = to_free / 64;
	bit_pos = to_free % 64;

	set_bit(bit_pos, (ulong *)&lun_info->lun_alloc_map[idx]);
	lun_info->free_aun_cnt++;

	if (idx < lun_info->free_low_idx)
		lun_info->free_low_idx = idx;
	else if (idx > lun_info->free_high_idx)
		lun_info->free_high_idx = idx;

	cxlflash_dbg("Successfully freed AU at bit_pos %X, bit map index %X on "
		     "lun_id %llX, free_aun_cnt = %llX", bit_pos, idx,
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	return 0;
}

static int ba_clone(struct ba_lun *ba_lun, u64 to_clone)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_clone)) {
		cxlflash_err("AUN %llX is not allocated on lun_id %llX",
			     to_clone, ba_lun->lun_id);
		return -1;
	}

	cxlflash_info("Received a request to clone AUN %llX on lun_id %llX",
		      to_clone, ba_lun->lun_id);

	if (lun_info->aun_clone_map[to_clone] == MAX_AUN_CLONE_CNT) {
		cxlflash_err
		    ("AUN %llX on lun_id %llX has hit max clones already",
		     to_clone, ba_lun->lun_id);
		return -1;
	}

	lun_info->aun_clone_map[to_clone]++;

	return 0;
}

static u64 ba_space(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	return lun_info->free_aun_cnt;
}

void ba_terminate(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (lun_info) {
		if (lun_info->aun_clone_map)
			kfree(lun_info->aun_clone_map);
		if (lun_info->lun_alloc_map)
			kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		ba_lun->ba_lun_handle = NULL;
	}
}

static int cxlflash_init_ba(struct lun_info *lun_info)
{
	int rc = 0;
	struct blka *blka = &lun_info->blka;

	memset(blka, 0, sizeof(*blka));
	mutex_init(&blka->mutex);

	blka->ba_lun.lun_id = lun_info->lun_id;
	blka->ba_lun.lsize = lun_info->max_lba + 1;
	blka->ba_lun.lba_size = lun_info->blk_len;

	blka->ba_lun.au_size = MC_CHUNK_SIZE;
	blka->nchunk = blka->ba_lun.lsize / MC_CHUNK_SIZE;

	rc = ba_init(&blka->ba_lun);
	if (rc) {
		cxlflash_err("cannot init block_alloc, rc=%d", rc);
		goto cxlflash_init_ba_exit;
	}

cxlflash_init_ba_exit:
	cxlflash_info("returning rc=%d lun_info=%p", rc, lun_info);
	return rc;
}

static int write_same16(struct afu *afu, struct lun_info *lun_info, u64 lba,
			u32 nblks)
{
	struct afu_cmd *cmd = NULL;
	int rc = 0;

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		cxlflash_err("could not get a free command");
		rc = -1;
		goto out;
	}

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	cmd->rcb.port_sel = BOTH_PORTS;
	cmd->rcb.lun_id = lun_info->lun_id;
	cmd->rcb.data_len = CMD_BUFSIZE;
	cmd->rcb.data_ea = (u64) cmd->buf; /* Filled w/ zeros on checkout */
	cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	cmd->rcb.cdb[0] = WRITE_SAME_16;
	put_unaligned_be64(lba, &cmd->rcb.cdb[2]);
	put_unaligned_be32(nblks, &cmd->rcb.cdb[10]);

	cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	cxlflash_info("sending cmd(0x%x) with RCB EA=%p data EA=0x%llx",
		      cmd->rcb.cdb[0], &cmd->rcb, cmd->rcb.data_ea);

	do {
		rc = cxlflash_send_cmd(afu, cmd);
		if (!rc)
			cxlflash_wait_resp(afu, cmd);
		else
			break;
	} while (cxlflash_check_status(&cmd->sa));

	if (cmd->sa.host_use_b[0] & B_ERROR) {
		cxlflash_err("command failed");
		rc = -1;
		goto out;
	}

out:
	if (cmd)
		cxlflash_cmd_checkin(cmd);
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

static int grow_lxt(struct afu *afu,
		    struct lun_info *lun_info,
		    ctx_hndl_t ctx_hndl_u,
		    res_hndl_t res_hndl_u,
		    struct sisl_rht_entry *rht_entry,
		    u64 delta,
		    u64 * act_new_size)
{
	struct sisl_lxt_entry *lxt = NULL, *lxt_old = NULL;
	unsigned int av_size;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;
	struct blka *blka = &lun_info->blka;

	/*
	 * Check what is available in the block allocator before re-allocating
	 * LXT array. This is done up front under the mutex which must not be
	 * released until after allocation is complete.
	 */
	mutex_lock(&blka->mutex);
	av_size = ba_space(&blka->ba_lun);
	if (av_size <= 0)
	{
		cxlflash_err("ba_space error: av_size %d", av_size);
		mutex_unlock(&blka->mutex);
		return -ENOSPC;
	}

	if (av_size < delta)
		delta = av_size;

	lxt_old = rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(rht_entry->lxt_cnt + delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size */
		lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (unlikely(!lxt)) {
			mutex_unlock(&blka->mutex);
			return -ENOMEM;
		}

		/* copy over all old entries */
		memcpy(lxt, lxt_old, (sizeof(*lxt) *
					  rht_entry->lxt_cnt));
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	*act_new_size = rht_entry->lxt_cnt + delta;

	/* add new entries to the end */
	for (i = rht_entry->lxt_cnt; i < *act_new_size; i++) {
		/*
		 * Due to the earlier check of available space, ba_alloc
		 * cannot fail here. If it did due to internal error,
		 * leave a rlba_base of -1u which will likely be a
		 * invalid LUN (too large).
		 */
		aun = ba_alloc(&blka->ba_lun);
		if ((aun == -1ULL) || (aun >= blka->nchunk))
			cxlflash_err("ba_alloc error: allocated chunk# %llX, "
				     "max %llX", aun, blka->nchunk - 1);

		/* select both ports, use r/w perms from RHT */
		lxt[i].rlba_base = ((aun << MC_CHUNK_SHIFT) |
				    (lun_info->lun_index << LXT_LUNIDX_SHIFT) |
				    (RHT_PERM_RW << LXT_PERM_SHIFT | 
				     BOTH_PORTS));
	}

	mutex_unlock(&blka->mutex);

	smp_wmb();		/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_start = lxt;	/* even if lxt didn't change */
	smp_wmb();

	rht_entry->lxt_cnt = *act_new_size;
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	cxlflash_dbg("returning");
	return 0;
}

static int shrink_lxt(struct afu *afu,
		      struct lun_info *lun_info,
		      ctx_hndl_t ctx_hndl_u,
		      res_hndl_t res_hndl_u,
		      struct sisl_rht_entry *rht_entry,
		      u64 delta, u64 * act_new_size)
{
	struct sisl_lxt_entry *lxt, *lxt_old;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;
	struct blka *blka = &lun_info->blka;

	lxt_old = rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(rht_entry->lxt_cnt - delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size unless new size is 0 */
		if (ngrps) {
			lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE *
					 ngrps), GFP_KERNEL);
			if (unlikely(!lxt))
				return -ENOMEM;

			/* copy over old entries that will remain */
			memcpy(lxt, lxt_old, (sizeof(*lxt) *
						  (rht_entry->lxt_cnt -
						   delta)));
		} else
			lxt = NULL;
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	*act_new_size = rht_entry->lxt_cnt - delta;

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_cnt = *act_new_size;
	smp_wmb();		/* also makes lxt updates visible */

	rht_entry->lxt_start = lxt;	/* even if lxt didn't change */
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_HW_SYNC);

	/* free LBAs allocated to freed chunks */
	mutex_lock(&blka->mutex);
	for (i = delta - 1; i >= 0; i--) {
		/* Mask the higher 48 bits before shifting, even though
		 * it is a noop
		 */
		aun = ((lxt_old[*act_new_size + i].rlba_base &
			SISL_ASTATUS_MASK) >> MC_CHUNK_SHIFT);
		if (ws)
			write_same16(afu, lun_info, aun, MC_CHUNK_SIZE);
		ba_free(&blka->ba_lun, aun);
	}
	mutex_unlock(&blka->mutex);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	cxlflash_dbg("returning");
	return 0;
}

/*
 * NAME:	cxlflash_vlun_resize()
 *
 * FUNCTION:	Resize a resource handle by changing the RHT entry and LXT
 *		Tbl it points to. Synchronize all contexts that refer to
 *		the RHT.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *		act_new_size	- pointer to actual new size in chunks
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 *		Setting new_size=0 will clear LXT_START and LXT_CNT fields
 *		in the RHT entry.
 */
int cxlflash_vlun_resize(struct scsi_device *sdev,
			 struct dk_cxlflash_resize *resize)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cfg->afu;

	u64 act_new_size = 0;
	res_hndl_t res_hndl = resize->rsrc_handle;
	u64 new_size;
	u64 nsectors;
	u64 ctxid = resize->context_id;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry;

	int rc = 0;

	/* req_size is always assumed to be in 4k blocks. So we have to convert
	 * it from 4k to chunk size
	 */
	nsectors = (resize->req_size * CXLFLASH_BLOCK_SIZE) /
	    (lun_info->blk_len);
	new_size = (nsectors + MC_CHUNK_SIZE - 1) / MC_CHUNK_SIZE;

	cxlflash_info("ctxid=%llu res_hndl=0x%llx, req_size=0x%llx,"
		      "new_size=%llx", ctxid, resize->rsrc_handle,
		      resize->req_size, new_size);

	if (unlikely(lun_info->mode != MODE_VIRTUAL)) {
		cxlflash_err("LUN mode does not support resize! (%d)",
			     lun_info->mode);
		rc = -EINVAL;
		goto out;

	}

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = cxlflash_get_rhte(ctx_info, res_hndl, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("Invalid resource handle! (%u)", res_hndl);
		rc = -EINVAL;
		goto out;
	}

	if (new_size > rht_entry->lxt_cnt)
		rc = grow_lxt(afu,
			      lun_info,
			      ctxid,
			      res_hndl,
			      rht_entry,
			      new_size - rht_entry->lxt_cnt,
			      &act_new_size);
	else if (new_size < rht_entry->lxt_cnt)
		rc = shrink_lxt(afu,
				lun_info,
				ctxid,
				res_hndl,
				rht_entry,
				rht_entry->lxt_cnt - new_size,
				&act_new_size);
	else
		act_new_size = new_size;

	resize->hdr.return_flags = 0;
	resize->last_lba = (((act_new_size * MC_CHUNK_SIZE *
			    lun_info->blk_len) / CXLFLASH_BLOCK_SIZE) - 1);

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("resized to %lld returning rc=%d", resize->last_lba, rc);
	return rc;
}

/* NAME:	cxlflash_disk_virtual_open
 *	
 * FUNCTION:	open a virtual lun of specified size	
 *	
 * INPUTS:	
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *	
 * OUTPUTS:	
 *              none
 *	
 * RETURNS:	
 *              0           - Success
 *              errno       - Failure
 *	
 * NOTES:	
 *		When successful:	
 *		a. find a free RHT entry	
 *		b. Resize to requested size
 *	
 */
int cxlflash_disk_virtual_open(struct scsi_device *sdev, void *arg)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;

	struct dk_cxlflash_uvirtual *virt = (struct dk_cxlflash_uvirtual *)arg;
	struct dk_cxlflash_resize resize;

	u64 ctxid = virt->context_id;
	u64 lun_size = virt->lun_size;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry = NULL;

	cxlflash_info("ctxid=%llu ls=0x%llx", ctxid, lun_size);

	if (lun_info->mode == MODE_NONE) {
		rc = cxlflash_init_ba(lun_info);
		if (rc) {
			cxlflash_err("call to cxlflash_init_ba failed "
				     "rc=%d!", rc);
			rc = -ENOMEM;
			goto out;
		}
	}

	rc = cxlflash_lun_attach(lun_info, MODE_VIRTUAL);
	if (unlikely(rc)) {
		cxlflash_err("Failed to attach to LUN! mode=%u", MODE_VIRTUAL);
		goto out;
	}

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto err1;
	}

	rht_entry = rhte_checkout(ctx_info, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("too many opens for this context");
		rc = -EMFILE;	/* too many opens  */
		goto err1;
	}

	rsrc_handle = (rht_entry - ctx_info->rht_start);

	rht_entry->nmask = MC_RHT_NMASK;
	rht_entry->fp = SISL_RHT_FP(0U, ctx_info->rht_perms);
	/* format 0 & perms */

	/* Resize even if requested size is 0 */
	marshall_virt_to_resize(virt, &resize);
	resize.rsrc_handle = rsrc_handle;
	rc = cxlflash_vlun_resize(sdev, &resize);
	if (rc) {
		cxlflash_err("resize failed rc %d", rc);
		goto err2;
	}
	last_lba = resize.last_lba;

	virt->hdr.return_flags = 0;
	virt->last_lba = last_lba;
	virt->rsrc_handle = rsrc_handle;

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("returning handle 0x%llx rc=%d llba %lld",
		      rsrc_handle, rc, last_lba);
	return rc;

err2:
	rhte_checkin(ctx_info, rht_entry);
err1:
	cxlflash_lun_detach(lun_info);
	goto out;
}

/*
 * NAME:	cxlflash_clone_lxt()
 *
 * FUNCTION:	clone a LXT table
 *
 * INPUTS:
 *		afu		- Pointer to afu struct
 *		ctx_hndl_u	- context that owns the destination LXT
 *		res_hndl_u	- res_hndl of the destination LXT
 *		rht_entry	- destination RHT to clone into
 *		rht_entry_src	- source RHT to clone from
 *
 * OUTPUTS:
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 */
int cxlflash_clone_lxt(struct afu *afu,
		       struct blka *blka,
		       ctx_hndl_t ctx_hndl_u,
		       res_hndl_t res_hndl_u,
		       struct sisl_rht_entry *rht_entry,
		       struct sisl_rht_entry *rht_entry_src)
{
	struct sisl_lxt_entry *lxt;
	unsigned int ngrps;
	u64 aun;		/* chunk# allocated by block allocator */
	int i, j;

	ngrps = LXT_NUM_GROUPS(rht_entry_src->lxt_cnt);

	if (ngrps) {
		/* allocate new LXTs for clone */
		lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (unlikely(!lxt))
			return -ENOMEM;

		/* copy over */
		memcpy(lxt, rht_entry_src->lxt_start,
		       (sizeof(*lxt) * rht_entry_src->lxt_cnt));

		/* clone the LBAs in block allocator via ref_cnt */
		mutex_lock(&blka->mutex);
		for (i = 0; i < rht_entry_src->lxt_cnt; i++) {
			aun = (lxt[i].rlba_base >> MC_CHUNK_SHIFT);
			if (ba_clone(&blka->ba_lun, aun) == -1ULL) {
				/* free the clones already made */
				for (j = 0; j < i; j++) {
					aun = (lxt[j].rlba_base >>
					       MC_CHUNK_SHIFT);
					ba_free(&blka->ba_lun, aun);
				}

				mutex_unlock(&blka->mutex);
				kfree(lxt);
				return -EIO;
			}
		}
		mutex_unlock(&blka->mutex);
	} else {
		lxt = NULL;
	}

	smp_wmb();		/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_start = lxt;	/* even if lxt is NULL */
	smp_wmb();

	rht_entry->lxt_cnt = rht_entry_src->lxt_cnt;
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	cxlflash_dbg("returning");
	return 0;
}

