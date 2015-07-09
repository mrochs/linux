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

static u32 ws;

/*
 * This is a temporary module parameter
 */
module_param_named(ws, ws, uint, 0);
MODULE_PARM_DESC(ws, " 1 = Perform WRITE_SAME16 per chunk on VLUN shrink");

/**
 * marshall_virt_to_resize() - translate uvirtual to resize structure
 * @virt:	Source structure from which to translate/copy.
 * @resize:	Destination structure for the translate/copy.
 */
static void marshall_virt_to_resize(struct dk_cxlflash_uvirtual *virt,
				    struct dk_cxlflash_resize *resize)
{
	resize->hdr = virt->hdr;
	resize->context_id = virt->context_id;
	resize->rsrc_handle = virt->rsrc_handle;
	resize->req_size = virt->lun_size;
	resize->last_lba = virt->last_lba;
}

/**
 * marshall_clone_to_rele() - translate clone to release structure
 * @clone:	Source structure from which to translate/copy.
 * @rele:	Destination structure for the translate/copy.
 */
static void marshall_clone_to_rele(struct dk_cxlflash_clone *clone,
				   struct dk_cxlflash_release *release)
{
	release->hdr = clone->hdr;
	release->context_id = clone->context_id_dst;
}

/**
 * ba_init() - initializes a block allocator
 * @ba_lun:	Block allocator to initialize.
 *
 * Return: 0 on success, -errno on failure
 */
static int ba_init(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info = NULL;
	int lun_size_au = 0, i = 0;
	int last_word_underflow = 0;
	u64 *lam;

	pr_debug("%s: Initializing LUN: lun_id = %llX, "
		 "ba_lun->lsize = %lX, ba_lun->au_size = %lX\n",
		__func__, ba_lun->lun_id, ba_lun->lsize, ba_lun->au_size);

	/* Calculate bit map size */
	lun_size_au = ba_lun->lsize / ba_lun->au_size;
	if (lun_size_au == 0) {
		pr_err("%s: Requested LUN size of 0!\n", __func__);
		return -EINVAL;
	}

	/* Allocate lun information container */
	lun_info = kzalloc(sizeof(struct ba_lun_info), GFP_KERNEL);
	if (unlikely(!lun_info)) {
		pr_err("%s: Failed to allocate lun_info for lun_id %llX\n",
		       __func__, ba_lun->lun_id);
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
		pr_err("%s: Failed to allocate lun allocation map: "
		       "lun_id = %llX\n", __func__, ba_lun->lun_id);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Initialize the bit map size and set all bits to '1' */
	lun_info->free_aun_cnt = lun_size_au;

	for (i = 0; i < lun_info->lun_bmap_size; i++)
		lun_info->lun_alloc_map[i] = 0xFFFFFFFFFFFFFFFFULL;

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
		pr_err("%s: Failed to allocate clone map: lun_id = %llX\n",
		       __func__, ba_lun->lun_id);
		kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Pass the allocated lun info as a handle to the user */
	ba_lun->ba_lun_handle = (void *)lun_info;

	pr_debug("%s: Successfully initialized the LUN: "
		 "lun_id = %llX, bitmap size = %X, free_aun_cnt = %llX\n",
		__func__, ba_lun->lun_id, lun_info->lun_bmap_size,
		lun_info->free_aun_cnt);
	return 0;
}

/**
 * find_free_range() - locates a free bit within the block allocator
 * @low:	First word in block allocator to start search.
 * @high:	Last word in block allocator to search.
 * @lun_info:	LUN information structure owning the block allocator to search.
 * @bit_word:	Passes back the word in the block allocator owning the free bit.
 *
 * Return: The bit position within the passed back word, -1 on failure
 */
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

			pr_devel("%s: Found free bit %llX in lun "
				 "map entry %llX at bitmap index = %X\n",
				 __func__, bit_pos, lun_info->lun_alloc_map[i],
				 i);

			*bit_word = i;
			lun_info->free_aun_cnt--;
			clear_bit(bit_pos, lam);
			break;
		}

	return bit_pos;
}

/**
 * ba_alloc() - allocates a block from the block allocator
 * @ba_lun:	Block allocator from which to allocate a block.
 *
 * Return: The allocated block, -1 on failure
 */
static u64 ba_alloc(struct ba_lun *ba_lun)
{
	u64 bit_pos = -1;
	int bit_word = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	pr_debug("%s: Received block allocation request: "
		 "lun_id = %llX, free_aun_cnt = %llX\n",
		 __func__, ba_lun->lun_id, lun_info->free_aun_cnt);

	if (lun_info->free_aun_cnt == 0) {
		pr_err("%s: No space left on LUN: lun_id = %llX\n",
		       __func__, ba_lun->lun_id);
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
			pr_err("%s: Could not find an allocation unit on LUN: "
			       "lun_id = %llX\n", __func__, ba_lun->lun_id);
			return -1ULL;
		}
	}

	/* Update the free_curr_idx */
	if (bit_pos == 63)
		lun_info->free_curr_idx = bit_word + 1;
	else
		lun_info->free_curr_idx = bit_word;

	pr_debug("%s: Allocating AU number %llX, on lun_id %llX, "
		 "free_aun_cnt = %llX\n", __func__,
		 ((bit_word * 64) + bit_pos), ba_lun->lun_id,
		 lun_info->free_aun_cnt);

	return (u64) ((bit_word * 64) + bit_pos);
}

/**
 * validate_alloc() - validates the specified block has been allocated
 * @ba_lun_info:	LUN info owning the block allocator.
 * @aun:		Block to validate.
 *
 * Return: 0 on success, -1 on failure
 */
static int validate_alloc(struct ba_lun_info *lun_info, u64 aun)
{
	int idx = 0, bit_pos = 0;

	idx = aun / 64;
	bit_pos = aun % 64;

	if (test_bit(bit_pos, (ulong *)&lun_info->lun_alloc_map[idx]))
		return -1;

	return 0;
}

/**
 * ba_free() - frees a block from the block allocator
 * @ba_lun:	Block allocator from which to allocate a block.
 * @to_free:	Block to free.
 *
 * Return: 0 on success, -1 on failure
 */
static int ba_free(struct ba_lun *ba_lun, u64 to_free)
{
	int idx = 0, bit_pos = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_free)) {
		pr_err("%s: The AUN %llX is not allocated on lun_id %llX\n",
		       __func__, to_free, ba_lun->lun_id);
		return -1;
	}

	pr_debug("%s: Received a request to free AU %llX on lun_id %llX, "
		 "free_aun_cnt = %llX\n", __func__, to_free, ba_lun->lun_id,
		 lun_info->free_aun_cnt);

	if (lun_info->aun_clone_map[to_free] > 0) {
		pr_debug("%s: AUN %llX on lun_id %llX has been cloned. Clone "
			 "count = %X\n", __func__, to_free, ba_lun->lun_id,
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

	pr_debug("%s: Successfully freed AU at bit_pos %X, bit map index %X on "
		 "lun_id %llX, free_aun_cnt = %llX\n", __func__, bit_pos, idx,
		 ba_lun->lun_id, lun_info->free_aun_cnt);

	return 0;
}

/**
 * ba_clone() - frees a block from the block allocator
 * @ba_lun:	Block allocator from which to allocate a block.
 * @to_free:	Block to free.
 *
 * Return: 0 on success, -1 on failure
 */
static int ba_clone(struct ba_lun *ba_lun, u64 to_clone)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_clone)) {
		pr_err("%s: AUN %llX is not allocated on lun_id %llX\n",
		       __func__, to_clone, ba_lun->lun_id);
		return -1;
	}

	pr_debug("%s: Received a request to clone AUN %llX on lun_id %llX\n",
		 __func__, to_clone, ba_lun->lun_id);

	if (lun_info->aun_clone_map[to_clone] == MAX_AUN_CLONE_CNT) {
		pr_err("%s: AUN %llX on lun_id %llX hit max clones already\n",
		       __func__, to_clone, ba_lun->lun_id);
		return -1;
	}

	lun_info->aun_clone_map[to_clone]++;

	return 0;
}

/**
 * ba_space() - returns the amount of free space left in the block allocator
 * @ba_lun:	Block allocator.
 *
 * Return: Amount of free space in block allocator
 */
static u64 ba_space(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	return lun_info->free_aun_cnt;
}

/**
 * cxlflash_ba_terminate() - frees resources associated with the block allocator
 * @ba_lun:	Block allocator.
 *
 * Safe to call in a partially allocated state.
 */
void cxlflash_ba_terminate(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (lun_info) {
		kfree(lun_info->aun_clone_map);
		kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		ba_lun->ba_lun_handle = NULL;
	}
}

/**
 * init_ba() - initializes and allocates a block allocator
 * @lun_info:	LUN information structure that owns the block allocator.
 *
 * Return: 0 on success, -errno on failure
 */
static int init_ba(struct llun_info *lli)
{
	int rc = 0;
	struct blka *blka = &lli->parent->blka;

	memset(blka, 0, sizeof(*blka));
	mutex_init(&blka->mutex);

	/* LUN IDs are unique per port, save the index instead */
	blka->ba_lun.lun_id = lli->lun_index;
	blka->ba_lun.lsize = lli->parent->max_lba + 1;
	blka->ba_lun.lba_size = lli->parent->blk_len;

	blka->ba_lun.au_size = MC_CHUNK_SIZE;
	blka->nchunk = blka->ba_lun.lsize / MC_CHUNK_SIZE;

	rc = ba_init(&blka->ba_lun);
	if (rc) {
		pr_err("%s: cannot init block_alloc, rc=%d\n", __func__, rc);
		goto init_ba_exit;
	}

init_ba_exit:
	pr_debug("%s: returning rc=%d lli=%p\n", __func__, rc, lli);
	return rc;
}

/**
 * write_same16() - sends a SCSI WRITE_SAME16 (0) command to specified LUN
 * @afu:	AFU associated with the host.
 * @sdev:	SCSI device associated with LUN.
 * @lba:	Logical block address to start write same.
 * @nblks:	Number of logical blocks to write same.
 *
 * Return: 0 on success, -1 on failure
 */
static int write_same16(struct afu *afu,
			struct scsi_device *sdev,
			u64 lba,
			u32 nblks)
{
	struct afu_cmd *cmd = NULL;
	struct llun_info *lli = sdev->hostdata;
	int rc = 0;

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		pr_err("%s: could not get a free command\n", __func__);
		rc = -1;
		goto out;
	}

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
			      SISL_REQ_FLAGS_SUP_UNDERRUN |
			      SISL_REQ_FLAGS_HOST_READ);

	cmd->rcb.port_sel = CHAN2PORT(sdev->channel);
	cmd->rcb.lun_id = lli->lun_id[sdev->channel];
	cmd->rcb.data_len = CMD_BUFSIZE;
	cmd->rcb.data_ea = (u64) cmd->buf; /* Filled w/ zeros on checkout */
	cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	cmd->rcb.cdb[0] = WRITE_SAME_16;
	put_unaligned_be64(lba, &cmd->rcb.cdb[2]);
	put_unaligned_be32(nblks, &cmd->rcb.cdb[10]);

	pr_debug("%s: sending cmd(0x%x) with RCB EA=%p data EA=0x%llx\n",
		 __func__, cmd->rcb.cdb[0], &cmd->rcb, cmd->rcb.data_ea);

	do {
		rc = cxlflash_send_cmd(afu, cmd);
		if (unlikely(rc))
			break;
		cxlflash_wait_resp(afu, cmd);
	} while (cxlflash_check_status(cmd));

	if (unlikely(cmd->sa.host_use_b[0] & B_ERROR)) {
		pr_err("%s: command failed\n", __func__);
		rc = -1;
		goto out;
	}

out:
	if (cmd)
		cxlflash_cmd_checkin(cmd);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * grow_lxt() - expands the translation table associated with the specified RHTE
 * @afu:	AFU associated with the host.
 * @sdev:	SCSI device associated with LUN.
 * @ctx_hndl_u:	Context ID of context owning the RHTE.
 * @res_hndl_u:	Resource handle associated with the RHTE.
 * @rht_entry:	Resource handle entry (RHTE).
 * @new_size:	Number of translation entries associated with RHTE.
 * @port_sel:	Port selection mask.
 *
 * By design, this routine employs a 'best attempt' allocation and will
 * truncate the requested size down if there is not sufficient space in
 * the block allocator to satisfy the request but there does exist some
 * amount of space. The user is made aware of this by returning the size
 * allocated.
 *
 * Return: 0 on success, -errno on failure
 */
static int grow_lxt(struct afu *afu,
		    struct scsi_device *sdev,
		    ctx_hndl_t ctx_hndl_u,
		    res_hndl_t res_hndl_u,
		    struct sisl_rht_entry *rht_entry,
		    u64 *new_size)
{
	struct sisl_lxt_entry *lxt = NULL, *lxt_old = NULL;
	struct llun_info *lli = sdev->hostdata;
	u32 av_size;
	u32 ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	u64 delta = *new_size - rht_entry->lxt_cnt;
	u64 my_new_size;
	int i, rc = 0;
	struct blka *blka = &lli->parent->blka;

	/*
	 * Check what is available in the block allocator before re-allocating
	 * LXT array. This is done up front under the mutex which must not be
	 * released until after allocation is complete.
	 */
	mutex_lock(&blka->mutex);
	av_size = ba_space(&blka->ba_lun);
	if (unlikely(av_size <= 0)) {
		pr_err("%s: ba_space error: av_size %d\n", __func__, av_size);
		mutex_unlock(&blka->mutex);
		rc = -ENOSPC;
		goto out;
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
			rc = -ENOMEM;
			goto out;
		}

		/* copy over all old entries */
		memcpy(lxt, lxt_old, (sizeof(*lxt) *
					  rht_entry->lxt_cnt));
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	my_new_size = rht_entry->lxt_cnt + delta;

	/* add new entries to the end */
	for (i = rht_entry->lxt_cnt; i < my_new_size; i++) {
		/*
		 * Due to the earlier check of available space, ba_alloc
		 * cannot fail here. If it did due to internal error,
		 * leave a rlba_base of -1u which will likely be a
		 * invalid LUN (too large).
		 */
		aun = ba_alloc(&blka->ba_lun);
		if ((aun == -1ULL) || (aun >= blka->nchunk))
			pr_err("%s: ba_alloc error: allocated chunk# %llX, "
			       "max %llX\n", __func__, aun, blka->nchunk - 1);

		/* select both ports, use r/w perms from RHT */
		lxt[i].rlba_base = ((aun << MC_CHUNK_SHIFT) |
				    (lli->lun_index << LXT_LUNIDX_SHIFT) |
				    (RHT_PERM_RW << LXT_PERM_SHIFT |
				     lli->port_sel));
	}

	mutex_unlock(&blka->mutex);

	/*
	 * The following sequence is prescribed in the SISlite spec
	 * for syncing up with the AFU when adding LXT entries.
	 */
	smp_wmb(); /* Make LXT updates are visible */

	rht_entry->lxt_start = lxt;
	smp_wmb(); /* Make RHT entry's LXT table update visible */

	rht_entry->lxt_cnt = my_new_size;
	smp_wmb(); /* Make RHT entry's LXT table size update visible */

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	*new_size = my_new_size;
out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * shrink_lxt() - reduces translation table associated with the specified RHTE
 * @afu:	AFU associated with the host.
 * @sdev:	SCSI device associated with LUN.
 * @ctx_hndl_u:	Context ID of context owning the RHTE.
 * @res_hndl_u:	Resource handle associated with the RHTE.
 * @rht_entry:	Resource handle entry (RHTE).
 * @new_size:	Number of translation entries associated with RHTE.
 * @port_sel:	Port selection mask.
 *
 * Return: 0 on success, -errno on failure
 */
static int shrink_lxt(struct afu *afu,
		      struct scsi_device *sdev,
		      ctx_hndl_t ctx_hndl_u,
		      res_hndl_t res_hndl_u,
		      struct sisl_rht_entry *rht_entry,
		      u64 *new_size)
{
	struct sisl_lxt_entry *lxt, *lxt_old;
	struct llun_info *lli = sdev->hostdata;
	u32 ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	u64 delta = rht_entry->lxt_cnt - *new_size;
	u64 my_new_size;
	int i, rc = 0;
	struct blka *blka = &lli->parent->blka;

	lxt_old = rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(rht_entry->lxt_cnt - delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size unless new size is 0 */
		if (ngrps) {
			lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE * ngrps),
				      GFP_KERNEL);
			if (unlikely(!lxt)) {
				rc = -ENOMEM;
				goto out;
			}

			/* copy over old entries that will remain */
			memcpy(lxt, lxt_old,
			       (sizeof(*lxt) * (rht_entry->lxt_cnt - delta)));
		} else
			lxt = NULL;
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	my_new_size = rht_entry->lxt_cnt - delta;

	/*
	 * The following sequence is prescribed in the SISlite spec
	 * for syncing up with the AFU when removing LXT entries.
	 */
	rht_entry->lxt_cnt = my_new_size;
	smp_wmb(); /* Make RHT entry's LXT table size update visible */

	rht_entry->lxt_start = lxt;
	smp_wmb(); /* Make RHT entry's LXT table update visible */

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_HW_SYNC);

	/* free LBAs allocated to freed chunks */
	mutex_lock(&blka->mutex);
	for (i = delta - 1; i >= 0; i--) {
		/* Mask the higher 48 bits before shifting, even though
		 * it is a noop
		 */
		aun = ((lxt_old[my_new_size + i].rlba_base &
			SISL_ASTATUS_MASK) >> MC_CHUNK_SHIFT);
		if (ws)
			write_same16(afu, sdev, aun, MC_CHUNK_SIZE);
		ba_free(&blka->ba_lun, aun);
	}
	mutex_unlock(&blka->mutex);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	*new_size = my_new_size;
out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * cxlflash_vlun_resize() - changes the size of a virtual lun
 * @sdev:	SCSI device associated with LUN owning virtual LUN.
 * @resize:	Resize ioctl data structure.
 *
 * On successful return, the user is informed of the new size (in blocks)
 * of the virtual lun in last LBA format. When the size of the virtual
 * lun is zero, the last LBA is reflected as -1.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_vlun_resize(struct scsi_device *sdev,
			 struct dk_cxlflash_resize *resize)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct afu *afu = cfg->afu;

	res_hndl_t res_hndl = resize->rsrc_handle;
	u64 new_size;
	u64 nsectors;
	u64 ctxid = DECODE_CTXID(resize->context_id),
	    rctxid = resize->context_id;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry;

	int rc = 0;

	/* req_size is always assumed to be in 4k blocks. So we have to convert
	 * it from 4k to chunk size
	 */
	nsectors = (resize->req_size * CXLFLASH_BLOCK_SIZE) /
		(lli->parent->blk_len);
	new_size = (nsectors + MC_CHUNK_SIZE - 1) / MC_CHUNK_SIZE;

	pr_debug("%s: ctxid=%llu res_hndl=0x%llx, req_size=0x%llx,"
		 "new_size=%llx\n", __func__, ctxid, resize->rsrc_handle,
		 resize->req_size, new_size);

	if (unlikely(lli->parent->mode != MODE_VIRTUAL)) {
		pr_err("%s: LUN mode does not support resize! (%d)\n",
		       __func__, lli->parent->mode);
		rc = -EINVAL;
		goto out;

	}

	ctx_info = get_context(cfg, rctxid, lli, 0);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n",
		       __func__, ctxid);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = get_rhte(ctx_info, res_hndl, lli);
	if (unlikely(!rht_entry)) {
		pr_err("%s: Invalid resource handle! (%u)\n",
		       __func__, res_hndl);
		rc = -EINVAL;
		goto out;
	}

	if (new_size > rht_entry->lxt_cnt)
		rc = grow_lxt(afu,
			      sdev,
			      ctxid,
			      res_hndl,
			      rht_entry,
			      &new_size);
	else if (new_size < rht_entry->lxt_cnt)
		rc = shrink_lxt(afu,
				sdev,
				ctxid,
				res_hndl,
				rht_entry,
				&new_size);

	resize->hdr.return_flags = 0;
	resize->last_lba = (((new_size * MC_CHUNK_SIZE * lli->parent->blk_len) /
			     CXLFLASH_BLOCK_SIZE) - 1);

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	pr_debug("%s: resized to %lld returning rc=%d\n",
		 __func__, resize->last_lba, rc);
	return rc;
}

/**
 * init_lun_table() - write an entry in the LUN table
 * @cfg:        Internal structure associated with the host.
 * @lli:	Per adapter LUN information structure.
 *
 * On successful return, a LUN table entry is created.
 * At the top for LUNs visible on both ports.
 * At the bottom for LUNs visible only on one port.
 *
 * Return: 0 on success, -errno on failure
 */
static int init_lun_table(struct cxlflash_cfg *cfg, struct llun_info *lli)
{
	u32 chan;
	int rc = 0;
	struct afu *afu = cfg->afu;

	if (lli->in_table)
		goto out;

	if (lli->port_sel == BOTH_PORTS) {
		/*
		 * If this LUN is visible from both ports, we will put
		 * it in the top half of the LUN table.
		 */
		if ((cfg->promote_lun_index == cfg->last_lun_index[0]) ||
		    (cfg->promote_lun_index == cfg->last_lun_index[1])) {
			rc = -ENOSPC;
			goto out;
		}

		lli->lun_index = cfg->promote_lun_index;
		writeq_be(lli->lun_id[0],
			  &afu->afu_map->global.fc_port[0]
			  [cfg->promote_lun_index]);
		writeq_be(lli->lun_id[1],
			  &afu->afu_map->global.fc_port[1]
			  [cfg->promote_lun_index]);
		cfg->promote_lun_index++;
		pr_debug("%s: Virtual LUN on slot %d  id0=%llx, id1=%llx\n",
			 __func__, lli->lun_index, lli->lun_id[0],
			 lli->lun_id[1]);
	} else {
		/*
		 * If this LUN is visible only from one port, we will put
		 * it in the bottom half of the LUN table.
		 */
		chan = PORT2CHAN(lli->port_sel);
		if (cfg->promote_lun_index == cfg->last_lun_index[chan]) {
			rc = -ENOSPC;
			goto out;
		}

		lli->lun_index = cfg->last_lun_index[chan];
		writeq_be(lli->lun_id[chan],
			  &afu->afu_map->global.fc_port[chan]
			  [cfg->last_lun_index[chan]]);
		cfg->last_lun_index[chan]--;
		pr_debug("%s: Virtual LUN on slot %d  chan=%d, id=%llx\n",
			 __func__, lli->lun_index, chan, lli->lun_id[chan]);
	}

	lli->in_table = true;
out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * cxlflash_disk_virtual_open() - open a virtual disk of specified size
 * @sdev:	SCSI device associated with LUN owning virtual LUN.
 * @arg:	UVirtual ioctl data structure.
 *
 * On successful return, the user is informed of the resource handle
 * to be used to identify the virtual lun and the size (in blocks) of
 * the virtual lun in last LBA format. When the size of the virtual lun
 * is zero, the last LBA is reflected as -1.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_disk_virtual_open(struct scsi_device *sdev, void *arg)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;

	struct dk_cxlflash_uvirtual *virt = (struct dk_cxlflash_uvirtual *)arg;
	struct dk_cxlflash_resize resize;

	u64 ctxid = DECODE_CTXID(virt->context_id),
	    rctxid = virt->context_id;
	u64 lun_size = virt->lun_size;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry = NULL;

	pr_debug("%s: ctxid=%llu ls=0x%llx\n", __func__, ctxid, lun_size);

	if (lli->parent->mode == MODE_NONE) {
		/* Setup the LUN table on the first call */
		rc = init_lun_table(cfg, lli);
		if (rc) {
			pr_err("%s: call to init_lun_table failed rc=%d!\n",
			       __func__, rc);
			goto out;
		}

		rc = init_ba(lli);
		if (rc) {
			pr_err("%s: call to init_ba failed rc=%d!\n",
			       __func__, rc);
			rc = -ENOMEM;
			goto out;
		}
	}

	rc = cxlflash_lun_attach(lli, MODE_VIRTUAL);
	if (unlikely(rc)) {
		pr_err("%s: Failed to attach to LUN! mode=%u\n",
		       __func__, MODE_VIRTUAL);
		goto out;
	}

	ctx_info = get_context(cfg, rctxid, lli, 0);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n",
		       __func__, ctxid);
		rc = -EINVAL;
		goto err1;
	}

	rht_entry = rhte_checkout(ctx_info, lli);
	if (unlikely(!rht_entry)) {
		pr_err("%s: too many opens for this context\n", __func__);
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
		pr_err("%s: resize failed rc %d\n", __func__, rc);
		goto err2;
	}
	last_lba = resize.last_lba;

	virt->hdr.return_flags = 0;
	virt->last_lba = last_lba;
	virt->rsrc_handle = rsrc_handle;

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	pr_debug("%s: returning handle 0x%llx rc=%d llba %lld\n",
		 __func__, rsrc_handle, rc, last_lba);
	return rc;

err2:
	rhte_checkin(ctx_info, rht_entry);
err1:
	cxlflash_lun_detach(lli);
	goto out;
}

/**
 * clone_lxt() - copies translation tables from source to destination RHTE
 * @afu:		AFU associated with the host.
 * @blka:		Block allocator associated with LUN.
 * @ctx_hndl_u:		Context ID of context owning the RHTE.
 * @res_hndl_u:		Resource handle associated with the RHTE.
 * @rht_entry:		Destination resource handle entry (RHTE).
 * @rht_entry_src:	Source resource handle entry (RHTE).
 *
 * Return: 0 on success, -errno on failure
 */
static int clone_lxt(struct afu *afu,
		     struct blka *blka,
		     ctx_hndl_t ctx_hndl_u,
		     res_hndl_t res_hndl_u,
		     struct sisl_rht_entry *rht_entry,
		     struct sisl_rht_entry *rht_entry_src)
{
	struct sisl_lxt_entry *lxt;
	u32 ngrps;
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

	/*
	 * The following sequence is prescribed in the SISlite spec
	 * for syncing up with the AFU when adding LXT entries.
	 */
	smp_wmb(); /* Make LXT updates are visible */

	rht_entry->lxt_start = lxt;
	smp_wmb(); /* Make RHT entry's LXT table update visible */

	rht_entry->lxt_cnt = rht_entry_src->lxt_cnt;
	smp_wmb(); /* Make RHT entry's LXT table size update visible */

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	pr_debug("%s: returning\n", __func__);
	return 0;
}

/**
 * cxlflash_disk_clone() - clone a context by making snapshot of another
 * @sdev:	SCSI device associated with LUN owning virtual LUN.
 * @clone:	Clone ioctl data structure.
 *
 * This routine effectively performs cxlflash_disk_open operation for each
 * in-use virtual resource in the source context. Note that the destination
 * context must be in pristine state and cannot have any resource handles
 * open at the time of the clone.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_disk_clone(struct scsi_device *sdev,
			struct dk_cxlflash_clone *clone)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct blka *blka = &lli->parent->blka;
	struct afu *afu = cfg->afu;
	struct dk_cxlflash_release release = { { 0 }, 0 };

	struct ctx_info *ctx_info_src = NULL,
			*ctx_info_dst = NULL;
	struct lun_access *lun_access_src, *lun_access_dst;
	u32 perms;
	u64 ctxid_src = DECODE_CTXID(clone->context_id_src),
	    ctxid_dst = DECODE_CTXID(clone->context_id_dst),
	    rctxid_src = clone->context_id_src,
	    rctxid_dst = clone->context_id_dst;
	int adap_fd_src = clone->adap_fd_src;
	int i, j;
	int rc = 0;
	bool found;
	LIST_HEAD(sidecar);

	pr_debug("%s: ctxid_src=%llu ctxid_dst=%llu adap_fd_src=%d\n",
		 __func__, ctxid_src, ctxid_dst, adap_fd_src);

	/* Do not clone yourself */
	if (unlikely(rctxid_src == rctxid_dst)) {
		rc = -EINVAL;
		goto out;
	}

	if (unlikely(lli->parent->mode != MODE_VIRTUAL)) {
		rc = -EINVAL;
		pr_err("%s: Clone not supported on physical LUNs! (%d)\n",
		       __func__, lli->parent->mode);
		goto out;
	}

	ctx_info_src = get_context(cfg, rctxid_src, lli, CTX_CTRL_CLONE);
	ctx_info_dst = get_context(cfg, rctxid_dst, lli, 0);
	if (unlikely(!ctx_info_src || !ctx_info_dst)) {
		pr_err("%s: Invalid context! (%llu,%llu)\n",
		       __func__, ctxid_src, ctxid_dst);
		rc = -EINVAL;
		goto out;
	}

	if (unlikely(adap_fd_src != ctx_info_src->lfd)) {
		pr_err("%s: Invalid source adapter fd! (%d)\n",
		       __func__, adap_fd_src);
		rc = -EINVAL;
		goto out;
	}

	/* Verify there is no open resource handle in the destination context */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (ctx_info_dst->rht_start[i].nmask != 0) {
			rc = -EINVAL;
			goto out;
		}

	/* Clone LUN access list */
	list_for_each_entry(lun_access_src, &ctx_info_src->luns, list) {
		found = false;
		list_for_each_entry(lun_access_dst, &ctx_info_dst->luns, list)
			if (lun_access_dst->sdev == lun_access_src->sdev) {
				found = true;
				break;
			}

		if (!found) {
			lun_access_dst = kzalloc(sizeof(*lun_access_dst),
						 GFP_KERNEL);
			if (unlikely(!lun_access_dst)) {
				pr_err("%s: Unable to allocate lun_access!\n",
				       __func__);
				rc = -ENOMEM;
				goto out;
			}

			*lun_access_dst = *lun_access_src;
			list_add(&lun_access_dst->list, &sidecar);
		}
	}

	if (unlikely(!ctx_info_src->rht_out)) {
		pr_err("%s: Nothing to clone!\n", __func__);
		goto out_success;
	}

	/* User specified permission on attach */
	perms = ctx_info_dst->rht_perms;

	/*
	 * Copy over checked-out RHT (and their associated LXT) entries by
	 * hand, stopping after we've copied all outstanding entries and
	 * cleaning up if the clone fails.
	 *
	 * Note: This loop is equivalent to performing cxlflash_disk_open and
	 * cxlflash_vlun_resize. As such, LUN accounting needs to be taken into
	 * account by attaching after each successful RHT entry clone. In the
	 * event that a clone failure is experienced, the LUN detach is handled
	 * via the cleanup performed by cxlflash_disk_release.
	 */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
		if (ctx_info_src->rht_out == ctx_info_dst->rht_out)
			break;
		if (ctx_info_src->rht_start[i].nmask == 0)
			continue;

		/* Consume a destination RHT entry */
		ctx_info_dst->rht_out++;
		ctx_info_dst->rht_start[i].nmask =
		    ctx_info_src->rht_start[i].nmask;
		ctx_info_dst->rht_start[i].fp =
		    SISL_RHT_FP_CLONE(ctx_info_src->rht_start[i].fp, perms);
		ctx_info_dst->rht_lun[i] = ctx_info_src->rht_lun[i];

		rc = clone_lxt(afu, blka, ctxid_dst, i,
			       &ctx_info_dst->rht_start[i],
			       &ctx_info_src->rht_start[i]);
		if (rc) {
			marshall_clone_to_rele(clone, &release);
			for (j = 0; j < i; j++) {
				release.rsrc_handle = j;
				cxlflash_disk_release(sdev, &release);
			}

			/* Put back the one we failed on */
			rhte_checkin(ctx_info_dst, &ctx_info_dst->rht_start[i]);
			goto err;
		}

		cxlflash_lun_attach(lli, lli->parent->mode);
	}

out_success:
	list_splice(&sidecar, &ctx_info_dst->luns);
	sys_close(adap_fd_src);

	/* fall through */
out:
	if (likely(ctx_info_src))
		atomic_dec(&ctx_info_src->nrefs);
	if (likely(ctx_info_dst))
		atomic_dec(&ctx_info_dst->nrefs);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;

err:
	list_for_each_entry_safe(lun_access_src, lun_access_dst, &sidecar, list)
		kfree(lun_access_src);
	goto out;
}

