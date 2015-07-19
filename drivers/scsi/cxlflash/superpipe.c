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

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <uapi/scsi/cxlflash_ioctl.h>

#include "sislite.h"
#include "common.h"
#include "vlun.h"
#include "superpipe.h"

static struct cxlflash_global global;

/**
 * marshal_rele_to_resize() - translate release to resize structure
 * @rele:	Source structure from which to translate/copy.
 * @resize:	Destination structure for the translate/copy.
 */
static void marshal_rele_to_resize(struct dk_cxlflash_release *release,
				   struct dk_cxlflash_resize *resize)
{
	resize->hdr = release->hdr;
	resize->context_id = release->context_id;
	resize->rsrc_handle = release->rsrc_handle;
}

/**
 * marshal_det_to_rele() - translate detach to release structure
 * @detach:	Destination structure for the translate/copy.
 * @rele:	Source structure from which to translate/copy.
 */
static void marshal_det_to_rele(struct dk_cxlflash_detach *detach,
				struct dk_cxlflash_release *release)
{
	release->hdr = detach->hdr;
	release->context_id = detach->context_id;
}

/**
 * create_local() - allocate and initialize a local LUN information structure
 * @sdev:	SCSI device associated with LUN.
 * @wwid:	World Wide Node Name for LUN.
 *
 * Return: Allocated local llun_info structure on success, NULL on failure
 */
static struct llun_info *create_local(struct scsi_device *sdev, u8 *wwid)
{
	struct llun_info *lli = NULL;

	lli = kzalloc(sizeof(*lli), GFP_KERNEL);
	if (unlikely(!lli)) {
		pr_err("%s: could not allocate lli\n", __func__);
		goto out;
	}

	lli->sdev = sdev;
	lli->newly_created = true;
	lli->host_no = sdev->host->host_no;
	lli->in_table = false;

	memcpy(lli->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN);
out:
	return lli;
}

/**
 * create_global() - allocate and initialize a global LUN information structure
 * @sdev:	SCSI device associated with LUN.
 * @wwid:	World Wide Node Name for LUN.
 *
 * Return: Allocated global glun_info structure on success, NULL on failure
 */
static struct glun_info *create_global(struct scsi_device *sdev, u8 *wwid)
{
	struct glun_info *gli = NULL;

	gli = kzalloc(sizeof(*gli), GFP_KERNEL);
	if (unlikely(!gli)) {
		pr_err("%s: could not allocate gli\n", __func__);
		goto out;
	}

	memcpy(gli->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN);
out:
	return gli;
}

/**
 * lookup_local() - find a local LUN information structure by WWID
 * @cfg:	Internal structure associated with the host.
 * @wwid:	WWID associated with LUN.
 *
 * Return: Found local lun_info structure on success, NULL on failure
 */
static struct llun_info *lookup_local(struct cxlflash_cfg *cfg, u8 *wwid)
{
	struct llun_info *lli, *temp;
	ulong lock_flags;

	spin_lock_irqsave(&cfg->slock, lock_flags);

	list_for_each_entry_safe(lli, temp, &cfg->lluns, list)
		if (!memcmp(lli->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN)) {
			lli->newly_created = false;
			spin_unlock_irqrestore(&cfg->slock, lock_flags);
			return lli;
		}

	spin_unlock_irqrestore(&cfg->slock, lock_flags);
	return NULL;
}

/**
 * lookup_global() - find a global LUN information structure by WWID
 * @wwid:	WWID associated with LUN.
 *
 * Return: Found global lun_info structure on success, NULL on failure
 */
static struct glun_info *lookup_global(u8 *wwid)
{
	struct glun_info *gli, *temp;
	ulong lock_flags;

	spin_lock_irqsave(&global.slock, lock_flags);

	list_for_each_entry_safe(gli, temp, &global.gluns, list)
		if (!memcmp(gli->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN)) {
			spin_unlock_irqrestore(&global.slock, lock_flags);
			return gli;
		}

	spin_unlock_irqrestore(&global.slock, lock_flags);
	return NULL;
}

/**
 * lookup_lun() - find or create a local LUN information structure
 * @sdev:	SCSI device associated with LUN.
 * @wwid:	WWID associated with LUN.
 *
 * When a local LUN is not found and a global LUN is also not found, both
 * a global LUN and local LUN are created. The global LUN is added to the
 * global list and the local LUN is returned.
 *
 * Return: Found/Allocated local lun_info structure on success, NULL on failure
 */
static struct llun_info *lookup_lun(struct scsi_device *sdev, u8 *wwid)
{
	struct llun_info *lli = NULL;
	struct glun_info *gli = NULL;
	struct Scsi_Host *shost = sdev->host;
	struct cxlflash_cfg *cfg = shost_priv(shost);
	ulong lock_flags;

	if (unlikely(!wwid))
		goto out;

	lli = lookup_local(cfg, wwid);
	if (lli)
		goto out;

	lli = create_local(sdev, wwid);
	if (unlikely(!lli))
		goto out;

	gli = lookup_global(wwid);
	if (gli) {
		lli->parent = gli;
		spin_lock_irqsave(&cfg->slock, lock_flags);
		list_add(&lli->list, &cfg->lluns);
		spin_unlock_irqrestore(&cfg->slock, lock_flags);
		goto out;
	}

	gli = create_global(sdev, wwid);
	if (unlikely(!gli)) {
		kfree(lli);
		lli = NULL;
		goto out;
	}

	lli->parent = gli;
	spin_lock_irqsave(&cfg->slock, lock_flags);
	list_add(&lli->list, &cfg->lluns);
	spin_unlock_irqrestore(&cfg->slock, lock_flags);

	spin_lock_irqsave(&global.slock, lock_flags);
	list_add(&gli->list, &global.gluns);
	spin_unlock_irqrestore(&global.slock, lock_flags);

out:
	pr_debug("%s: returning %p\n", __func__, lli);
	return lli;
}

/**
 * lookup_local() - find a local LUN information structure by WWID
 * @cfg:	Internal structure associated with the host.
 * @wwid:	WWID associated with LUN.
 *
 * Return: Found local lun_info structure on success, NULL on failure
 */
static void reset_local(struct cxlflash_cfg *cfg)
{
	struct llun_info *lli, *temp;
	ulong lock_flags;

	spin_lock_irqsave(&cfg->slock, lock_flags);

	list_for_each_entry_safe(lli, temp, &cfg->lluns, list)
		lli->in_table = false;

	spin_unlock_irqrestore(&cfg->slock, lock_flags);
}

/**
 * cxlflash_term_luns() - Delete all entries from local lun list, free.
 * @cfg:	Internal structure associated with the host.
 */
void cxlflash_term_luns(struct cxlflash_cfg *cfg)
{
	struct llun_info *lli, *temp;
	ulong lock_flags;

	spin_lock_irqsave(&cfg->slock, lock_flags);
	list_for_each_entry_safe(lli, temp, &cfg->lluns, list) {
		list_del(&lli->list);
		kfree(lli);
	}
	spin_unlock_irqrestore(&cfg->slock, lock_flags);
}

/**
 * cxlflash_list_init() - initializes the global LUN list
 */
void cxlflash_list_init(void)
{
	INIT_LIST_HEAD(&global.gluns);
	spin_lock_init(&global.slock);
	global.err_page = NULL;
}

/**
 * cxlflash_list_terminate() - frees resources associated with global LUN list
 */
void cxlflash_list_terminate(void)
{
	struct glun_info *gli, *temp;
	ulong flags = 0;

	spin_lock_irqsave(&global.slock, flags);
	list_for_each_entry_safe(gli, temp, &global.gluns, list) {
		list_del(&gli->list);
		cxlflash_ba_terminate(&gli->blka.ba_lun);
		kfree(gli);
	}

	if (global.err_page) {
		__free_page(global.err_page);
		global.err_page = NULL;
	}
	spin_unlock_irqrestore(&global.slock, flags);
}

/**
 * cxlflash_stop_term_user_contexts() - stops/terminates known user contexts
 * @cfg:	Internal structure associated with the host.
 *
 * When the host needs to go down, all users must be quiesced and their
 * memory freed. This is accomplished by putting the contexts in error
 * state which will notify the user and let them 'drive' the teardown.
 * Meanwhile, this routine camps until all user contexts have been removed.
 */
void cxlflash_stop_term_user_contexts(struct cxlflash_cfg *cfg)
{
	int i, found;

	cfg->eeh_active = EEH_STATE_FAILED;
	cxlflash_mark_contexts_error(cfg);

	while (true) {
		found = false;

		for (i = 0; i < MAX_CONTEXT; i++)
			if (cfg->ctx_tbl[i]) {
				found = true;
				break;
			}

		if (!found && list_empty(&cfg->ctx_err_recovery))
			return;

		pr_debug("%s: Wait for user context to quiesce...\n", __func__);
		wake_up_all(&cfg->eeh_waitq);
		ssleep(1);
	}
}

/**
 * find_error_context() - locates a context by cookie on the error recovery list
 * @cfg:	Internal structure associated with the host.
 * @rctxid:	Desired context by id.
 * @file:	Desired context by file.
 *
 * Return: Found context on success, NULL on failure
 */
static struct ctx_info *find_error_context(struct cxlflash_cfg *cfg, u64 rctxid,
					   struct file *file)
{
	struct ctx_info *ctxi;

	list_for_each_entry(ctxi, &cfg->ctx_err_recovery, list)
		if ((ctxi->ctxid == rctxid) || (ctxi->file == file))
			return ctxi;

	return NULL;
}

/**
 * get_context() - obtains a validated and locked context reference
 * @cfg:	Internal structure associated with the host.
 * @rctxid:	Desired context (raw, undecoded format).
 * @arg:	LUN information or file associated with request.
 * @ctx_ctrl:	Control information to 'steer' desired lookup.
 *
 * NOTE: despite the name pid, in linux, current->pid actually refers
 * to the lightweight process id (tid) and can change if the process is
 * multi threaded. The tgid remains constant for the process and only changes
 * when the process of fork. For all intents and purposes, think of tgid
 * as a pid in the traditional sense.
 *
 * Return: Validated context on success, NULL on failure
 */
struct ctx_info *get_context(struct cxlflash_cfg *cfg, u64 rctxid,
			     void *arg, enum ctx_ctrl ctx_ctrl)
{
	struct ctx_info *ctxi = NULL;
	struct lun_access *lun_access = NULL;
	struct file *file = NULL;
	struct llun_info *lli = arg;
	u64 ctxid = DECODE_CTXID(rctxid);
	int rc;
	pid_t pid = current->tgid, ctxpid = 0;

	if (ctx_ctrl & CTX_CTRL_FILE) {
		lli = NULL;
		file = (struct file *)arg;
	}

	if (ctx_ctrl & CTX_CTRL_CLONE)
		pid = current->parent->tgid;

	if (likely(ctxid < MAX_CONTEXT)) {
retry:
		rc = mutex_lock_interruptible(&cfg->ctx_tbl_list_mutex);
		if (rc)
			goto out;

		ctxi = cfg->ctx_tbl[ctxid];
		if (ctxi)
			if ((file && (ctxi->file != file)) ||
			    (!file && (ctxi->ctxid != rctxid)))
				ctxi = NULL;

		if ((ctx_ctrl & CTX_CTRL_ERR) ||
		    (!ctxi && (ctx_ctrl & CTX_CTRL_ERR_FALLBACK)))
			ctxi = find_error_context(cfg, rctxid, file);
		mutex_unlock(&cfg->ctx_tbl_list_mutex);
		if (!ctxi)
			goto out;

		rc = mutex_trylock(&ctxi->mutex);
		if (!rc)
			goto retry;

		ctxpid = ctxi->pid;
		if (likely(!(ctx_ctrl & CTX_CTRL_NOPID)))
			if (pid != ctxpid)
				goto denied;

		if (lli) {
			list_for_each_entry(lun_access, &ctxi->luns, list)
				if (lun_access->lli == lli)
					goto out;
			goto denied;
		}
	}

out:
	pr_debug("%s: rctxid=%016llX ctxinfo=%p ctxpid=%u pid=%u ctx_ctrl=%u\n",
		 __func__, rctxid, ctxi, ctxpid, pid, ctx_ctrl);

	return ctxi;

denied:
	mutex_unlock(&ctxi->mutex);
	ctxi = NULL;
	goto out;
}

/**
 * afu_attach() - attach a context to the AFU
 * @cfg:	Internal structure associated with the host.
 * @ctxi:	Context to attach.
 *
 * Upon setting the context capabilities, they must be confirmed with
 * a read back operation as the context might have been closed since
 * the mailbox was unlocked. When this occurs, registration is failed.
 *
 * Return: 0 on success, -errno on failure
 */
static int afu_attach(struct cxlflash_cfg *cfg, struct ctx_info *ctxi)
{
	struct afu *afu = cfg->afu;
	struct sisl_ctrl_map *ctrl_map = ctxi->ctrl_map;
	int rc = 0;
	u64 val;

	/* Unlock cap and restrict user to read/write cmds in translated mode */
	readq_be(&ctrl_map->mbox_r);
	val = (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD);
	writeq_be(val, &ctrl_map->ctx_cap);
	val = readq_be(&ctrl_map->ctx_cap);
	if (val != (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD)) {
		pr_err("%s: ctx may be closed val=%016llX\n", __func__, val);
		rc = -EAGAIN;
		goto out;
	}

	/* Set up MMIO registers pointing to the RHT */
	writeq_be((u64)ctxi->rht_start, &ctrl_map->rht_start);
	val = SISL_RHT_CNT_ID((u64)MAX_RHT_PER_CONTEXT, (u64)(afu->ctx_hndl));
	writeq_be(val, &ctrl_map->rht_cnt_id);
out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * read_cap16() - issues a SCSI READ_CAP16 command
 * @sdev:       SCSI device associated with LUN.
 * @lli:	LUN destined for capacity request.
 *
 * Return: 0 on success, -1 on failure
 */
static int read_cap16(struct scsi_device *sdev, struct llun_info *lli)
{
	struct glun_info *gli = lli->parent;
	u8 scsi_cmd[MAX_COMMAND_SIZE];
	u8 *cmd_buf = NULL;
	u8 *sense_buf = NULL;
	int rc = 0;
	int result = 0;

	memset(scsi_cmd, 0, sizeof(scsi_cmd));
	cmd_buf = kzalloc(CMD_BUFSIZE, GFP_KERNEL);
	sense_buf = kzalloc(SCSI_SENSE_BUFFERSIZE, GFP_NOIO);
	if (!cmd_buf || !sense_buf) {
		rc = -ENOMEM;
		goto out;
	}

	scsi_cmd[0] = SERVICE_ACTION_IN_16;	/* read cap(16) */
	scsi_cmd[1] = SAI_READ_CAPACITY_16;	/* service action */
	put_unaligned_be32(CMD_BUFSIZE, &scsi_cmd[10]);

	pr_debug("%s: sending cmd(0x%x)\n", __func__, scsi_cmd[0]);

	result = scsi_execute(sdev, scsi_cmd, DMA_FROM_DEVICE, cmd_buf,
			      CMD_BUFSIZE, sense_buf,
			      (MC_DISCOVERY_TIMEOUT*HZ), 5, 0, NULL);

	if (result) {
		pr_err("%s: command failed, result=0x%x\n", __func__, result);
		rc = -EIO;
		goto out;
	}

	/*
	 * Read cap was successful, grab values from the buffer;
	 * note that we don't need to worry about unaligned access
	 * as the buffer is allocated on an aligned boundary.
	 */
	spin_lock(&gli->slock);
	gli->max_lba = swab64(*((u64 *)&cmd_buf[0]));
	gli->blk_len = swab32(*((u32 *)&cmd_buf[8]));
	spin_unlock(&gli->slock);

out:
	kfree(cmd_buf);
	kfree(sense_buf);
	pr_debug("%s: maxlba=%lld blklen=%d rc=%d\n", __func__,
		 gli->max_lba, gli->blk_len, rc);
	return rc;
}

/**
 * get_rhte() - obtains validated resource handle table entry reference
 * @ctxi:	Context owning the resource handle.
 * @rhndl:	Resource handle associated with entry.
 * @lli:	LUN associated with request.
 *
 * Return: Validated RHTE on success, NULL on failure
 */
struct sisl_rht_entry *get_rhte(struct ctx_info *ctxi, res_hndl_t rhndl,
				struct llun_info *lli)
{
	struct sisl_rht_entry *rhte = NULL;

	if (unlikely(!ctxi->rht_start)) {
		pr_err("%s: Context does not have allocated RHT!\n", __func__);
		goto out;
	}

	if (unlikely(rhndl >= MAX_RHT_PER_CONTEXT)) {
		pr_err("%s: Bad resource handle! (%d)\n", __func__, rhndl);
		goto out;
	}

	if (unlikely(ctxi->rht_lun[rhndl] != lli)) {
		pr_err("%s: Bad resource handle LUN! (%d)\n", __func__, rhndl);
		goto out;
	}

	rhte = &ctxi->rht_start[rhndl];
	if (unlikely(rhte->nmask == 0)) {
		pr_err("%s: Unopened resource handle! (%d)\n", __func__, rhndl);
		rhte = NULL;
		goto out;
	}

out:
	return rhte;
}

/**
 * rhte_checkout() - obtains free/empty resource handle table entry
 * @ctxi:	Context owning the resource handle.
 * @lli:	LUN associated with request.
 *
 * Return: Free RHTE on success, NULL on failure
 */
struct sisl_rht_entry *rhte_checkout(struct ctx_info *ctxi,
				     struct llun_info *lli)
{
	struct sisl_rht_entry *rhte = NULL;
	int i;

	/* Find a free RHT entry */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (ctxi->rht_start[i].nmask == 0) {
			rhte = &ctxi->rht_start[i];
			ctxi->rht_out++;
			break;
		}

	if (likely(rhte))
		ctxi->rht_lun[i] = lli;

	pr_debug("%s: returning rhte=%p (%d)\n", __func__, rhte, i);
	return rhte;
}

/**
 * rhte_checkin() - releases a resource handle table entry
 * @ctxi:	Context owning the resource handle.
 * @rhte:	RHTE to release.
 */
void rhte_checkin(struct ctx_info *ctxi,
		  struct sisl_rht_entry *rhte)
{
	rhte->nmask = 0;
	rhte->fp = 0;
	ctxi->rht_out--;
	ctxi->rht_lun[rhte - ctxi->rht_start] = NULL;
}

/**
 * rhte_format1() - populates a RHTE for format 1
 * @rhte:	RHTE to populate.
 * @lun_id:	LUN ID of LUN associated with RHTE.
 * @perm:	Desired permissions for RHTE.
 * @port_sel:   Port selection mask
 */
static void rht_format1(struct sisl_rht_entry *rhte, u64 lun_id, u32 perm,
			u32 port_sel)
{
	/*
	 * Populate the Format 1 RHT entry for direct access (physical
	 * LUN) using the synchronization sequence defined in the
	 * SISLite specification.
	 */
	struct sisl_rht_entry_f1 dummy = { 0 };
	struct sisl_rht_entry_f1 *rhte_f1 = (struct sisl_rht_entry_f1 *)rhte;

	memset(rhte_f1, 0, sizeof(*rhte_f1));
	rhte_f1->fp = SISL_RHT_FP(1U, 0);
	dma_wmb(); /* Make setting of format bit visible */

	rhte_f1->lun_id = lun_id;
	dma_wmb(); /* Make setting of LUN id visible */

	/*
	 * Use a dummy RHT Format 1 entry to build the second dword
	 * of the entry that must be populated in a single write when
	 * enabled (valid bit set to TRUE).
	 */
	dummy.valid = 0x80;
	dummy.fp = SISL_RHT_FP(1U, perm);
	dummy.port_sel = port_sel;
	rhte_f1->dw = dummy.dw;

	dma_wmb(); /* Make remaining RHT entry fields visible */
}

/**
 * cxlflash_lun_attach() - attaches a user to a LUN and manages the LUN's mode
 * @lli:	LUN to attach.
 * @mode:	Desired mode of the LUN.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_lun_attach(struct glun_info *gli, enum lun_mode mode)
{
	int rc = 0;

	spin_lock(&gli->slock);
	if (gli->mode == MODE_NONE)
		gli->mode = mode;
	else if (gli->mode != mode) {
		pr_err("%s: LUN operating in mode %d, requested mode %d\n",
		       __func__, gli->mode, mode);
		rc = -EINVAL;
		goto out;
	}

	gli->users++;
	BUG_ON(gli->users <= 0);
out:
	pr_debug("%s: Returning rc=%d gli->mode=%u gli->users=%u\n",
		 __func__, rc, gli->mode, gli->users);
	spin_unlock(&gli->slock);
	return rc;
}

/**
 * cxlflash_lun_detach() - detaches a user from a LUN and resets the LUN's mode
 * @lli:	LUN to detach.
 */
void cxlflash_lun_detach(struct glun_info *gli)
{
	spin_lock(&gli->slock);
	BUG_ON(gli->mode == MODE_NONE); /* XXX - remove me before submit */
	if (--gli->users == 0)
		gli->mode = MODE_NONE;
	pr_debug("%s: gli->users=%u\n", __func__, gli->users);
	BUG_ON(gli->users < 0);
	spin_unlock(&gli->slock);
}

/**
 * _cxlflash_disk_release() - releases the specified resource entry
 * @sdev:	SCSI device associated with LUN.
 * @ctxi:	Context owning resources.
 * @release:	Release ioctl data structure.
 *
 * For LUN's in virtual mode, the virtual lun associated with the specified
 * resource handle is resized to 0 prior to releasing the RHTE. Note that the
 * AFU sync should _not_ be performed when the context is sitting on the error
 * recovery list. A context on the error recovery list is not known to the AFU
 * due to reset. When the context is recovered, it will be reattached and made
 * known again to the AFU.
 *
 * Return: 0 on success, -errno on failure
 */
int _cxlflash_disk_release(struct scsi_device *sdev,
			   struct ctx_info *ctxi,
			   struct dk_cxlflash_release *release)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct glun_info *gli = lli->parent;
	struct afu *afu = cfg->afu;
	bool unlock_ctx = false;

	struct dk_cxlflash_resize size;
	res_hndl_t rhndl = release->rsrc_handle;

	int rc = 0;
	u64 ctxid = DECODE_CTXID(release->context_id),
	    rctxid = release->context_id;

	struct sisl_rht_entry *rhte;
	struct sisl_rht_entry_f1 *rhte_f1;

	pr_debug("%s: ctxid=%llu rhndl=0x%llx gli->mode=%u gli->users=%u\n",
		 __func__, ctxid, release->rsrc_handle, gli->mode, gli->users);

	if (!ctxi) {
		ctxi = get_context(cfg, rctxid, lli, CTX_CTRL_ERR_FALLBACK);
		if (unlikely(!ctxi)) {
			pr_err("%s: Bad context! (%llu)\n", __func__, ctxid);
			rc = -EINVAL;
			goto out;
		}

		unlock_ctx = true;
	}

	rhte = get_rhte(ctxi, rhndl, lli);
	if (unlikely(!rhte)) {
		pr_err("%s: Bad resource handle! (%d)\n", __func__, rhndl);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * Resize to 0 for virtual LUNS by setting the size
	 * to 0. This will clear LXT_START and LXT_CNT fields
	 * in the RHT entry and properly sync with the AFU.
	 *
	 * Afterwards we clear the remaining fields.
	 */
	switch (gli->mode) {
	case MODE_VIRTUAL:
		marshal_rele_to_resize(release, &size);
		size.req_size = 0;
		rc = _cxlflash_vlun_resize(sdev, ctxi, &size);
		if (rc) {
			pr_err("%s: resize failed rc %d\n", __func__, rc);
			goto out;
		}

		break;
	case MODE_PHYSICAL:
		/*
		 * Clear the Format 1 RHT entry for direct access
		 * (physical LUN) using the synchronization sequence
		 * defined in the SISLite specification.
		 */
		rhte_f1 = (struct sisl_rht_entry_f1 *)rhte;

		rhte_f1->valid = 0;
		dma_wmb(); /* Make revocation of RHT entry visible */

		rhte_f1->lun_id = 0;
		dma_wmb(); /* Make clearing of LUN id visible */

		rhte_f1->dw = 0;
		dma_wmb(); /* Make RHT entry bottom-half clearing visible */

		if (!ctxi->err_recovery_active)
			cxlflash_afu_sync(afu, ctxid, rhndl, AFU_HW_SYNC);
		break;
	default:
		BUG();
		goto out;
	}

	rhte_checkin(ctxi, rhte);
	cxlflash_lun_detach(gli);

out:
	if (unlock_ctx)
		mutex_unlock(&ctxi->mutex);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

int cxlflash_disk_release(struct scsi_device *sdev,
			  struct dk_cxlflash_release *release)
{
	return _cxlflash_disk_release(sdev, NULL, release);
}

/**
 * destroy_context() - releases a context
 * @cfg:	Internal structure associated with the host.
 * @ctxi:	Context to release.
 *
 * Note that the rht_lun member of the context was cut from a single
 * allocation when the context was created and therefore does not need
 * to be explicitly freed. Also note that we conditionally check for the
 * existence of the context control map before clearing the RHT registers
 * and context capbilities because it is possible to destroy a context
 * while the context is in the error state (previous mapping was removed
 * [so we don't have to worry about clearing] and context is waiting for
 * a new mapping).
 */
static void destroy_context(struct cxlflash_cfg *cfg,
			    struct ctx_info *ctxi)
{
	BUG_ON(!list_empty(&ctxi->luns));

	/* Clear RHT registers and drop all capabilities for this context */
	if (ctxi->ctrl_map) {
		writeq_be(0, &ctxi->ctrl_map->rht_start);
		writeq_be(0, &ctxi->ctrl_map->rht_cnt_id);
		writeq_be(0, &ctxi->ctrl_map->ctx_cap);
	}

	/* Free the RHT memory */
	free_page((ulong)ctxi->rht_start);

	/* Free the context; note that rht_lun was allocated at same time */
	kfree(ctxi);
	atomic_dec_if_positive(&cfg->num_user_contexts);
}

/**
 * create_context() - allocates and initializes a context
 * @cfg:	Internal structure associated with the host.
 * @ctx:	Previously obtained CXL context reference.
 * @ctxid:	Previously obtained process element associated with CXL context.
 * @adap_fd:	Previously obtained adapter fd associated with CXL context.
 * @file:	Previously obtained file associated with CXL context.
 * @perms:	User-specified permissions.
 *
 * The context's mutex is locked when an allocated context is returned.
 *
 * Return: Allocated context on success, NULL on failure
 */
static struct ctx_info *create_context(struct cxlflash_cfg *cfg,
				       struct cxl_context *ctx, int ctxid,
				       int adap_fd, struct file *file,
				       u32 perms)
{
	char *tmp = NULL;
	size_t size;
	struct afu *afu = cfg->afu;
	struct ctx_info *ctxi = NULL;
	struct sisl_rht_entry *rhte;

	size = (MAX_RHT_PER_CONTEXT * sizeof(*ctxi->rht_lun));
	size += sizeof(*ctxi);

	tmp = kzalloc(size, GFP_KERNEL);
	if (unlikely(!tmp)) {
		pr_err("%s: Unable to allocate context! (%ld)\n",
		       __func__, size);
		goto out;
	}

	rhte = (struct sisl_rht_entry *)get_zeroed_page(GFP_KERNEL);
	if (unlikely(!rhte)) {
		pr_err("%s: Unable to allocate RHT!\n", __func__);
		goto err;
	}

	ctxi = (struct ctx_info *)tmp;
	ctxi->rht_lun = (struct llun_info **)(tmp + sizeof(*ctxi));
	ctxi->rht_start = rhte;
	ctxi->rht_perms = perms;

	ctxi->ctrl_map = &afu->afu_map->ctrls[ctxid].ctrl;
	ctxi->ctxid = ENCODE_CTXID(ctxi, ctxid);
	ctxi->lfd = adap_fd;
	ctxi->pid = current->tgid; /* tgid = pid */
	ctxi->ctx = ctx;
	ctxi->file = file;
	mutex_init(&ctxi->mutex);
	INIT_LIST_HEAD(&ctxi->luns);
	INIT_LIST_HEAD(&ctxi->list); /* initialize for list_empty() */

	atomic_inc(&cfg->num_user_contexts);
	mutex_lock(&ctxi->mutex);
out:
	return ctxi;

err:
	kfree(tmp);
	goto out;
}

/**
 * _cxlflash_disk_detach() - detaches a LUN from a context
 * @sdev:	SCSI device associated with LUN.
 * @ctxi:	Context owning resources.
 * @detach:	Detach ioctl data structure.
 *
 * As part of the detach, all per-context resources associated with the LUN
 * are cleaned up. When detaching the last LUN for a context, the context
 * itself is cleaned up and released.
 *
 * Return: 0 on success, -errno on failure
 */
static int _cxlflash_disk_detach(struct scsi_device *sdev,
				 struct ctx_info *ctxi,
				 struct dk_cxlflash_detach *detach)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct lun_access *lun_access, *t;
	struct dk_cxlflash_release rel;
	bool unlock_ctx = false;

	int i;
	int rc = 0;
	int lfd;
	u64 ctxid = DECODE_CTXID(detach->context_id),
	    rctxid = detach->context_id;

	pr_debug("%s: ctxid=%llu\n", __func__, ctxid);

	if (!ctxi) {
		ctxi = get_context(cfg, rctxid, lli, CTX_CTRL_ERR_FALLBACK);
		if (unlikely(!ctxi)) {
			pr_err("%s: Bad context! (%llu)\n", __func__, ctxid);
			rc = -EINVAL;
			goto out;
		}

		unlock_ctx = true;
	}

	/* Cleanup outstanding resources tied to this LUN */
	if (ctxi->rht_out) {
		marshal_det_to_rele(detach, &rel);
		for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
			if (ctxi->rht_lun[i] == lli) {
				rel.rsrc_handle = i;
				_cxlflash_disk_release(sdev, ctxi, &rel);
			}

			/* No need to loop further if we're done */
			if (ctxi->rht_out == 0)
				break;
		}
	}

	/* Take our LUN out of context, free the node */
	list_for_each_entry_safe(lun_access, t, &ctxi->luns, list)
		if (lun_access->lli == lli) {
			list_del(&lun_access->list);
			kfree(lun_access);
			lun_access = NULL;
			break;
		}

	/* Tear down context following last LUN cleanup */
	if (list_empty(&ctxi->luns)) {
		mutex_lock(&cfg->ctx_tbl_list_mutex);

		/* Might not have been in error list so conditionally remove */
		if (!list_empty(&ctxi->list))
			list_del(&ctxi->list);
		cfg->ctx_tbl[ctxid] = NULL;
		mutex_unlock(&cfg->ctx_tbl_list_mutex);
		mutex_unlock(&ctxi->mutex);

		lfd = ctxi->lfd;
		destroy_context(cfg, ctxi);
		ctxi = NULL;
		unlock_ctx = false;

		/*
		 * As a last step, clean up external resources when not
		 * already on an external cleanup thread, ie: close(adap_fd).
		 *
		 * NOTE: this will free up the context from the CXL services,
		 * allowing it to dole out the same context_id on a future
		 * (or even currently in-flight) disk_attach operation.
		 */
		if (lfd != -1)
			sys_close(lfd);
	}

out:
	if (unlock_ctx)
		mutex_unlock(&ctxi->mutex);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

static int cxlflash_disk_detach(struct scsi_device *sdev,
				struct dk_cxlflash_detach *detach)
{
	return _cxlflash_disk_detach(sdev, NULL, detach);
}

/**
 * cxlflash_cxl_release() - release handler for adapter file descriptor
 * @inode:	Filesystem inode associated with fd.
 * @file:	File installed with adapter file descriptor.
 *
 * This routine is the release handler for the fops registered with
 * the CXL services on an initial attach for a context. It is called
 * when a close is performed on the adapter file descriptor returned
 * to the user. Programmatically, the user is not required to perform
 * the close, as it is handled internally via the detach ioctl when
 * a context is being removed. Note that nothing prevents the user
 * from performing a close, but the user should be aware that doing
 * so is considered catastrophic and subsequent usage of the superpipe
 * API with previously saved off tokens will fail.
 *
 * When initiated from an external close (either by the user or via
 * a process tear down), the routine derives the context reference
 * and calls detach for each LUN associated with the context. The
 * final detach operation will cause the context itself to be freed.
 * Note that the saved off lfd is reset prior to calling detach to
 * signify that the final detach should not perform a close.
 *
 * When initiated from a detach operation as part of the tear down
 * of a context, the context is first completely freed and then the
 * close is performed. This routine will fail to derive the context
 * reference (due to the context having already been freed) and then
 * call into the CXL release entry point.
 *
 * Thus, with exception to when the CXL process element (context id)
 * lookup fails (a case that should theoretically never occur), every
 * call into this routine results in a complete freeing of a context.
 *
 * As part of the detach, all per-context resources associated with the LUN
 * are cleaned up. When detaching the last LUN for a context, the context
 * itself is cleaned up and released.
 *
 * Return: 0 on success
 */
static int cxlflash_cxl_release(struct inode *inode, struct file *file)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
						cxl_fops);
	struct ctx_info *ctxi = NULL;
	struct dk_cxlflash_detach detach = { { 0 }, 0 };
	struct lun_access *lun_access, *t;
	enum ctx_ctrl ctrl = CTX_CTRL_ERR_FALLBACK | CTX_CTRL_FILE;
	int ctxid;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		goto out;
	}

	ctxi = get_context(cfg, ctxid, file, ctrl);
	if (unlikely(!ctxi)) {
		ctxi = get_context(cfg, ctxid, file, ctrl | CTX_CTRL_CLONE);
		if (!ctxi) {
			pr_debug("%s: Context %d already free!\n",
				 __func__, ctxid);
			goto out_release;
		}

		pr_debug("%s: Another process owns context %d!\n",
			 __func__, ctxid);
		mutex_unlock(&ctxi->mutex);
		goto out;
	}

	pr_debug("%s: close(%d) for context %d\n",
		 __func__, ctxi->lfd, ctxid);

	/* Reset the file descriptor to indicate we're on a close() thread */
	ctxi->lfd = -1;
	detach.context_id = ctxi->ctxid;
	list_for_each_entry_safe(lun_access, t, &ctxi->luns, list)
		_cxlflash_disk_detach(lun_access->sdev, ctxi, &detach);
out_release:
	cxl_fd_release(inode, file);
out:
	pr_debug("%s: returning\n", __func__);
	return 0;
}

/**
 * unmap_context() - clears a previously established mapping
 * @ctxi:	Context owning the mapping.
 *
 * This routine is used to switch between the error notification page
 * (dummy page of all 1's) and the real mapping (established by the CXL
 * fault handler).
 */
static void unmap_context(struct ctx_info *ctxi)
{
	unmap_mapping_range(ctxi->file->f_mapping, 0, 0, 1);
}

/**
 * get_err_page() - obtains and allocates the error notification page
 *
 * Return: error notification page on success, NULL on failure
 */
static struct page *get_err_page(void)
{
	struct page *err_page = global.err_page;
	ulong flags = 0;

	if (unlikely(!err_page)) {
		err_page = alloc_page(GFP_KERNEL);
		if (unlikely(!err_page)) {
			pr_err("%s: Unable to allocate err_page!\n", __func__);
			goto out;
		}

		memset(page_address(err_page), -1, PAGE_SIZE);

		/* Serialize update w/ other threads to avoid a leak */
		spin_lock_irqsave(&global.slock, flags);
		if (likely(!global.err_page))
			global.err_page = err_page;
		else {
			__free_page(err_page);
			err_page = global.err_page;
		}
		spin_unlock_irqrestore(&global.slock, flags);
	}

out:
	pr_debug("%s: returning err_page=%p\n", __func__, err_page);
	return err_page;
}

/**
 * cxlflash_mmap_fault() - mmap fault handler for adapter file descriptor
 * @vma:	VM area associated with mapping.
 * @vmf:	VM fault associated with current fault.
 *
 * To support error notification via MMIO, faults are 'caught' by this routine
 * that was inserted before passing back the adapter file descriptor on attach.
 * When a fault occurs, this routine evaluates if error recovery is active and
 * if so, installs the error page to 'notify' the user about the error state.
 * During normal operation, the fault is simply handled by the original fault
 * handler that was installed by CXL services as part of initializing the
 * adapter file descriptor.
 *
 * Return: 0 on success, VM_FAULT_SIGBUS on failure
 */
static int cxlflash_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *file = vma->vm_file;
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
						cxl_fops);
	struct ctx_info *ctxi = NULL;
	struct page *err_page = NULL;
	enum ctx_ctrl ctrl = CTX_CTRL_ERR_FALLBACK | CTX_CTRL_FILE;
	int rc = 0;
	int ctxid;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		goto err;
	}

	ctxi = get_context(cfg, ctxid, file, ctrl);
	if (unlikely(!ctxi)) {
		pr_err("%s: Bad context! (%d)\n", __func__, ctxid);
		goto err;
	}

	pr_debug("%s: fault(%d) for context %d\n",
		 __func__, ctxi->lfd, ctxid);

	if (likely(!ctxi->err_recovery_active))
		rc = ctxi->cxl_mmap_vmops->fault(vma, vmf);
	else {
		pr_debug("%s: err recovery active, use err_page!\n", __func__);

		err_page = get_err_page();
		if (unlikely(!err_page)) {
			pr_err("%s: Could not obtain error page!\n", __func__);
			rc = VM_FAULT_RETRY;
			goto out;
		}

		get_page(err_page);
		vmf->page = err_page;
	}

out:
	if (likely(ctxi))
		mutex_unlock(&ctxi->mutex);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;

err:
	rc = VM_FAULT_SIGBUS;
	goto out;
}

/*
 * Local MMAP vmops to 'catch' faults
 */
static const struct vm_operations_struct cxlflash_mmap_vmops = {
	.fault = cxlflash_mmap_fault,
};

/**
 * cxlflash_cxl_mmap() - mmap handler for adapter file descriptor
 * @file:	File installed with adapter file descriptor.
 * @vma:	VM area associated with mapping.
 *
 * Installs local mmap vmops to 'catch' faults for error notification support.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_cxl_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
						cxl_fops);
	struct ctx_info *ctxi = NULL;
	enum ctx_ctrl ctrl = CTX_CTRL_ERR_FALLBACK | CTX_CTRL_FILE;
	int ctxid;
	int rc = 0;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		rc = -EIO;
		goto out;
	}

	ctxi = get_context(cfg, ctxid, file, ctrl);
	if (unlikely(!ctxi)) {
		pr_err("%s: Bad context! (%d)\n", __func__, ctxid);
		rc = -EIO;
		goto out;
	}

	pr_debug("%s: mmap(%d) for context %d\n", __func__, ctxi->lfd, ctxid);

	rc = cxl_fd_mmap(file, vma);
	if (likely(!rc)) {
		/* Insert ourself in the mmap fault handler path */
		ctxi->cxl_mmap_vmops = vma->vm_ops;
		vma->vm_ops = &cxlflash_mmap_vmops;
	}

out:
	if (likely(ctxi))
		mutex_unlock(&ctxi->mutex);
	return rc;
}

/*
 * Local fops for adapter file descriptor
 */
static const struct file_operations cxlflash_cxl_fops = {
	.owner = THIS_MODULE,
	.mmap = cxlflash_cxl_mmap,
	.release = cxlflash_cxl_release,
};

/**
 * cxlflash_mark_contexts_error() - move contexts to error state and list
 * @cfg:	Internal structure associated with the host.
 *
 * A context is only moved over to the error list when there are no outstanding
 * references to it. This ensures that a running operation has completed. After
 * marking all contexts in error, the CPU is scheduled to allow user threads
 * time to respond to the freshly installed error page.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_mark_contexts_error(struct cxlflash_cfg *cfg)
{
	int i, rc = 0;
	struct ctx_info *ctxi = NULL;

	reset_local(cfg);

	mutex_lock(&cfg->ctx_tbl_list_mutex);

	for (i = 0; i < MAX_CONTEXT; i++) {
		ctxi = cfg->ctx_tbl[i];
		if (ctxi) {
			mutex_lock(&ctxi->mutex);
			cfg->ctx_tbl[i] = NULL;
			list_add(&ctxi->list, &cfg->ctx_err_recovery);
			ctxi->err_recovery_active = true;
			ctxi->ctrl_map = NULL;
			unmap_context(ctxi);
			mutex_unlock(&ctxi->mutex);
		}
	}

	mutex_unlock(&cfg->ctx_tbl_list_mutex);
	schedule();
	return rc;
}

/*
 * Dummy NULL fops
 */
static const struct file_operations null_fops = {
	.owner = THIS_MODULE,
};

/**
 * cxlflash_disk_attach() - attach a LUN to a context
 * @sdev:	SCSI device associated with LUN.
 * @attach:	Attach ioctl data structure.
 *
 * Creates a context and attaches LUN to it. A LUN can only be attached
 * one time to a context (subsequent attaches for the same context/LUN pair
 * are not supported). Additional LUNs can be attached to a context by
 * specifying the 'reuse' flag defined in the cxlflash_ioctl.h header.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_disk_attach(struct scsi_device *sdev,
				struct dk_cxlflash_attach *attach)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
	struct llun_info *lli = sdev->hostdata;
	struct glun_info *gli = lli->parent;
	struct cxl_ioctl_start_work *work;
	struct ctx_info *ctxi = NULL;
	struct lun_access *lun_access = NULL;
	int rc = 0;
	u32 perms;
	int ctxid = -1;
	u64 rctxid = 0UL;
	struct file *file;

	struct cxl_context *ctx;

	int fd = -1;

	/* On first attach set fileops */
	if (atomic_read(&cfg->num_user_contexts) == 0)
		cfg->cxl_fops = cxlflash_cxl_fops;

	if (attach->num_interrupts > 4) {
		pr_err("%s: Cannot support this many interrupts %llu\n",
		       __func__, attach->num_interrupts);
		rc = -EINVAL;
		goto out;
	}

	if (gli->max_lba == 0) {
		pr_debug("%s: No capacity info yet for this LUN (%016llX)\n",
			 __func__, lli->lun_id[sdev->channel]);
		rc = read_cap16(sdev, lli);
		if (rc) {
			pr_err("%s: Invalid device! (%d)\n", __func__, rc);
			rc = -ENODEV;
			goto out;
		}
		pr_debug("%s: LBA = %016llX\n", __func__, gli->max_lba);
		pr_debug("%s: BLK_LEN = %08X\n", __func__, gli->blk_len);
	}

	if (attach->hdr.flags & DK_CXLFLASH_ATTACH_REUSE_CONTEXT) {
		rctxid = attach->context_id;
		ctxi = get_context(cfg, rctxid, NULL, 0);
		if (!ctxi) {
			pr_err("%s: Bad context! (%016llX)\n",
			       __func__, rctxid);
			rc = -EINVAL;
			goto out;
		}

		list_for_each_entry(lun_access, &ctxi->luns, list)
			if (lun_access->lli == lli) {
				pr_err("%s: Already attached!\n", __func__);
				rc = -EINVAL;
				goto out;
			}
	}

	lun_access = kzalloc(sizeof(*lun_access), GFP_KERNEL);
	if (unlikely(!lun_access)) {
		pr_err("%s: Unable to allocate lun_access!\n", __func__);
		rc = -ENOMEM;
		goto out;
	}

	lun_access->lli = lli;
	lun_access->sdev = sdev;

	/* Non-NULL context indicates reuse */
	if (ctxi) {
		pr_debug("%s: Reusing context for LUN! (%016llX)\n",
			 __func__, rctxid);
		list_add(&lun_access->list, &ctxi->luns);
		fd = ctxi->lfd;
		goto out_attach;
	}

	ctx = cxl_dev_context_init(cfg->dev);
	if (unlikely(IS_ERR_OR_NULL(ctx))) {
		pr_err("%s: Could not initialize context %p\n", __func__, ctx);
		rc = -ENODEV;
		goto err0;
	}

	ctxid = cxl_process_element(ctx);
	if (unlikely((ctxid > MAX_CONTEXT) || (ctxid < 0))) {
		pr_err("%s: ctxid (%d) invalid!\n", __func__, ctxid);
		rc = -EPERM;
		goto err1;
	}

	file = cxl_get_fd(ctx, &cfg->cxl_fops, &fd);
	if (unlikely(fd < 0)) {
		rc = -ENODEV;
		pr_err("%s: Could not get file descriptor\n", __func__);
		goto err1;
	}

	/* Translate read/write O_* flags from fcntl.h to AFU permission bits */
	perms = SISL_RHT_PERM(attach->hdr.flags + 1);

	ctxi = create_context(cfg, ctx, ctxid, fd, file, perms);
	if (unlikely(!ctxi)) {
		pr_err("%s: Failed to create context! (%d)\n", __func__, ctxid);
		goto err2;
	}

	work = &ctxi->work;
	work->num_interrupts = attach->num_interrupts;
	work->flags = CXL_START_WORK_NUM_IRQS;

	rc = cxl_start_work(ctx, work);
	if (unlikely(rc)) {
		pr_debug("%s: Could not start context rc=%d\n", __func__, rc);
		goto err3;
	}

	rc = afu_attach(cfg, ctxi);
	if (unlikely(rc)) {
		pr_err("%s: Could not attach AFU rc %d\n", __func__, rc);
		goto err4;
	}

	/*
	 * No error paths after this point. Once the fd is installed it's
	 * visible to user space and can't be undone safely on this thread.
	 */
	list_add(&lun_access->list, &ctxi->luns);
	mutex_lock(&cfg->ctx_tbl_list_mutex);
	cfg->ctx_tbl[ctxid] = ctxi;
	mutex_unlock(&cfg->ctx_tbl_list_mutex);
	fd_install(fd, file);

out_attach:
	attach->hdr.return_flags = 0;
	attach->context_id = ctxi->ctxid;
	attach->block_size = gli->blk_len;
	attach->mmio_size = sizeof(afu->afu_map->hosts[0].harea);
	attach->last_lba = gli->max_lba;
	attach->max_xfer = (sdev->host->max_sectors * 512) / gli->blk_len;

out:
	attach->adap_fd = fd;

	if (ctxi)
		mutex_unlock(&ctxi->mutex);

	pr_debug("%s: returning ctxid=%d fd=%d bs=%lld rc=%d llba=%lld\n",
		 __func__, ctxid, fd, attach->block_size, rc, attach->last_lba);
	return rc;

err4:
	cxl_stop_context(ctx);
err3:
	destroy_context(cfg, ctxi);
err2:
	/*
	 * XXX - look at collapsing this such that we don't need to override
	 * the fops. Instead, we should be able to simplify some of this error
	 * handling with the notion that CXL cleanup will be performed via the
	 * release call that fput(file) makes.
	 *
	 * Here, we're overriding the fops with a dummy all-NULL fops because
	 * fput() calls the release fop, which will cause us to mistakenly
	 * call into the CXL code. Rather than try to add yet more complexity
	 * to that routine (cxlflash_cxl_release) we should try to fix the
	 * issue here.
	 */
	file->f_op = &null_fops;
	fput(file);
	put_unused_fd(fd);
	fd = -1;
err1:
	cxl_release_context(ctx);
err0:
	kfree(lun_access);
	goto out;
}

/**
 * cxlflash_manage_lun() - handles lun management activities
 * @sdev:	SCSI device associated with LUN.
 * @manage:	Manage ioctl data structure.
 *
 * This routine is used to notify the driver about a LUN's WWID and associate
 * SCSI devices (sdev) with a global LUN instance. Additionally it serves to
 * change a LUN's operating mode: legacy or superpipe.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_manage_lun(struct scsi_device *sdev,
			       struct dk_cxlflash_manage_lun *manage)
{
	int rc = 0;
	struct llun_info *lli = NULL;
	u64 flags = manage->hdr.flags;
	u32 chan = sdev->channel;

	lli = lookup_lun(sdev, manage->wwid);
	pr_debug("%s: ENTER: WWID = %016llX%016llX, flags = %016llX li = %p\n",
		 __func__, get_unaligned_le64(&manage->wwid[0]),
		 get_unaligned_le64(&manage->wwid[8]),
		 manage->hdr.flags, lli);
	if (unlikely(!lli)) {
		rc = -ENOMEM;
		goto out;
	}

	if (flags & DK_CXLFLASH_MANAGE_LUN_ENABLE_SUPERPIPE) {
		if (lli->newly_created)
			lli->port_sel = CHAN2PORT(chan);
		else
			lli->port_sel = BOTH_PORTS;
		/* Store off lun in unpacked, AFU-friendly format */
		lli->lun_id[chan] = lun_to_lunid(sdev->lun);
		sdev->hostdata = lli;
	} else if (flags & DK_CXLFLASH_MANAGE_LUN_DISABLE_SUPERPIPE) {
		if (lli->parent->mode != MODE_NONE)
			rc = -EBUSY;
		else
			sdev->hostdata = NULL;
	}

out:
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

/**
 * recover_context() - recovers a context in error
 * @cfg:	Internal structure associated with the host.
 * @ctxi:	Context to release.
 *
 * Restablishes the state for a context-in-error.
 *
 * Return: 0 on success, -errno on failure
 */
static int recover_context(struct cxlflash_cfg *cfg, struct ctx_info *ctxi)
{
	int rc = 0;
	int old_fd, fd = -1;
	int ctxid = -1;
	struct file *file;
	struct cxl_context *ctx;
	struct afu *afu = cfg->afu;

	ctx = cxl_dev_context_init(cfg->dev);
	if (unlikely(IS_ERR_OR_NULL(ctx))) {
		pr_err("%s: Could not initialize context %p\n", __func__, ctx);
		rc = -ENODEV;
		goto out;
	}

	ctxid = cxl_process_element(ctx);
	if (unlikely((ctxid > MAX_CONTEXT) || (ctxid < 0))) {
		pr_err("%s: ctxid (%d) invalid!\n", __func__, ctxid);
		rc = -EPERM;
		goto err1;
	}

	file = cxl_get_fd(ctx, &cfg->cxl_fops, &fd);
	if (unlikely(fd < 0)) {
		rc = -ENODEV;
		pr_err("%s: Could not get file descriptor\n", __func__);
		goto err1;
	}

	rc = cxl_start_work(ctx, &ctxi->work);
	if (unlikely(rc)) {
		pr_err("%s: Could not start context rc=%d\n", __func__, rc);
		goto err2;
	}

	/* Update with new MMIO area based on updated context id */
	ctxi->ctrl_map = &afu->afu_map->ctrls[ctxid].ctrl;

	rc = afu_attach(cfg, ctxi);
	if (rc) {
		pr_err("%s: Could not attach AFU rc %d\n", __func__, rc);
		goto err3;
	}

	/*
	 * No error paths after this point. Once the fd is installed it's
	 * visible to user space and can't be undone safely on this thread.
	 */
	old_fd = ctxi->lfd;
	ctxi->ctxid = ENCODE_CTXID(ctxi, ctxid);
	ctxi->lfd = fd;
	ctxi->ctx = ctx;
	ctxi->file = file;

	/* Put context back in table (note the reinit of the context list) */
	mutex_lock(&cfg->ctx_tbl_list_mutex);
	list_del_init(&ctxi->list);
	cfg->ctx_tbl[ctxid] = ctxi;
	mutex_unlock(&cfg->ctx_tbl_list_mutex);
	fd_install(fd, file);

	/* Release the original adapter fd and associated CXL resources */
	sys_close(old_fd);
out:
	pr_debug("%s: returning ctxid=%d fd=%d rc=%d\n",
		 __func__, ctxid, fd, rc);
	return rc;

err3:
	cxl_stop_context(ctx);
err2:
	fput(file);
	put_unused_fd(fd);
err1:
	cxl_release_context(ctx);
	goto out;
}

/**
 * check_eeh() - checks and responds to the current EEH state
 * @cfg:	Internal structure associated with the host.
 *
 * This routine can block and should only be used on process context.
 * Note that when waking up from waiting on the EEH event to clear,
 * the state must be checked again in case another EEH has occurred or
 * the previous event failed recovery.
 *
 * Return: 0 on success, -errno on failure
 */
static int check_eeh(struct cxlflash_cfg *cfg)
{
	int rc = 0;

retry:
	switch (cfg->eeh_active) {
	case EEH_STATE_ACTIVE:
		pr_debug("%s: EEH Active, going to wait...\n", __func__);
		rc = wait_event_interruptible(cfg->eeh_waitq,
					      cfg->eeh_active !=
					      EEH_STATE_ACTIVE);
		if (unlikely(rc))
			goto out;
		goto retry;
	case EEH_STATE_FAILED:
		pr_debug("%s: EEH Failed\n", __func__);
		rc = -ENODEV;
		goto out;
	case EEH_STATE_NONE:
		break;
	}
out:
	return rc;
}

/**
 * cxlflash_afu_recover() - initiates AFU recovery
 * @sdev:	SCSI device associated with LUN.
 * @recover:	Recover ioctl data structure.
 *
 * Because a user can detect an error condition before the kernel, it is
 * quite possible for this routine to act as the kernel's EEH detection
 * source (MMIO read of mbox_r). Because of this, there is a window of
 * time where an EEH might have been detected but not yet 'serviced'
 * (callback invoked, causing the EEH state to flip). To avoid looping
 * in this routine during that window, a 1 second sleep is in place
 * between the time the MMIO failure is detected and the time a wait
 * on the EEH wait queue is attempted.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_afu_recover(struct scsi_device *sdev,
				struct dk_cxlflash_recover_afu *recover)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct afu *afu = cfg->afu;
	struct ctx_info *ctxi = NULL;
	u64 ctxid = DECODE_CTXID(recover->context_id),
	    rctxid = recover->context_id;
	long reg;
	int rc = 0;

	pr_debug("%s: reason 0x%016llX rctxid=%016llX\n", __func__,
		 recover->reason, rctxid);

retry:
	/* Ensure that this process is attached to the context */
	ctxi = get_context(cfg, rctxid, lli, CTX_CTRL_ERR_FALLBACK);
	if (unlikely(!ctxi)) {
		pr_err("%s: Bad context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto out;
	}

	if (ctxi->err_recovery_active) {
		rc = cxlflash_init_luntable(cfg, lli);
		if (unlikely(rc)) {
			pr_err("%s: Init LUN table for LUN %d (rc=%d)\n",
			       __func__, lli->lun_index, rc);
			goto out;
		}

		rc = recover_context(cfg, ctxi);
		if (unlikely(rc)) {
			pr_err("%s: Recovery failed for context %llu (rc=%d)\n",
			       __func__, ctxid, rc);
			goto out;
		}

		ctxi->err_recovery_active = false;
		recover->context_id = ctxi->ctxid;
		recover->adap_fd = ctxi->lfd;
		recover->mmio_size = sizeof(afu->afu_map->hosts[0].harea);
		recover->hdr.return_flags |=
			DK_CXLFLASH_RECOVER_AFU_CONTEXT_RESET;
		goto out;
	}

	/* Test if in error state */
	reg = readq_be(&afu->ctrl_map->mbox_r);
	if (reg == -1) {
		pr_info("%s: MMIO read fail! Wait for recovery...\n", __func__);
		mutex_unlock(&ctxi->mutex);
		ctxi = NULL;
		ssleep(1);
		rc = check_eeh(cfg);
		if (unlikely(rc))
			goto out;
		goto retry;
	}

	pr_debug("%s: MMIO working, no recovery required!\n", __func__);
out:
	if (likely(ctxi))
		mutex_unlock(&ctxi->mutex);
	return rc;
}

/**
 * process_sense() - evaluates and processes sense data
 * @sdev:	SCSI device associated with LUN.
 * @verify:	Verify ioctl data structure.
 *
 * Return: 0 on success, -errno on failure
 */
static int process_sense(struct scsi_device *sdev,
			 struct dk_cxlflash_verify *verify)
{
	struct request_sense_data *sense_data = (struct request_sense_data *)
		&verify->sense_data;
	struct llun_info *lli = sdev->hostdata;
	struct glun_info *gli = lli->parent;
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	u64 prev_lba = gli->max_lba;
	int rc = 0;

	switch (sense_data->sense_key) {
	case NO_SENSE:
	case RECOVERED_ERROR:
		/* fall through */
	case NOT_READY:
		break;
	case UNIT_ATTENTION:
		switch (sense_data->add_sense_key) {
		case 0x29: /* Power on Reset or Device Reset */
			/* fall through */
		case 0x2A: /* Device settings/capacity changed */
			rc = read_cap16(sdev, lli);
			if (rc) {
				rc = -ENODEV;
				break;
			}
			if (prev_lba != gli->max_lba)
				pr_debug("%s: Capacity changed old=%lld "
					 "new=%lld\n", __func__, prev_lba,
					 gli->max_lba);
			break;
		case 0x3F: /* Report LUNs changed, Rescan. */
			scsi_scan_host(cfg->host);
			break;
		default:
			rc = -EIO;
			break;
		}
		break;
	default:
		rc = -EIO;
		break;
	}
	pr_debug("%s: sense_key %x asc %x rc %d\n", __func__,
		 sense_data->sense_key, sense_data->add_sense_key, rc);
	return rc;
}

/**
 * cxlflash_disk_verify() - verifies a LUN is the same and handle size changes
 * @sdev:	SCSI device associated with LUN.
 * @verify:	Verify ioctl data structure.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_disk_verify(struct scsi_device *sdev,
				struct dk_cxlflash_verify *verify)
{
	int rc = 0;
	struct ctx_info *ctxi = NULL;
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	struct glun_info *gli = lli->parent;
	struct sisl_rht_entry *rhte = NULL;
	res_hndl_t rhndl = verify->rsrc_handle;
	u64 ctxid = DECODE_CTXID(verify->context_id),
	    rctxid = verify->context_id;
	u64 last_lba = 0;

	pr_debug("%s: ctxid=%llu rhndl=0x%llx, hint=0x%llx\n",
		 __func__, ctxid, verify->rsrc_handle, verify->hint);

	ctxi = get_context(cfg, rctxid, lli, 0);
	if (unlikely(!ctxi)) {
		pr_err("%s: Bad context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto out;
	}

	rhte = get_rhte(ctxi, rhndl, lli);
	if (unlikely(!rhte)) {
		pr_err("%s: Bad resource handle! (%d)\n", __func__, rhndl);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * Look at the hint/sense to see if it requires us to redrive
	 * inquiry (i.e. the Unit attention is due to the WWN changing).
	 */
	if (verify->hint & DK_CXLFLASH_VERIFY_HINT_SENSE) {
		rc = process_sense(sdev, verify);
		if (unlikely(rc)) {
			pr_err("%s: Failed to validate sense data! (%d)\n",
			       __func__, rc);
			goto out;
		}
	}

	switch (gli->mode) {
	case MODE_PHYSICAL:
		last_lba = gli->max_lba;
		break;
	case MODE_VIRTUAL:
		last_lba = (rhte->lxt_cnt * MC_CHUNK_SIZE * gli->blk_len);
		last_lba /= CXLFLASH_BLOCK_SIZE;
		last_lba--;
		break;
	default:
		BUG();
	}

	verify->last_lba = last_lba;

out:
	if (likely(ctxi))
		mutex_unlock(&ctxi->mutex);
	pr_debug("%s: returning rc=%d llba=%lld\n",
		 __func__, rc, verify->last_lba);
	return rc;
}

/**
 * decode_ioctl() - translates an encoded ioctl to an easily identifiable string
 * @cmd:	The ioctl command to decode.
 *
 * Return: A string identifying the decoded ioctl.
 */
static char *decode_ioctl(int cmd)
{
	switch (cmd) {
	case DK_CXLFLASH_ATTACH:
		return __stringify_1(DK_CXLFLASH_ATTACH);
	case DK_CXLFLASH_USER_DIRECT:
		return __stringify_1(DK_CXLFLASH_USER_DIRECT);
	case DK_CXLFLASH_USER_VIRTUAL:
		return __stringify_1(DK_CXLFLASH_USER_VIRTUAL);
	case DK_CXLFLASH_VLUN_RESIZE:
		return __stringify_1(DK_CXLFLASH_VLUN_RESIZE);
	case DK_CXLFLASH_RELEASE:
		return __stringify_1(DK_CXLFLASH_RELEASE);
	case DK_CXLFLASH_DETACH:
		return __stringify_1(DK_CXLFLASH_DETACH);
	case DK_CXLFLASH_VERIFY:
		return __stringify_1(DK_CXLFLASH_VERIFY);
	case DK_CXLFLASH_CLONE:
		return __stringify_1(DK_CXLFLASH_CLONE);
	case DK_CXLFLASH_RECOVER_AFU:
		return __stringify_1(DK_CXLFLASH_RECOVER_AFU);
	case DK_CXLFLASH_MANAGE_LUN:
		return __stringify_1(DK_CXLFLASH_MANAGE_LUN);
	}

	return "UNKNOWN";
}

/**
 * cxlflash_disk_direct_open() - opens a direct (physical) disk
 * @sdev:	SCSI device associated with LUN.
 * @arg:	UDirect ioctl data structure.
 *
 * On successful return, the user is informed of the resource handle
 * to be used to identify the direct lun and the size (in blocks) of
 * the direct lun in last LBA format.
 *
 * Return: 0 on success, -errno on failure
 */
static int cxlflash_disk_direct_open(struct scsi_device *sdev, void *arg)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
	struct llun_info *lli = sdev->hostdata;
	struct glun_info *gli = lli->parent;

	struct dk_cxlflash_udirect *pphys = (struct dk_cxlflash_udirect *)arg;

	u64 ctxid = DECODE_CTXID(pphys->context_id),
	    rctxid = pphys->context_id;
	u64 lun_size = 0;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;
	u32 port = CHAN2PORT(sdev->channel);

	int rc = 0;

	struct ctx_info *ctxi = NULL;
	struct sisl_rht_entry *rhte = NULL;

	pr_debug("%s: ctxid=%llu ls=0x%llx\n", __func__, ctxid, lun_size);

	rc = cxlflash_lun_attach(gli, MODE_PHYSICAL);
	if (unlikely(rc)) {
		pr_err("%s: Failed to attach to LUN! (PHYSICAL)\n", __func__);
		goto out;
	}

	ctxi = get_context(cfg, rctxid, lli, 0);
	if (unlikely(!ctxi)) {
		pr_err("%s: Bad context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto err1;
	}

	rhte = rhte_checkout(ctxi, lli);
	if (unlikely(!rhte)) {
		pr_err("%s: too many opens for this context\n", __func__);
		rc = -EMFILE;	/* too many opens  */
		goto err1;
	}

	rsrc_handle = (rhte - ctxi->rht_start);

	rht_format1(rhte, lli->lun_id[sdev->channel], ctxi->rht_perms, port);
	cxlflash_afu_sync(afu, ctxid, rsrc_handle, AFU_LW_SYNC);

	last_lba = gli->max_lba;
	pphys->hdr.return_flags = 0;
	pphys->last_lba = last_lba;
	pphys->rsrc_handle = rsrc_handle;

out:
	if (likely(ctxi))
		mutex_unlock(&ctxi->mutex);
	pr_debug("%s: returning handle 0x%llx rc=%d llba %lld\n",
		 __func__, rsrc_handle, rc, last_lba);
	return rc;

err1:
	cxlflash_lun_detach(gli);
	goto out;
}

/**
 * ioctl_common() - common IOCTL handler for driver
 * @sdev:	SCSI device associated with LUN.
 * @cmd:	IOCTL command.
 *
 * Handles common fencing operations that are valid for multiple ioctls. In
 * the event of an EEH failure, allow through ioctls that are cleanup oriented
 * in nature.
 *
 * Return: 0 on success, -errno on failure
 */
static int ioctl_common(struct scsi_device *sdev, int cmd)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct llun_info *lli = sdev->hostdata;
	int rc = 0;

	if (unlikely(!lli)) {
		pr_debug("%s: Unknown LUN\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	rc = check_eeh(cfg);
	if (unlikely(rc) && (cfg->eeh_active == EEH_STATE_FAILED)) {
		switch (cmd) {
		case DK_CXLFLASH_VLUN_RESIZE:
		case DK_CXLFLASH_RELEASE:
		case DK_CXLFLASH_DETACH:
			pr_debug("%s: Command override! (%d)\n", __func__, rc);
			rc = 0;
			break;
		}
	}
out:
	return rc;
}

/**
 * cxlflash_ioctl() - IOCTL handler for driver
 * @sdev:	SCSI device associated with LUN.
 * @cmd:	IOCTL command.
 * @arg:	Userspace ioctl data structure.
 *
 * Return: 0 on success, -errno on failure
 */
int cxlflash_ioctl(struct scsi_device *sdev, int cmd, void __user *arg)
{
	typedef int (*sioctl) (struct scsi_device *, void *);

	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
	struct dk_cxlflash_hdr *hdr;
	char buf[MAX_CXLFLASH_IOCTL_SZ];
	size_t size = 0;
	bool known_ioctl = false;
	int idx;
	int rc = 0;
	struct Scsi_Host *shost = sdev->host;
	sioctl do_ioctl = NULL;

	static const struct {
		size_t size;
		sioctl ioctl;
	} ioctl_tbl[] = {	/* NOTE: order matters here */
	{sizeof(struct dk_cxlflash_attach), (sioctl)cxlflash_disk_attach},
	{sizeof(struct dk_cxlflash_udirect), cxlflash_disk_direct_open},
	{sizeof(struct dk_cxlflash_uvirtual), cxlflash_disk_virtual_open},
	{sizeof(struct dk_cxlflash_resize), (sioctl)cxlflash_vlun_resize},
	{sizeof(struct dk_cxlflash_release), (sioctl)cxlflash_disk_release},
	{sizeof(struct dk_cxlflash_detach), (sioctl)cxlflash_disk_detach},
	{sizeof(struct dk_cxlflash_verify), (sioctl)cxlflash_disk_verify},
	{sizeof(struct dk_cxlflash_clone), (sioctl)cxlflash_disk_clone},
	{sizeof(struct dk_cxlflash_recover_afu), (sioctl)cxlflash_afu_recover},
	{sizeof(struct dk_cxlflash_manage_lun), (sioctl)cxlflash_manage_lun},
	};

	/* Restrict command set to physical support only for internal LUN */
	if (afu->internal_lun)
		switch (cmd) {
		case DK_CXLFLASH_USER_VIRTUAL:
		case DK_CXLFLASH_VLUN_RESIZE:
		case DK_CXLFLASH_RELEASE:
		case DK_CXLFLASH_CLONE:
			pr_err("%s: %s not supported for lun_mode=%d\n",
			       __func__, decode_ioctl(cmd), afu->internal_lun);
			rc = -EINVAL;
			goto cxlflash_ioctl_exit;
		}

	switch (cmd) {
	case DK_CXLFLASH_ATTACH:
	case DK_CXLFLASH_USER_DIRECT:
	case DK_CXLFLASH_USER_VIRTUAL:
	case DK_CXLFLASH_VLUN_RESIZE:
	case DK_CXLFLASH_RELEASE:
	case DK_CXLFLASH_DETACH:
	case DK_CXLFLASH_VERIFY:
	case DK_CXLFLASH_CLONE:
	case DK_CXLFLASH_RECOVER_AFU:
		pr_debug("%s: %s (%08X) on dev(%d/%d/%d/%llu)\n", __func__,
			 decode_ioctl(cmd), cmd, shost->host_no, sdev->channel,
			 sdev->id, sdev->lun);
		rc = ioctl_common(sdev, cmd);
		if (unlikely(rc))
			goto cxlflash_ioctl_exit;

		/* fall through */

	case DK_CXLFLASH_MANAGE_LUN:
		known_ioctl = true;
		idx = _IOC_NR(cmd) - _IOC_NR(DK_CXLFLASH_ATTACH);
		size = ioctl_tbl[idx].size;
		do_ioctl = ioctl_tbl[idx].ioctl;

		if (likely(do_ioctl))
			break;

		/* fall through */
	default:
		rc = -EINVAL;
		goto cxlflash_ioctl_exit;
	}

	if (unlikely(copy_from_user(&buf, arg, size))) {
		pr_err("%s: copy_from_user() fail! "
		       "size=%lu cmd=%d (%s) arg=%p\n",
		       __func__, size, cmd, decode_ioctl(cmd), arg);
		rc = -EFAULT;
		goto cxlflash_ioctl_exit;
	}

	hdr = (struct dk_cxlflash_hdr *)&buf;
	if (hdr->version != 0) {
		pr_err("%s: Version %u not supported for %s\n",
		       __func__, hdr->version, decode_ioctl(cmd));
		rc = -EINVAL;
		goto cxlflash_ioctl_exit;
	}

	rc = do_ioctl(sdev, (void *)&buf);
	if (likely(!rc))
		if (unlikely(copy_to_user(arg, &buf, size))) {
			pr_err("%s: copy_to_user() fail! "
			       "size=%lu cmd=%d (%s) arg=%p\n",
			       __func__, size, cmd, decode_ioctl(cmd), arg);
			rc = -EFAULT;
		}

	/* fall through to exit */

cxlflash_ioctl_exit:
	if (unlikely(rc && known_ioctl))
		pr_err("%s: ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
		       "returned rc %d\n", __func__,
		       decode_ioctl(cmd), cmd, shost->host_no,
		       sdev->channel, sdev->id, sdev->lun, rc);
	else
		pr_debug("%s: ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
			 "returned rc %d\n", __func__, decode_ioctl(cmd),
			 cmd, shost->host_no, sdev->channel, sdev->id,
			 sdev->lun, rc);
	return rc;
}

