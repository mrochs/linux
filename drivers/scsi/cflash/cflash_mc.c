/*
* Copyright 2015 IBM Corp.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
*/
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/syscalls.h>
#include <uapi/misc/cxl.h>
#include <misc/cxl.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <asm/unistd.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_cmnd.h>

#include "sislite.h"
#include "cflash.h"
#include "cflash_mc.h"
#include "cflash_ba.h"
#include "cflash_ioctl.h"
#include "afu_fc.h"
#include "mserv.h"

/* Until we figure out how to get the process element, need to include
 * Mikey's header file
 */
#include "cxl.h"

extern int cflash_init_ba(cflash_t *p_cflash, int lunindex);
extern bool provFindVPDKw(const char* i_kw, const uint8_t* i_vpd_buffer,
                   size_t i_vpd_buffer_length,
                   uint8_t* o_kwdata,
                   int* io_kwdata_length);

/* Mask off the low nibble of the length to ensure 16 byte multiple */
#define SISLITE_LEN_MASK 0xFFFFFFF0

void
hexdump(void *data, long len, const char *hdr)
{

        int     i,j,k;
        char    str[18];
        char    *p = (char *)data;

        i=j=k=0;
        printk("%s: length=%ld\n", hdr?hdr:"hexdump()", len);

        /* Print each 16 byte line of data */
        while (i < len)
        {
                if (!(i%16))    /* Print offset at 16 byte bndry */
                        printk("%03x  ",i);

                /* Get next data byte, save ascii, print hex */
                j=(int) p[i++];
                if (j>=32 && j<=126)
                        str[k++] = (char) j;
                else
                        str[k++] = '.';
                printk("%02x ",j);

                /* Add an extra space at 8 byte bndry */
                if (!(i%8))
                {
                        printk(" ");
                        str[k++] = ' ';
                }

                /* Print the ascii at 16 byte bndry */
                if (!(i%16))
                {
                        str[k] = '\0';
                        printk(" %s\n",str);
                        k = 0;
                }
        }

        /* If we didn't end on an even 16 byte bndry, print ascii for partial
         * line. */
        if ((j = i%16)) {
                /* First, space over to ascii region */
                while (i%16)
                {
                        /* Extra space at 8 byte bndry--but not if we
                         * started there (was already inserted) */
                        if (!(i%8) && j != 8)
                                printk(" ");
                        printk("   ");
                        i++;
                }
                /* Terminate the ascii and print it */
                str[k]='\0';
                printk("  %s\n",str);
        }

        return;
}


int cflash_afu_attach(cflash_t *p_cflash,  uint64_t context_id)
{
	afu_t      *p_afu             = p_cflash->p_afu;
	ctx_info_t *p_ctx_info        = &p_afu->ctx_info[context_id]; 
	int   rc                      = 0;
	__u64 reg;

	/* This code reads the mbox w/o knowing if the requester is 
	 * the true owner of the context it wants to register. The 
	 * read has no side effect and does not affect the true 
	 * owner if this is a fraudulent registration attempt.
	  */
	reg = read_64(&p_ctx_info->p_ctrl_map->mbox_r);

	/* zeroed mbox is a locked mbox */
	if (reg == 0) {
		cflash_err("zero mbox reg 0x%llx\n", reg);
	}

	/* This context is not duped and is in a group by 
	 * itself. 
	 */
	p_ctx_info->p_next = p_ctx_info;
	p_ctx_info->p_forw = p_ctx_info;

	/* restrict user to read/write cmds in translated 
	 * mode. User has option to choose read and/or write 
	 * permissions again in mc_open.  
	 */
	write_64(&p_ctx_info->p_ctrl_map->ctx_cap,
		 SISL_CTX_CAP_READ_CMD |
		 SISL_CTX_CAP_WRITE_CMD);

	asm volatile ( "eieio" : : );
	reg = read_64(&p_ctx_info->p_ctrl_map->ctx_cap);

	/* if the write failed, the ctx must have been 
	 * closed since the mbox read and the ctx_cap 
	 * register locked up.  fail the registration 
	 */
	if (reg != (SISL_CTX_CAP_READ_CMD |
		    SISL_CTX_CAP_WRITE_CMD)) {
		cflash_err("ctx may be closed reg=%llx\n", reg);
		rc = -EAGAIN;
		goto out;
	}

	/* the context gets a dedicated RHT tbl unless it 
	 * is dup'ed later. 
	 */
	p_ctx_info->p_rht_info =
		&p_afu->rht_info[context_id];
	p_ctx_info->p_rht_info->ref_cnt = 1;
	memset(p_ctx_info->p_rht_info->rht_start, 0,
	       sizeof(sisl_rht_entry_t)*MAX_RHT_PER_CONTEXT);
	/* make clearing of the RHT visible to AFU before 
	 * MMIO 
	 */
	asm volatile ( "lwsync" : : );

	/* set up MMIO registers pointing to the RHT */
	write_64(&p_ctx_info->p_ctrl_map->rht_start,
		 (__u64)p_ctx_info->p_rht_info->rht_start);
	write_64(&p_ctx_info->p_ctrl_map->rht_cnt_id, 
		 SISL_RHT_CNT_ID((__u64)MAX_RHT_PER_CONTEXT, 
				 (__u64)(p_afu->ctx_hndl))); 
out:
        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;

}


int cflash_disk_attach(struct scsi_device *sdev, void __user *arg)
{
	cflash_t	*p_cflash = (cflash_t *)sdev->host->hostdata;
	afu_t		*p_afu = p_cflash->p_afu;
	lun_info_t *p_lun_info = sdev->hostdata;
	int rc = 0;

	struct dk_capi_attach *parg = (struct dk_capi_attach *)arg;
	struct cxl_context *ctx;

	int fd = 0;

	ctx = cxl_dev_context_init(p_cflash->p_dev);
	if (!ctx) {
		cflash_err("in %s Could not initialize context\n", __func__);
		rc = -ENODEV;
		goto out;
	} 

	/* XXX: Cannot get to the process element until Mikey's headers
	 * are included
	*/
	parg->context_id = (uint64_t)ctx->pe;

	/* 
	 * Create and attach a new file descriptor. This must be the last 
	 * statement as once this is run, the file descritor is visible to 
	 * userspace and can't be undone. No error paths after this as we 
	 * can't free the fd safely.
	 */ 

	p_lun_info->work.num_interrupts = 4;
	p_lun_info->work.flags = CXL_START_WORK_NUM_IRQS;

	fd = cxl_attach_fd(ctx, &(p_lun_info->work)); 
	if (fd < 0) {
		rc = -ENODEV;
		cxl_release_context(ctx);
		cflash_err("Could not attach file descriptor\n");
		goto out; 
	}

	/* XXX: Currently there cannot be any error path after attach_fd.
	 * However the AFU resets the context capabilities on start. 
	 * Until a tear down service is provided this needs to 
	 * not fail
	rc = cflash_afu_attach(p_cflash, parg->context_id);
	 */
	cflash_afu_attach(p_cflash, parg->context_id);
	if (rc)
	{
		cflash_err("in %s Could not attach AFU rc %d\n", __func__, rc);
		cxl_release_context(ctx);
		goto out;
	}

	p_lun_info->lfd = fd;

	parg->return_flags = 0;
	parg->adap_fd = fd;
	parg->block_size = p_lun_info->li.blk_len;
	parg->mmio_size = sizeof(p_afu->p_afu_map->hosts[0].harea);

out:
        cflash_info("in %s returning fd=%d bs=%lld rc=%d\n", 
		    __func__, fd, parg->block_size, rc);
	return rc;
}

int do_mc_close(afu_t    *p_afu,
	    conn_info_t  *p_conn_info,
	    res_hndl_t    res_hndl)
{
	int rc=-EINVAL;

        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return -EINVAL;
}


/*
 * NAME:        cflash_disk_uvirtual
 *
 * FUNCTION:    Unregister a user AFU context with master.
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
 *              When successful:
 *               a. Sets CTX_CAP
 *               b. Sets RHT_START & RHT_CNT registers for the
 *                  registered context
 *               c. Clears all RHT entries effectively making
 *                  all resource handles invalid.
 *               d. goes to rx_ready state
 *
 */
int cflash_disk_uvirtual(struct scsi_device *sdev, void __user *arg)
{
	cflash_t   *p_cflash   = (cflash_t *)sdev->host->hostdata;
	afu_t      *p_afu      = p_cflash->p_afu;
	lun_info_t *p_lun_info = sdev->hostdata;

	struct dk_capi_uvirtual *parg = (struct dk_capi_uvirtual *)arg;

	int   rc;
	int i;

	ctx_info_t *p_ctx_info = &p_afu->ctx_info[parg->context_id]; 
	rht_info_t *p_rht_info = NULL; 
	sisl_rht_entry_t *p_rht_entry = NULL;

	cflash_info("%s, context=0x%llx res_hndl=0x%llx, ls=0x%llx\n",
		    __func__, parg->context_id,
		    parg->rsrc_handle,
		    parg->lun_size);

	if (parg->context_id < MAX_CONTEXT) {
		p_ctx_info = &p_afu->ctx_info[parg->context_id];

		p_rht_info = &p_afu->rht_info[parg->context_id];
	
		cflash_info("in %s ctx 0x%llx ctxinfo %p rhtinfo %p\n", 
			    __func__, parg->context_id, 
			    p_ctx_info, p_rht_info);

		/* find a free RHT entry */ 
		for (i = 0; i <  MAX_RHT_PER_CONTEXT; i++) { 
			if (p_rht_info->rht_start[i].nmask == 0) { 
				p_rht_entry = &p_rht_info->rht_start[i]; 
				break; 
			} 
		} 
		cflash_info("in %s i %d rhti %p rhte %p\n", __func__, 
			    i, p_rht_info, p_rht_entry);
	
		/* if we did not find a free entry, reached max opens allowed 
		 * per context 
		 */ 
		
		if (p_rht_entry == NULL) { 
			cflash_err("in %s too many contexts open\n", __func__); 
			rc = -EMFILE; // too many opens 
			goto out; 
		} 
		
		p_rht_entry->nmask = MC_RHT_NMASK; 
		p_rht_entry->fp = SISL_RHT_FP(0u, 0x3); 
		/* format 0 & perms */ 
		
		parg->rsrc_handle = (p_rht_entry - p_rht_info->rht_start);

		rc =  0; 
	} 
	else { 
		rc =  EINVAL; 
		goto out;
	}

	parg->return_flags = 0;
	parg->block_size = p_lun_info->li.blk_len;
	parg->last_lba = p_lun_info->li.max_lba;

out:
        cflash_info("in %s returning handle 0x%llx rc=%d bs %lld llba %lld\n", 
		    __func__, parg->rsrc_handle, rc, parg->block_size,
		    parg->last_lba);
	return rc;
}


/*
 * NAME:        cflash_disk_release
 *
 * FUNCTION:    Close a virtual LBA space setting it to 0 size and
 *              marking the res_hndl as free/closed.
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
 *              When successful, the RHT entry is cleared.
 */
int cflash_disk_release(struct scsi_device *sdev, void __user *arg)
{
	cflash_t *p_cflash = (cflash_t *)sdev->host->hostdata;
	afu_t    *p_afu    = p_cflash->p_afu;

	struct dk_capi_resize *parg     = (struct dk_capi_resize *)arg;
	res_hndl_t             res_hndl = parg->rsrc_handle;

	int rc = 0;

	ctx_info_t       *p_ctx_info = &p_afu->ctx_info[parg->context_id]; 
	rht_info_t       *p_rht_info = p_ctx_info->p_rht_info; 
	sisl_rht_entry_t *p_rht_entry; 

	cflash_info("%s, context=0x%llx res_hndl=0x%llx, challenge=0x%llx\n",
		    __func__, parg->context_id,
		    parg->rsrc_handle,
		    parg->challenge);

	if (parg->context_id < MAX_CONTEXT) {
		p_ctx_info = &p_afu->ctx_info[parg->context_id];
		p_rht_info = p_ctx_info->p_rht_info;
	} else {
		cflash_info("in %s context id too large 0x%llx\n", __func__,
			    parg->context_id);
		rc = -EINVAL;
		goto out;
	}

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];
		if (p_rht_entry->nmask == 0) { /* not open */ 
			rc = -EINVAL;
			cflash_info("in %s not open\n", __func__);
			goto out;
		}

		/* set size to 0, this will clear LXT_START and LXT_CNT 
		 * fields in the RHT entry 
		 */ 
		parg->req_size = 0;
		cflash_vlun_resize(sdev, arg); // p_conn good ?  
		
		p_rht_entry->nmask = 0; 
		p_rht_entry->fp = 0; 
		
		/* now the RHT entry is all cleared */ 
		rc = 0;
	} 
	else { 
		rc = -EINVAL; 
		cflash_info("in %s resource handle invalid %d\n", __func__,
			    res_hndl);
	}

out:
        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
}



/*
 * NAME:        cflash_disk_detach
 *
 * FUNCTION:    Unregister a user AFU context with master.
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
 *              When successful:
 *               a. RHT_START, RHT_CNT & CTX_CAP registers for the
 *                  context are cleared
 *               b. There is no need to clear RHT entries since
 *                  RHT_CNT=0.
 */
int cflash_disk_detach(struct scsi_device *sdev, void __user *arg)
{
	cflash_t *p_cflash = (cflash_t *)sdev->host->hostdata;
	afu_t    *p_afu    = p_cflash->p_afu;

	struct dk_capi_detach  *parg = (struct dk_capi_detach *)arg;
	struct dk_capi_release *rel  = (struct dk_capi_release *)parg;

	ctx_info_t *p_ctx_info;

	int i;
	int rc=0;

	cflash_info("%s, context=0x%llx\n", __func__, parg->context_id);

	if (parg->context_id < MAX_CONTEXT)
		p_ctx_info = &p_afu->ctx_info[parg->context_id];
	else
	{
		rc =  -EINVAL;
		goto out;
	}


	if (p_ctx_info->ref_cnt-- == 1) {

		/* close the context */
		/* for any resource still open, dealloate LBAs and close 
		 * if nobody else is using it. 
		 */

		if (p_ctx_info->p_rht_info->ref_cnt-- == 1) {
			for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
				rel->rsrc_handle = i;
				cflash_disk_release(sdev, arg);
			}
		}

		/* clear RHT registers for this context */
		write_64(&p_ctx_info->p_ctrl_map->rht_start, 0);
		write_64(&p_ctx_info->p_ctrl_map->rht_cnt_id, 0);
		/* drop all capabilities */
		write_64(&p_ctx_info->p_ctrl_map->ctx_cap, 0);
	}
	/* client can now send another MCREG */

out:
        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
}

// online means the FC link layer has sync and has completed the link layer
// handshake. It is ready for login to start.
void set_port_online(volatile __u64 *p_fc_regs)
{
	__u64 cmdcfg;

	cmdcfg = read_64(&p_fc_regs[FC_MTIP_CMDCONFIG/8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_OFFLINE);  // clear OFF_LINE
	cmdcfg |= (FC_MTIP_CMDCONFIG_ONLINE); // set ON_LINE
	write_64(&p_fc_regs[FC_MTIP_CMDCONFIG/8], cmdcfg);
}

void set_port_offline(volatile __u64 *p_fc_regs)
{
	__u64 cmdcfg;

	cmdcfg = read_64(&p_fc_regs[FC_MTIP_CMDCONFIG/8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_ONLINE); // clear ON_LINE
	cmdcfg |= (FC_MTIP_CMDCONFIG_OFFLINE);  // set OFF_LINE
	write_64(&p_fc_regs[FC_MTIP_CMDCONFIG/8], cmdcfg);
}

// returns 1 - went online
// wait_port_xxx will timeout when cable is not pluggd in
int wait_port_online(volatile __u64 *p_fc_regs,
		     useconds_t delay_us,
		     unsigned int nretry)

{
	__u64 status;

	if (delay_us < 1000) {
		cflash_err("invalid delay specified %d\n", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us/1000);
		status = read_64(&p_fc_regs[FC_MTIP_STATUS/8]);
	}  while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_ONLINE &&
		  nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_ONLINE);
}

// returns 1 - went offline
int wait_port_offline(volatile __u64 *p_fc_regs,
		      useconds_t delay_us,
		      unsigned int nretry)
{
	__u64 status;

	if (delay_us < 1000) {
		cflash_err("invalid delay specified %d\n", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us/1000);
		status = read_64(&p_fc_regs[FC_MTIP_STATUS/8]);
	} while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_OFFLINE &&
		 nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_OFFLINE);
}

// this function can block up to a few seconds
int afu_set_wwpn(afu_t *p_afu, int port, volatile __u64 *p_fc_regs,
		  __u64 wwpn)
{
	int ret = 0;

	set_port_offline(p_fc_regs);

	if (!wait_port_offline(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			       FC_PORT_STATUS_RETRY_CNT)) {
		 cflash_dbg("wait on port %d to go offline timed out\n", port);
		 ret = -1; // but continue on to leave the port back online
	}

	if (ret == 0) {
		write_64(&p_fc_regs[FC_PNAME/8], wwpn);
	}

	set_port_online(p_fc_regs);

	if (!wait_port_online(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT)) {
		cflash_dbg("wait on port %d to go online timed out\n", port);
		ret = -1;
	}

	cflash_info("In %s returning rc=%d\n", __func__, ret);
	
	return ret;
}


void cflash_undo_start_afu(afu_t *p_afu, enum undo_level level)
{
	switch(level)
	{
	case UNDO_AFU_ALL:
	case UNDO_EPOLL_ADD:
	case UNDO_EPOLL_CREATE:
	case UNDO_BIND_SOCK:
	case UNDO_OPEN_SOCK:
	case UNDO_AFU_MMAP:
		cxl_psa_unmap((void *)p_afu->p_afu_map);
	case UNDO_AFU_START:
	case UNDO_AFU_OPEN:
	case UNDO_TIMER:
		/*
		 * Nothing to do for timers; note that in the context of
		 * a non-error path teardown (ie: cflash_terminate_afu)
		 * we should probably ensure all timers are stopped prior
		 * to calling this routine.
		 */
	case UNDO_MLOCK:
	default:
		break;
	}
        cflash_info("in %s returning level=%d\n", __func__, level);
}

int cflash_terminate_afu(afu_t *p_afu)
{
	int i;
	int rc=0;

	/* Ensure all timers are stopped before removing resources */
	for (i = 0; i < NUM_CMDS; i++)
		timer_stop(&p_afu->cmd[i].timer, TRUE);

	cflash_undo_start_afu(p_afu, UNDO_AFU_ALL);

        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
}

void afu_err_intr_init(afu_t *p_afu)
{
	int i;

	/* global async interrupts: AFU clears afu_ctrl on context exit
	 * if async interrupts were sent to that context. This prevents
	 * the AFU form sending further async interrupts when
	 * there is
	 * nobody to receive them.
	 */

	// mask all
	write_64(&p_afu->p_afu_map->global.regs.aintr_mask, -1ull);
	// set LISN# to send and point to master context
	write_64(&p_afu->p_afu_map->global.regs.afu_ctrl,
		 ((__u64)((p_afu->ctx_hndl << 8) | SISL_MSI_ASYNC_ERROR)) <<
		 40);
	// clear all
	write_64(&p_afu->p_afu_map->global.regs.aintr_clear, -1ull);
	// unmask bits that are of interest
	// note: afu can send an interrupt after this step
	write_64(&p_afu->p_afu_map->global.regs.aintr_mask, SISL_ASTATUS_MASK);
	// clear again in case a bit came on after previous clear but before
	// unmask
	write_64(&p_afu->p_afu_map->global.regs.aintr_clear, -1ull);

	// now clear FC errors
	for (i = 0; i < NUM_FC_PORTS; i++) {
		write_64(&p_afu->p_afu_map->global.fc_regs[i][FC_ERROR/8],
			 (__u32)-1);
		write_64(&p_afu->p_afu_map->global.fc_regs[i][FC_ERRCAP/8], 0);
	}

	// sync interrupts for master's IOARRIN write
	// note that unlike asyncs, there can be no pending sync interrupts
	// at this time (this is a fresh context and master has not written
	// IOARRIN yet), so there is nothing to clear.
	//
	// set LISN#, it is always sent to the context that wrote IOARRIN
	write_64(&p_afu->p_host_map->ctx_ctrl, SISL_MSI_SYNC_ERROR);
	write_64(&p_afu->p_host_map->intr_mask, SISL_ISTATUS_MASK);
}


static irqreturn_t cflash_dummy_irq_handler(int irq, void *data)
{
	/* XXX - to be removed once we settle the 4th interrupt */
        cflash_info("in %s returning rc=%d\n", __func__, IRQ_HANDLED);
	return IRQ_HANDLED;
}

static irqreturn_t cflash_sync_err_irq(int irq, void *data)
{
	struct afu	*p_afu = (struct afu *)data;
	__u64		 reg;
	__u64		 reg_unmasked;

	reg = read_64(&p_afu->p_host_map->intr_status);
	reg_unmasked = (reg & SISL_ISTATUS_UNMASK);

	if (reg_unmasked == 0UL) {
		cflash_err("%llX: spurious interrupt, intr_status %016llX\n",
			   (u64)p_afu, reg);
		goto cflash_sync_err_irq_exit;
	}

	cflash_err("%llX: unexpected interrupt, intr_status %016llX\n",
		   (u64)p_afu, reg);

	write_64(&p_afu->p_host_map->intr_clear, reg_unmasked);

cflash_sync_err_irq_exit:
        cflash_info("in %s returning rc=%d\n", __func__, IRQ_HANDLED);
	return IRQ_HANDLED;
}

static irqreturn_t cflash_rrq_irq(int irq, void *data)
{
	struct afu	*p_afu = (struct afu *)data;
	struct afu_cmd	*p_cmd;
	unsigned long	 lock_flags = 0UL;

	/*
	 * XXX - might want to look at using locals for loop control
	 * as an optimizaion
	 */

	/* Process however many RRQ entries that are ready */
	while ((*p_afu->p_hrrq_curr & SISL_RESP_HANDLE_T_BIT) == p_afu->toggle)
	{
		struct scsi_cmnd *scp;

		p_cmd = (struct afu_cmd *)
			((*p_afu->p_hrrq_curr) & (~SISL_RESP_HANDLE_T_BIT));

		spin_lock_irqsave(&p_cmd->slock, lock_flags);
		p_cmd->sa.host_use_b[0] |= B_DONE;
		spin_unlock_irqrestore(&p_cmd->slock, lock_flags);

		/* already stopped if timer fired */
		timer_stop(&p_cmd->timer, FALSE); 

		/*
		hexdump ((void *)&p_cmd->rcb, sizeof(sisl_ioarcb_t), "rcb");
		hexdump ((void *)&p_cmd->sa, sizeof(sisl_ioasa_t), "sa");
		hexdump ((void *)p_cmd->rcb.data_ea, 64, "data");
		*/

		if (p_cmd->rcb.rsvd2) {
			scp =  (struct scsi_cmnd *)p_cmd->rcb.rsvd2;
			cflash_info("In %s calling scsi_set_resid, "
				    "scp=0x%llx len=%d\n",
				    __func__, p_cmd->rcb.rsvd2,
				    p_cmd->sa.resid);

			scsi_set_resid(scp, p_cmd->sa.resid);
			scp->scsi_done(scp);
			scsi_dma_unmap(scp);
		}

		/* Advance to next entry or wrap and flip the toggle bit */
		if (p_afu->p_hrrq_curr < p_afu->p_hrrq_end) {
			p_afu->p_hrrq_curr++;
		} else {
			p_afu->p_hrrq_curr = p_afu->p_hrrq_start;
			p_afu->toggle ^= SISL_RESP_HANDLE_T_BIT;
		}
	}

	/* XXX
        cflash_info("in %s returning rc=%d\n", __func__, IRQ_HANDLED);
	*/
	return IRQ_HANDLED;
}

static irqreturn_t cflash_async_err_irq(int irq, void *data)
{
	struct afu	*p_afu = (struct afu *)data;

	/*
	 * XXX - Matt to work on this next, need to create a thread
	 * as this type of interrupt can drive a link reset which
	 * will block.
	 */

        cflash_info("in %s returning rc=%d, afu = %p\n",
		    __func__, IRQ_HANDLED, p_afu);
	return IRQ_HANDLED;
}

/*
 * Start the afu context.  This is calling into the generic CXL driver code
 * (except for the contents of the WED).
 */
int cflash_start_context(cflash_t *p_cflash)
{
        int rc = 0;

        rc =  cxl_start_context(p_cflash->p_ctx,
				p_cflash->p_afu->work.work_element_descriptor,
				NULL);

        cflash_info("in %s returning rc=%d\n", __func__, rc);
        return rc;
}

/*
 * Stop the afu context.  This is calling into the generic CXL driver code
 */
void cflash_stop_context(cflash_t *p_cflash)
{
	cxl_stop_context(p_cflash->p_ctx);
        cflash_info("in %s returning \n", __func__);
}

static void send_cmd_timeout(struct afu_cmd *p_cmd)
{
	unsigned long lock_flags = 0;

	cflash_err("command timeout, opcode 0x%X\n", p_cmd->rcb.cdb[0]);

	spin_lock_irqsave(&p_cmd->slock, lock_flags);
	p_cmd->sa.host_use_b[0] |= (B_DONE | B_ERROR | B_TIMEOUT);
	spin_unlock_irqrestore(&p_cmd->slock, lock_flags);
}

#define WWPN_BUFFER_LENGTH 17

int cflash_read_vpd(cflash_t *p_cflash, __u64 wwpn[]) {

	char *buf  = NULL;
	int   rc = 0;
	int   bytes = 0;
	bool  l_rc;
	int l_kw_length;
	char localwwpn[SURELOCK_NUM_FC_PORTS][WWPN_BUFFER_LENGTH];

	cflash_info("in %s pci_dev %p\n", __func__, 
		    p_cflash->parent_dev);

	buf = kzalloc(KWDATA_SZ, GFP_KERNEL);
	if (!buf)
	{
		cflash_err("in %s could not allocate mem\n", __func__);
		rc = -ENOMEM;
		goto out;
	}
	bytes = pci_read_vpd(p_cflash->parent_dev, 0, KWDATA_SZ, buf);
	if (bytes <=0) {
		cflash_err("could not read VPD rc %d\n", rc);
		rc = -ENODEV;
		goto out;
	}
	hexdump ((void *)buf, KWDATA_SZ, "vpd");

        l_kw_length = 16; 
        l_rc = provFindVPDKw("V5", buf, KWDATA_SZ, (uint8_t*)&localwwpn[0],
			     &l_kw_length); 
	if(l_rc == false) { 
		cflash_err("Error: Unable to find Port name VPD for Port 1 "
			   "(VPD KW V5)") ; 
		rc = ENODEV; 
		goto out;
	}

	hexdump ((void *)localwwpn[0], 16, "wwpn0");
	/* NULL terminate before calling kstrtoul */
	localwwpn[0][16] = 0x0;

	rc = kstrtoul(localwwpn[0], 16, (unsigned long *)&wwpn[0]);
	if (rc)
		goto out;

        l_kw_length = 16; 
	l_rc = provFindVPDKw("V6", buf, KWDATA_SZ, (uint8_t*)&localwwpn[1],
			     &l_kw_length);
        if(l_rc == false) { 
		cflash_err("Error: Unable to find Port name VPD for Port 1 "
			   "(VPD KW V5)") ; 
		rc = ENODEV; 
		goto out;
	}

	hexdump ((void *)localwwpn[1], 16, "wwpn1");
	/* NULL terminate before calling kstrtoul */
	localwwpn[1][16] = 0x0;
	rc = kstrtoul(localwwpn[1], 16, (unsigned long *)&wwpn[1]);
	if (rc)
		goto out;

out:
	if (buf)
		kfree(buf);
        cflash_info("in %s returning rc=%d\n", __func__, rc);
        return rc;
}

int cflash_start_afu(cflash_t *p_cflash)
{
	afu_t *p_afu = p_cflash->p_afu;
	char version[16];
	__u64 wwpn[SURELOCK_NUM_FC_PORTS]; // wwpn of AFU ports

	int   i  = 0;
	int   rc = 0;
	__u64 reg;
	enum undo_level level = UNDO_NONE;

	rc = cflash_read_vpd(p_cflash, &wwpn[0]);
	if (rc) {
		cflash_err("in %s could not read vpd rc=%d\n", __func__, rc);
		goto out;
	}
	cflash_info("in %s wwpn0=0x%llx wwpn1=0x%llx\n", __func__, 
		    wwpn[0], wwpn[1]);

	for (i = 0; i < MAX_CONTEXT; i++) {
		p_afu->rht_info[i].rht_start = &p_afu->rht[i][0];
	}

	for (i = 0; i < NUM_CMDS; i++) {
		struct timer_list *p_timer = &p_afu->cmd[i].timer;

		init_timer(p_timer);
		p_timer->data = (unsigned long)&p_afu->cmd[i];
		p_timer->function = (void (*)(unsigned long))send_cmd_timeout;

		spin_lock_init(&p_afu->cmd[i].slock);
	}
	level= UNDO_TIMER;

	/* Map the entire MMIO space of the AFU. 
	 */
	p_afu->p_afu_map =  cxl_psa_map(p_cflash->p_ctx);
	if (!p_afu->p_afu_map)
		goto out;

	for (i = 0; i < MAX_CONTEXT; i++) {
		p_afu->ctx_info[i].p_ctrl_map =
			&p_afu->p_afu_map->ctrls[i].ctrl;
		// disrupt any clients that could be running
		// e. g. clients that survived a master restart
		write_64(&p_afu->ctx_info[i].p_ctrl_map->rht_start, 0);
		write_64(&p_afu->ctx_info[i].p_ctrl_map->rht_cnt_id, 0);
		write_64(&p_afu->ctx_info[i].p_ctrl_map->ctx_cap, 0);
	}
	level  = UNDO_AFU_MMAP;

	// copy frequently used fields into p_afu
	/* XXX, why cannot we get at the process element 
	*/
	p_afu->ctx_hndl =  (u16) (p_cflash->p_ctx->pe); 
	// ctx_hndl is 16 bits in CAIA
	p_afu->p_host_map = &p_afu->p_afu_map->hosts[p_afu->ctx_hndl].host;
	p_afu->p_ctrl_map = &p_afu->p_afu_map->ctrls[p_afu->ctx_hndl].ctrl;

	// initialize RRQ pointers
	p_afu->p_hrrq_start = &p_afu->rrq_entry[0];
	p_afu->p_hrrq_end = &p_afu->rrq_entry[NUM_RRQ_ENTRY - 1];
	p_afu->p_hrrq_curr = p_afu->p_hrrq_start;
	p_afu->toggle = 1;

	memset(&version[0], 0, sizeof(version));
	// don't byte reverse on reading afu_version, else the string form
	//     will be backwards
	reg = p_afu->p_afu_map->global.regs.afu_version;
	memcpy(&version[0], &reg, 8);
	cflash_dbg("afu version %s, ctx_hndl %d\n", version, p_afu->ctx_hndl);

	// initialize cmd fields that never change
	for (i = 0; i < NUM_CMDS; i++) {
		p_afu->cmd[i].rcb.ctx_id = p_afu->ctx_hndl;
		p_afu->cmd[i].rcb.msi = SISL_MSI_RRQ_UPDATED;
		p_afu->cmd[i].rcb.rrq = 0x0;
	}

	// set up RRQ in AFU for master issued cmds
	write_64(&p_afu->p_host_map->rrq_start, (__u64) p_afu->p_hrrq_start);
	write_64(&p_afu->p_host_map->rrq_end, (__u64) p_afu->p_hrrq_end);

	// AFU configuration
	reg = read_64(&p_afu->p_afu_map->global.regs.afu_config);
	reg |= 0x7F00;        // enable auto retry
	// leave others at default:
	// CTX_CAP write protected, mbox_r does not clear on read and
	// checker on if dual afu
	write_64(&p_afu->p_afu_map->global.regs.afu_config, reg);

	 // global port select: select either port
	 write_64(&p_afu->p_afu_map->global.regs.afu_port_sel, 0x3);

	 for (i = 0; i < NUM_FC_PORTS; i++) {
		// unmask all errors (but they are still masked at AFU)
		write_64(&p_afu->p_afu_map->global.fc_regs[i][FC_ERRMSK/8],
			 0);
		// clear CRC error cnt & set a threshold
		(void) read_64(&p_afu->p_afu_map->
			       global.fc_regs[i][FC_CNT_CRCERR/8]);
		write_64(&p_afu->p_afu_map->global.fc_regs[i]
			 [FC_CRC_THRESH/8], MC_CRC_THRESH);

		/* XXX: This whole section with WWPN and and LUN_IDs needs
		 * to be reworked.
		 */
		  // set WWPNs. If already programmed, wwpn[i] is 0
		if (wwpn[i] != 0 &&
			afu_set_wwpn(p_afu, i,
			&p_afu->p_afu_map->global.fc_regs[i][0], wwpn[i])) {
			cflash_dbg("failed to set WWPN on port %d\n", i);
			cflash_undo_start_afu(p_afu, level);
			return -1;
		 }

	 }

	 // set up master's own CTX_CAP to allow real mode, host translation
	 // tbls, afu cmds and non-read/write GSCSI cmds.
	 // First, unlock ctx_cap write by reading mbox
	 //
	 (void) read_64(&p_afu->p_ctrl_map->mbox_r); // unlock ctx_cap
	 asm volatile ( "eieio" : : );
	 write_64(&p_afu->p_ctrl_map->ctx_cap, 
		  SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE | 
		  SISL_CTX_CAP_AFU_CMD | SISL_CTX_CAP_GSCSI_CMD);
	  // init heartbeat
	  p_afu->hb = read_64(&p_afu->p_afu_map->global.regs.afu_hb);

out:
        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
}

int cflash_init_afu(cflash_t *p_cflash)
{
	int		    rc;
	afu_t		   *p_afu = p_cflash->p_afu;
	struct cxl_context *ctx;

	ctx = cxl_dev_context_init(p_cflash->p_dev);
	if (!ctx)
		return -ENOMEM;
	p_cflash->p_ctx = ctx;

	/* Set it up as a master with the CXL */
	cxl_set_master(ctx); 
	
	/* Allocate AFU generated interrupt handler */
	rc = cxl_allocate_afu_irqs(ctx, 4);
	if (rc) {
		dev_err(&p_cflash->p_dev->dev,
			"call to allocate_afu_irqs failed rc=%d!\n", rc);
		goto err1;
	}

	/* Register AFU interrupt 1 (SISL_MSI_SYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 1, cflash_sync_err_irq, p_afu,
			     "SISL_MSI_SYNC_ERROR");
	if (!rc) {
		dev_err(&p_cflash->p_dev->dev,
			"call to map IRQ 1 (SISL_MSI_SYNC_ERROR) failed!\n");
		goto err2;
	}
	/* Register AFU interrupt 2 (SISL_MSI_RRQ_UPDATED) */
	rc = cxl_map_afu_irq(ctx, 2, cflash_rrq_irq, p_afu,
			     "SISL_MSI_RRQ_UPDATED");
	if (!rc) {
		dev_err(&p_cflash->p_dev->dev,
			"call to map IRQ 2 (SISL_MSI_RRQ_UPDATED) failed!\n");
		goto err3;
	}
	/* Register AFU interrupt 3 (SISL_MSI_ASYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 3, cflash_async_err_irq, p_afu,
			     "SISL_MSI_ASYNC_ERROR");
	if (!rc) {
		dev_err(&p_cflash->p_dev->dev,
			"call to map IRQ 3 (SISL_MSI_ASYNC_ERROR) failed!\n");
		goto err4;
	}

	/*
	 * XXX - why did we put a 4th interrupt? Were we thinking this is
	 * for the SISL_MSI_PSL_XLATE? Wouldn't that be covered under the
	 * cxl_register_error_irq() ?
         */

	/* Register AFU interrupt 4 for errors. */
	rc = cxl_map_afu_irq(ctx, 4, cflash_dummy_irq_handler, p_afu,
			     "err3");
	if (!rc) {
		dev_err(&p_cflash->p_dev->dev, "call to map IRQ 4 failed!\n");
		goto err5;
	}

	/* Register for PSL errors. TODO: implement this */
	//cxl_register_error_irq(dev, flags??, callback function, private data);

	/* This performs the equivalent of the CXL_IOCTL_START_WORK.
	 * The CXL_IOCTL_GET_PROCESS_ELEMENT is implicit in the process
	 * element (pe) that is embedded in the context (ctx)
	 */
        cflash_start_context (p_cflash);

        rc = cflash_start_afu (p_cflash);
        if (rc) {
		dev_err(&p_cflash->p_dev->dev,
			"call to start_afu failed, rc=%d!\n", rc);
                goto err6;
	}

        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
err6:
	cflash_stop_context(p_cflash);
	cxl_unmap_afu_irq(ctx, 4, p_afu);
err5:
	cxl_unmap_afu_irq(ctx, 3, p_afu);
err4:
	cxl_unmap_afu_irq(ctx, 2, p_afu);
err3:
	cxl_unmap_afu_irq(ctx, 1, p_afu);
err2:
	cxl_free_afu_irqs(ctx);
err1:
	cxl_release_context(ctx);
	p_cflash->p_ctx = NULL;
        cflash_info("in %s returning rc=%d\n", __func__, rc);
	return rc;
}

void cflash_term_afu(cflash_t *p_cflash)
{
	int	 i, nbytes;
	afu_t	*p_afu = p_cflash->p_afu;

	cflash_stop_context(p_cflash);
        cflash_info("in %s before unmap 4 \n", __func__);
	cxl_unmap_afu_irq(p_cflash->p_ctx, 4, p_afu);
        cflash_info("in %s before unmap 3 \n", __func__);
	cxl_unmap_afu_irq(p_cflash->p_ctx, 3, p_afu);
        cflash_info("in %s before unmap 2 \n", __func__);
	cxl_unmap_afu_irq(p_cflash->p_ctx, 2, p_afu);
        cflash_info("in %s before unmap 1 \n", __func__);
	cxl_unmap_afu_irq(p_cflash->p_ctx, 1, p_afu);
        cflash_info("in %s before cxl_free_afu_irqs \n", __func__);
	cxl_free_afu_irqs(p_cflash->p_ctx);
        cflash_info("in %s before cxl_release_context \n", __func__);
	cxl_release_context(p_cflash->p_ctx);
	p_cflash->p_ctx = NULL;

	for (i = 0; i < CFLASH_MAX_LUNS; i++) {
		if (p_afu->p_blka[i]) {
			ba_terminate(&p_afu->p_blka[i]->ba_lun);
			kfree(p_afu->p_blka[i]);
			p_afu->p_blka[i] = NULL;
		}
	}

	nbytes = sizeof(struct afu) * CFLASH_NAFU;
        free_pages((unsigned long)p_cflash->p_afu, get_order(nbytes));
	p_cflash->p_afu = NULL;
}

void timer_start(struct timer_list *p_timer, unsigned long timeout_in_jiffies)
{
	p_timer->expires = (jiffies + timeout_in_jiffies);
	add_timer(p_timer);
}


void timer_stop(struct timer_list *p_timer, bool sync)
{
	if (unlikely(sync))
		del_timer_sync(p_timer);
	else
		del_timer(p_timer);
}

// do we need to retry AFU_CMDs (sync) on afu_rc = 0x30 ?
// can we not avoid that ?
// not retrying afu timeouts (B_TIMEOUT)
// returns 1 if the cmd should be retried, 0 otherwise
// sets B_ERROR flag based on IOASA
int check_status(sisl_ioasa_t *p_ioasa)
{
    if (p_ioasa->ioasc == 0) {
        return 0;
    }

    p_ioasa->host_use_b[0] |= B_ERROR;

    if (!(p_ioasa->host_use_b[1]++ < MC_RETRY_CNT)) {
        return 0;
    }

    switch (p_ioasa->rc.afu_rc)
    {
    case SISL_AFU_RC_NO_CHANNELS:
    case SISL_AFU_RC_OUT_OF_DATA_BUFS:
        msleep(1); // 1 msec
        return 1;

    case 0:
        // no afu_rc, but either scsi_rc and/or fc_rc is set
        // retry all scsi_rc and fc_rc after a small delay
        msleep(1); // 1 msec
        return 1;
    }

    return 0;
}

void cflash_send_cmd(afu_t *p_afu, struct afu_cmd *p_cmd)
{
	int nretry = 0;

        cflash_info("in %s p_afu %p p_cmd %p\n", __func__, p_afu, p_cmd);

	if (p_afu->room == 0) {
		asm volatile ( "eieio" : : ); /* let IOARRIN writes complete */
		do {
			p_afu->room = read_64(&p_afu->p_host_map->cmd_room);
			udelay(nretry);
		} while ((p_afu->room == 0) && (nretry++ < MC_ROOM_RETRY_CNT));
	}

	p_cmd->sa.host_use_b[0] = 0; // 0 means active
	p_cmd->sa.ioasc = 0;

	/* make memory updates visible to AFU before MMIO */
	asm volatile ( "lwsync" : : );

	/*
	 * XXX - find out why this code originally (and still does)
	 * have a doubler (*2) for the timeout value
	 */
#if 0
	timer_start(&p_cmd->timer, (p_cmd->rcb.timeout * 2 * HZ));
#endif

	/* Write IOARRIN */
	if (p_afu->room)
		write_64(&p_afu->p_host_map->ioarrin, (__u64)&p_cmd->rcb);
	else
		cflash_err("no cmd_room to send 0x%X\n", p_cmd->rcb.cdb[0]);

	cflash_info("In %s p_cmd=%p len=%d ea=%p\n", 
		    __func__, p_cmd, p_cmd->rcb.data_len, 
		    (void *)p_cmd->rcb.data_ea); 

	/* Let timer fire to complete the response... */
}

void cflash_wait_resp(afu_t *p_afu, struct afu_cmd *p_cmd)
{
	unsigned long lock_flags = 0;

	spin_lock_irqsave(&p_cmd->slock, lock_flags);
	while (!(p_cmd->sa.host_use_b[0] & B_DONE)) {

		/*
		 * XXX - how do we want to handle this...
		 * need to study how send_cmd/wait_resp
		 * is used in interrupt context.
		 */

		spin_unlock_irqrestore(&p_cmd->slock, lock_flags);
		udelay(10);
		spin_lock_irqsave(&p_cmd->slock, lock_flags);
	}
	spin_unlock_irqrestore(&p_cmd->slock, lock_flags);

	timer_stop(&p_cmd->timer, FALSE);  /* already stopped if timer fired */

	if (p_cmd->sa.ioasc != 0)
		cflash_err("CMD 0x%x failed, IOASC: flags 0x%x, afu_rc 0x%x, "
			   "scsi_rc 0x%x, fc_rc 0x%x\n",
			p_cmd->rcb.cdb[0],
			p_cmd->sa.rc.flags,
			p_cmd->sa.rc.afu_rc,
			p_cmd->sa.rc.scsi_rc,
			p_cmd->sa.rc.fc_rc);
}

/*
 * afu_sync can be called from interrupt thread and the main processing
 * thread. Caller is responsible for any serialization.
 * Also, it can be called even before/during discovery, so we must use
 * a dedicated cmd not used by discovery.
 *
 * AFU takes only 1 sync cmd at a time.
 */
int afu_sync(afu_t	*p_afu,
	    ctx_hndl_t	 ctx_hndl_u,
	    res_hndl_t	 res_hndl_u,
	    __u8	 mode)
{
	__u16 *p_u16;
	__u32 *p_u32;
	struct afu_cmd *p_cmd = &p_afu->cmd[AFU_SYNC_INDEX];
	int rc = 0;

        cflash_info("in %s p_afu %p p_cmd %p %d\n", 
		    __func__, p_afu, p_cmd, ctx_hndl_u);

	memset(&p_cmd->rcb.cdb[0], 0, sizeof(p_cmd->rcb.cdb));

	p_cmd->rcb.req_flags = SISL_REQ_FLAGS_AFU_CMD;
	p_cmd->rcb.port_sel  = 0x0; /* NA */
	p_cmd->rcb.lun_id    = 0x0; /* NA */
	p_cmd->rcb.data_len  = 0x0;
	p_cmd->rcb.data_ea   = 0x0;
	p_cmd->rcb.timeout   = MC_AFU_SYNC_TIMEOUT;

	p_cmd->rcb.cdb[0] = 0xC0; /* AFU Sync */
	p_cmd->rcb.cdb[1] = mode;
	p_u16 = (__u16*)&p_cmd->rcb.cdb[2];
	write_16(p_u16, ctx_hndl_u); /* context to sync up */
	p_u32 = (__u32*)&p_cmd->rcb.cdb[4];
	write_32(p_u32, res_hndl_u); /* res_hndl to sync up */

	cflash_send_cmd(p_afu, p_cmd);
	cflash_wait_resp(p_afu, p_cmd);

	if ((p_cmd->sa.ioasc != 0) ||
	    (p_cmd->sa.host_use_b[0] & B_ERROR)) {
		rc = -1;
		/* B_ERROR is set on timeout */
	}

        cflash_info("in %s returning rc %d", __func__, rc);
	return rc;
}

/*
 * NAME:	cflash_vlun_resize()
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
 *		p_act_new_size	- pointer to actual new size in chunks
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 *		Setting new_size=0 will clear LXT_START and LXT_CNT fields
 *		in the RHT entry.
 */
int cflash_vlun_resize(struct scsi_device *sdev, void __user *arg)
{
	cflash_t	*p_cflash = (cflash_t *)sdev->host->hostdata;
	lun_info_t	*p_lun_info = sdev->hostdata;
	afu_t		*p_afu = p_cflash->p_afu;

	struct dk_capi_resize *parg  = (struct dk_capi_resize *)arg;
	__u64         p_act_new_size = 0;
	res_hndl_t    res_hndl       = parg->rsrc_handle;
	__u64         new_size;
	__u64         nsectors;

	ctx_info_t *p_ctx_info;
	rht_info_t *p_rht_info;
	sisl_rht_entry_t *p_rht_entry;

	int rc = 0,
	    lun_index = p_lun_info - p_afu->lun_info;


	/* req_size is always assumed to be in 4k blocks. So we have to convert	
	 * it from 4k to chunk size
	 */
	nsectors = (parg->req_size * DK_CAPI_BLOCK) / (p_lun_info->li.blk_len);
	new_size = (nsectors + MC_CHUNK_SIZE - 1)/MC_CHUNK_SIZE;

	cflash_info("%s, context=0x%llx res_hndl=0x%llx, req_size=0x%llx,"
		    "new_size=%llx\n",
		    __func__, parg->context_id,
		    parg->rsrc_handle,
		    parg->req_size, 
		    new_size);

	if (parg->context_id < MAX_CONTEXT) {

		p_ctx_info = &p_afu->ctx_info[parg->context_id];
		p_rht_info = p_ctx_info->p_rht_info;
	} else {
		cflash_err("in %s context id too large 0x%llx\n",  __func__,
			   parg->context_id);
		rc = -EINVAL;
		goto out;
	}

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];

		if (p_rht_entry->nmask == 0) { /* not open */
			cflash_err("in %s not open rhti %p rhte %p\n",  
				   __func__, p_rht_info, p_rht_entry);
			rc = -EINVAL;
			goto out;
		}

		if (new_size > p_rht_entry->lxt_cnt) {
			grow_lxt(p_afu,
				 lun_index,
				 parg->context_id,
				 res_hndl,
				 p_rht_entry,
				 new_size - p_rht_entry->lxt_cnt,
				 &p_act_new_size);
		} else if (new_size < p_rht_entry->lxt_cnt) {
			shrink_lxt(p_afu,
				   lun_index,
				   parg->context_id,
				   res_hndl,
				   p_rht_entry,
				   p_rht_entry->lxt_cnt - new_size,
				   &p_act_new_size);
		} else {
			p_act_new_size = new_size;
		}
	} else {
		cflash_err("in %s res_hndl %d invalid\n",  __func__, 
			   res_hndl);
		rc = -EINVAL;
	}
	parg->return_flags = 0;
	parg->last_lba = (p_act_new_size *  MC_CHUNK_SIZE *
		p_lun_info->li.blk_len)/ DK_CAPI_BLOCK;

out:
        cflash_info("in %s resized to %lld returning rc=%d\n", __func__, 
		    parg->last_lba, rc);
	return rc;
}

int grow_lxt(afu_t		*p_afu,
	     int		 lun_index,
	     ctx_hndl_t		 ctx_hndl_u,
	     res_hndl_t		 res_hndl_u,
	     sisl_rht_entry_t	*p_rht_entry,
	     __u64		 delta,
	     __u64		*p_act_new_size)
{
	sisl_lxt_entry_t *p_lxt = NULL, *p_lxt_old = NULL;
	blka_t *p_blka = p_afu->p_blka[lun_index];
	unsigned int av_size;
	unsigned int ngrps, ngrps_old;
	aun_t aun; /* chunk# allocated by block allocator */
	int i;

	/*
	 * Check what is available in the block allocator before re-allocating
	 * LXT array. This is done up front under the mutex which must not be
	 * released until after allocation is complete. 
	 */
	mutex_lock(&p_blka->mutex);
	av_size = ba_space(&p_blka->ba_lun);
	if (av_size < delta)
		delta = av_size;

	p_lxt_old = p_rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt + delta);

	if (ngrps != ngrps_old) {
		/* realloate to fit new size */
		p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (!p_lxt) {
			mutex_unlock(&p_blka->mutex);
			return -ENOMEM;
		}

		/* copy over all old entries */
		memcpy(p_lxt, p_lxt_old, (sizeof(*p_lxt) *
					  p_rht_entry->lxt_cnt));
	} else {
		p_lxt = p_lxt_old;
	}

	/* nothing can fail from now on */
	*p_act_new_size = p_rht_entry->lxt_cnt + delta;

	/* add new entries to the end */
	for (i = p_rht_entry->lxt_cnt; i < *p_act_new_size; i++) {
		/*
		 * Due to the earlier check of available space, ba_alloc
		 * cannot fail here. If it did due to internal error,
		 * leave a rlba_base of -1u which will likely be a
		 * invalid LUN (too large).
		 */
		aun = ba_alloc(&p_blka->ba_lun);
		if ((aun == (aun_t)-1) || (aun >= p_blka->nchunk)) {
			cflash_err("ba_alloc error: allocated chunk# %lX, "
				   "max %llX", aun, 
				   p_blka->nchunk - 1);
		}

		/* lun_indx = 0, select both ports, use r/w perms from RHT */
		p_lxt[i].rlba_base = ((aun << MC_CHUNK_SHIFT) | 0x33);
	}

	mutex_unlock(&p_blka->mutex);

	asm volatile ( "lwsync" : : );  /* make lxt updates visible */
	/*
	 * XXX - Do we really need 3 separate syncs here? The first one
	 * for the lxt visibility updates make sense, as does having one
	 * after we update the p_rht_entry fields. But having one after
	 * updating lxt_start and then again after updating lxt_cnt seems
	 * overkill unless there is a dependency (and if there is one, why
	 * isn't it noted here in a BIG comment).
	 */

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_start = p_lxt; /* even if p_lxt didn't change */
	asm volatile ( "lwsync" : : );

	p_rht_entry->lxt_cnt = *p_act_new_size;
	asm volatile ( "lwsync" : : );

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* free old lxt if reallocated */
	if (p_lxt != p_lxt_old)
		kfree(p_lxt_old);

	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list */
        cflash_info("in %s returning\n", __func__);
	return 0;
}

int shrink_lxt(afu_t		*p_afu,
	       int		 lun_index,
	       ctx_hndl_t	 ctx_hndl_u,
	       res_hndl_t	 res_hndl_u,
	       sisl_rht_entry_t *p_rht_entry,
	       __u64		 delta,
	       __u64		*p_act_new_size)
{
	sisl_lxt_entry_t *p_lxt, *p_lxt_old;
	blka_t *p_blka = p_afu->p_blka[lun_index];
	unsigned int ngrps, ngrps_old;
	aun_t aun; /* chunk# allocated by block allocator */
	int i;

	p_lxt_old = p_rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt - delta);

	if (ngrps != ngrps_old) {
		/* realloate to fit new size unless new size is 0 */
		if (ngrps) {
			p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE *
					 ngrps), GFP_KERNEL);
			if (!p_lxt)
				return -ENOMEM;

			/* copy over old entries that will remain */
			memcpy(p_lxt, p_lxt_old, (sizeof(*p_lxt) *
						  (p_rht_entry->lxt_cnt -
						   delta)));
		} else {
			p_lxt = NULL;
		}
	} else {
		p_lxt = p_lxt_old;
	}

	/* nothing can fail from now on */
	*p_act_new_size = p_rht_entry->lxt_cnt - delta;

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_cnt = *p_act_new_size;
	asm volatile ( "lwsync" : : ); /* also makes lxt updates visible */

	p_rht_entry->lxt_start = p_lxt; /* even if p_lxt didn't change */
	asm volatile ( "lwsync" : : );

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_HW_SYNC);

	/* free LBAs allocated to freed chunks */
	mutex_lock(&p_blka->mutex);
	for (i = delta - 1; i >= 0; i--) {
		aun = (p_lxt_old[*p_act_new_size + i].rlba_base >> 
		       MC_CHUNK_SHIFT);
		ba_free(&p_blka->ba_lun, aun);
	}
	mutex_unlock(&p_blka->mutex);

	/* free old lxt if reallocated */
	if (p_lxt != p_lxt_old)
		kfree(p_lxt_old);
	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list!!! */
        cflash_info("in %s returning\n", __func__);
	return 0;
}

/*
 * NAME:	clone_lxt()
 *
 * FUNCTION:	clone a LXT table
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		ctx_hndl_u	- context that owns the destination LXT
 *		res_hndl_u	- res_hndl of the destination LXT
 *		p_rht_entry	- destination RHT to clone into
 *		p_rht_entry_src	- source RHT to clone from
 *
 * OUTPUTS:
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 */
int clone_lxt(afu_t		*p_afu,
	      int		 lun_index,
	      ctx_hndl_t	 ctx_hndl_u,
	      res_hndl_t	 res_hndl_u,
	      sisl_rht_entry_t	*p_rht_entry,
	      sisl_rht_entry_t	*p_rht_entry_src)
{
	sisl_lxt_entry_t *p_lxt;
	blka_t *p_blka = p_afu->p_blka[lun_index];
	unsigned int ngrps;
	aun_t aun; /* chunk# allocated by block allocator */
	int i, j;

	ngrps = LXT_NUM_GROUPS(p_rht_entry_src->lxt_cnt);

	if (ngrps) {
		/* alloate new LXTs for clone */
		p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (!p_lxt)
			return -ENOMEM;

		/* copy over */
		memcpy(p_lxt, p_rht_entry_src->lxt_start,
		       (sizeof(*p_lxt) * p_rht_entry_src->lxt_cnt));

		/* clone the LBAs in block allocator via ref_cnt */
		mutex_lock(&p_blka->mutex);
		for (i = 0; i < p_rht_entry_src->lxt_cnt; i++) {
			aun = (p_lxt[i].rlba_base >> MC_CHUNK_SHIFT);
			if (ba_clone(&p_blka->ba_lun, aun) == -1) {
				/* free the clones already made */
				for (j = 0; j < i; j++) {
					aun = (p_lxt[j].rlba_base >>
					       MC_CHUNK_SHIFT);
					ba_free(&p_blka->ba_lun, aun);
				}

				mutex_unlock(&p_blka->mutex);
				kfree(p_lxt);
				return -EIO;
			}
		}
		mutex_unlock(&p_blka->mutex);
	} else {
		p_lxt = NULL;
	}

	asm volatile ( "lwsync" : : );  /* make lxt updates visible */

	/*
	 * XXX - Do we really need 3 separate syncs here? The first one
	 * for the lxt visibility updates make sense, as does having one
	 * after we update the p_rht_entry fields. But having one after
	 * updating lxt_start and then again after updating lxt_cnt seems
	 * overkill unless there is a dependency (and if there is one, why
	 * isn't it noted here in a BIG comment).
	 */

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_start = p_lxt; /* even if p_lxt is NULL */
	asm volatile ( "lwsync" : : );

	p_rht_entry->lxt_cnt = p_rht_entry_src->lxt_cnt;
	asm volatile ( "lwsync" : : );

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list */
        cflash_info("in %s returning\n", __func__);
	return 0;
}

/*
 * NAME:        do_mc_xlate_lba
 *
 * FUNCTION:    Query the physical LBA mapped to a virtual LBA
 *
 * INPUTS:
 *              p_afu       - Pointer to afu struct
 *              p_conn_info - Pointer to connection the request came in
 *              res_hndl    - resource handle to query on
 *              v_lba       - virtual LBA on res_hndl
 *
 * OUTPUTS:
 *              p_p_lba     - pointer to output physical LBA
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 */
int do_mc_xlate_lba(afu_t        *p_afu,
		    conn_info_t* p_conn_info,
		    res_hndl_t   res_hndl,
		    __u64        v_lba,
		    __u64        *p_p_lba)
{
	ctx_info_t *p_ctx_info = p_conn_info->p_ctx_info;
	rht_info_t *p_rht_info = p_ctx_info->p_rht_info;
	sisl_rht_entry_t *p_rht_entry;
	__u64 chunk_id, chunk_off, rlba_base;

	cflash_info("%s, client_pid=%d client_fd=%d ctx_hdl=%d\n",
		    __func__, p_conn_info->client_pid,
		    p_conn_info->client_fd,
		    p_conn_info->ctx_hndl);

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];
		if (p_rht_entry->nmask == 0) {
			/* not open */
			return -EINVAL;
		}

		chunk_id = (v_lba >> MC_CHUNK_SHIFT); chunk_off
			= (v_lba & MC_CHUNK_OFF_MASK);

		if (chunk_id < p_rht_entry->lxt_cnt) {
			rlba_base =
				(p_rht_entry->lxt_start[chunk_id].rlba_base &
				 (~MC_CHUNK_OFF_MASK));
			*p_p_lba = (rlba_base | chunk_off);
		} else {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

        cflash_info("in %s returning\n", __func__);
	return 0;
}

/*
 * NAME:        do_mc_clone
 *
 * FUNCTION:    clone by making a snapshot copy of another context
 *
 * INPUTS:
 *              p_afu        - Pointer to afu struct
 *              p_conn_info  - Pointer to connection the request came in
 *                             This is also the target of the clone.
 *              ctx_hndl_src - AFU context to clone from
 *              challenge    - used to validate access to ctx_hndl_src
 *              flags        - permissions for the cloned copy
 *
 * OUTPUTS:
 *              None
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 * clone effectively does what open and size do. The destination
 * context must be in pristine state with no resource handles open.
 *
 */
// todo dest ctx must be unduped
int do_mc_clone(afu_t        *p_afu,
		conn_info_t  *p_conn_info,
		ctx_hndl_t   ctx_hndl_src,
		__u64        challenge,
		__u64        flags)
{
	ctx_info_t *p_ctx_info = p_conn_info->p_ctx_info;
	rht_info_t *p_rht_info = p_ctx_info->p_rht_info;

	ctx_info_t *p_ctx_info_src;
	rht_info_t *p_rht_info_src;
	__u64 reg;
	int i, j;
	int rc,
	    lun_index = 0; /* XXX - fix when routine is transitioned */

	cflash_info("%s, client_pid=%d client_fd=%d ctx_hdl=%d\n",
		    __func__, p_conn_info->client_pid,
		    p_conn_info->client_fd,
		    p_conn_info->ctx_hndl);

	/* verify there is no open resource handle in the target context 
	 * of the clone.  
	 */ 
	
	for (i = 0; i <  MAX_RHT_PER_CONTEXT; i++) { 
		if (p_rht_info->rht_start[i].nmask != 0) { 
			return EINVAL; 
		} 
	} 
	
	/* do not clone yourself */ 
	if (p_conn_info->ctx_hndl == ctx_hndl_src) { 
		return EINVAL; 
	} 
	
	if (ctx_hndl_src < MAX_CONTEXT) { 
		p_ctx_info_src = &p_afu->ctx_info[ctx_hndl_src]; 
		p_rht_info_src = &p_afu->rht_info[ctx_hndl_src]; 
	} 
	else { 
		return EINVAL; 
	} 
	
	reg = read_64(&p_ctx_info_src->p_ctrl_map->mbox_r); 
	
	if (reg == 0 || /* zeroed mbox is a locked mbox */ 
	    challenge != reg) { 
		return EACCES; /* return Permission denied */ 
	} 
	
	/* this loop is equivalent to do_mc_open & cflash_vlun_resize 
	 * Not checking if the source context has anything open or whether 
	 * it is even registered.  
	 */

	for (i = 0; i <  MAX_RHT_PER_CONTEXT; i++) {
		p_rht_info->rht_start[i].nmask =
			p_rht_info_src->rht_start[i].nmask;
		p_rht_info->rht_start[i].fp =
			SISL_RHT_FP_CLONE(p_rht_info_src->rht_start[i].fp,
					  flags & 0x3);

		rc = clone_lxt(p_afu, lun_index, p_conn_info->ctx_hndl, i,
			       &p_rht_info->rht_start[i],
			       &p_rht_info_src->rht_start[i]);

		if (rc != 0) {
			for (j = 0; j < i; j++) {
				do_mc_close(p_afu, p_conn_info, j);
			}

			p_rht_info->rht_start[i].nmask = 0;
			p_rht_info->rht_start[i].fp = 0;
			return rc;
		}
	}

        cflash_info("in %s returning\n", __func__);
	return 0;
}

/*
 * NAME:	do_mc_dup()
 *
 * FUNCTION:	dup 2 contexts by linking their RHTs
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		p_conn_info	- Pointer to connection the request came in
 *				  This is the context to dup to (target)
 *		ctx_hndl_cand	- This is the context to dup from source)
 *		challenge	- used to validate access to ctx_hndl_cand
 *
 * OUTPUTS:
 *		None
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 */
/* XXX - what is the significance of this comment? */
// dest ctx must be unduped and with no open res_hndls
int do_mc_dup(afu_t		*p_afu,
	      conn_info_t	*p_conn_info,
	      ctx_hndl_t	 ctx_hndl_cand,
	      __u64		 challenge)
{
	ctx_info_t *p_ctx_info = p_conn_info->p_ctx_info;
	rht_info_t *p_rht_info = p_ctx_info->p_rht_info;

	ctx_info_t *p_ctx_info_cand;
	__u64 reg;
	int i;

	cflash_info("%s, client_pid=%d client_fd=%d ctx_hdl=%d\n",
		__func__, p_conn_info->client_pid,
		p_conn_info->client_fd,
		p_conn_info->ctx_hndl);

	/* verify there is no open resource handle in the target context of the clone */
	for (i = 0; i <  MAX_RHT_PER_CONTEXT; i++)
		if (p_rht_info->rht_start[i].nmask != 0)
			return -EINVAL;

	/* do not dup yourself */
	if (p_conn_info->ctx_hndl == ctx_hndl_cand)
		return -EINVAL;

	if (ctx_hndl_cand < MAX_CONTEXT)
		p_ctx_info_cand = &p_afu->ctx_info[ctx_hndl_cand];
	else
		return -EINVAL;

	reg = read_64(&p_ctx_info_cand->p_ctrl_map->mbox_r);

	/* fyi, zeroed mbox is a locked mbox */
	if ((reg == 0) || (challenge != reg))
		return -EACCES; /* return Permission denied */

	/* XXX - what does this mean? */
        cflash_info("in %s returning\n", __func__);
	return -EIO; // todo later!!!
}

/*
 * NAME:	do_mc_stat()
 *
 * FUNCTION:	Query the current information on a resource handle
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		p_conn_info	- Pointer to connection the request came in
 *		res_hndl	- resource handle to query
 *
 * OUTPUTS:
 *		p_mc_stat	- pointer to output stat information
 *
 * RETURNS:
 *		0		- Success
 *		errno		- Failure
 *
 */
int do_mc_stat(afu_t		*p_afu,
	       conn_info_t	*p_conn_info,
	       res_hndl_t	 res_hndl,
	       mc_stat_t	*p_mc_stat)
{
	ctx_info_t *p_ctx_info = p_conn_info->p_ctx_info;
	rht_info_t *p_rht_info = p_ctx_info->p_rht_info;
	sisl_rht_entry_t *p_rht_entry;
	int lun_index = 0;
	blka_t *p_blka = p_afu->p_blka[lun_index]; /* TODO - properly derive
						      lun_index */

	cflash_info("%s, client_pid=%d client_fd=%d ctx_hdl=%d\n",
		__func__, p_conn_info->client_pid,
		p_conn_info->client_fd,
		p_conn_info->ctx_hndl);

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];

		/* not open */
		if (p_rht_entry->nmask == 0)
			return -EINVAL;

		p_mc_stat->blk_len = p_blka->ba_lun.lba_size;
		p_mc_stat->nmask = p_rht_entry->nmask;
		p_mc_stat->size = p_rht_entry->lxt_cnt;
		p_mc_stat->flags = SISL_RHT_PERM(p_rht_entry->fp);
	} else {
		return -EINVAL;
	}

        cflash_info("in %s returning\n", __func__);
	return 0;
}

int read_cap16(afu_t *p_afu, lun_info_t *p_lun_info, __u32 port_sel) { 

	__u32 *p_u32; 
	__u64 *p_u64; 

	struct afu_cmd *p_cmd = &p_afu->cmd[AFU_INIT_INDEX]; 
	
	memset(&p_afu->buf[0], 0, sizeof(p_afu->buf)); 
	memset(&p_cmd->rcb.cdb[0], 0, sizeof(p_cmd->rcb.cdb)); 
	
	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID | 
				SISL_REQ_FLAGS_SUP_UNDERRUN | 
				SISL_REQ_FLAGS_HOST_READ); 
	
	p_cmd->rcb.port_sel = port_sel; 
	p_cmd->rcb.lun_id = p_lun_info->lun_id; 
	p_cmd->rcb.data_len = sizeof(p_afu->buf); 
	p_cmd->rcb.data_ea = (__u64) &p_afu->buf[0]; 
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT; 
	
	p_cmd->rcb.cdb[0] = 0x9E; /* read cap(16) */ 
	p_cmd->rcb.cdb[1] = 0x10; /* service action */ 
	p_u32 = (__u32*)&p_cmd->rcb.cdb[10]; 
	write_32(p_u32, sizeof(p_afu->buf)); /* allocation length */ 
	p_cmd->sa.host_use_b[1] = 0; /* reset retry cnt */ 
	
	cflash_info("in %s: sending cmd(0x%x) with RCB EA=%p data EA=0x%llx\n", 
		    __func__, p_cmd->rcb.cdb[0], &p_cmd->rcb, 
		    p_cmd->rcb.data_ea); 
	
	do { 
		cflash_send_cmd(p_afu, p_cmd); 
		cflash_wait_resp(p_afu, p_cmd); 
	} while (check_status(&p_cmd->sa)); 
	
	if (p_cmd->sa.host_use_b[0] & B_ERROR) { 
		return -1; 
	} 
	
	// read cap success 
	p_u64 = (__u64*)&p_afu->buf[0]; 
	p_lun_info->li.max_lba = read_64(p_u64); 
	
	p_u32 = (__u32*)&p_afu->buf[8]; 
	p_lun_info->li.blk_len = read_32(p_u32); 

        cflash_info("in %s maxlba=%lld blklen=%d pcmd %p\n", __func__,
		    p_lun_info->li.max_lba, p_lun_info->li.blk_len, p_cmd);
	return 0;
}

// lun_id must be set in p_lun_info
int find_lun(cflash_t *p_cflash, __u32 port_sel)
{
	__u32 *p_u32;
	__u32 len;
	__u64 *p_u64;
	afu_t      *p_afu     = p_cflash->p_afu;
	struct afu_cmd *p_cmd = &p_afu->cmd[AFU_INIT_INDEX];
	__u64 lunidarray[CFLASH_MAX_NUM_LUNS_PER_TARGET];
	int i = 0;
	int j = 0;
	int rc = 0;

	memset(&p_afu->buf[0], 0, sizeof(p_afu->buf));
	memset(&p_cmd->rcb.cdb[0], 0, sizeof(p_cmd->rcb.cdb));

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = 0x0; /* use lun_id=0 w/report luns */
	p_cmd->rcb.data_len = sizeof(p_afu->buf);
	p_cmd->rcb.data_ea = (__u64) &p_afu->buf[0];
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	p_cmd->rcb.cdb[0] = 0xA0; /* report luns */
	p_u32 = (__u32*)&p_cmd->rcb.cdb[6];
	write_32(p_u32, sizeof(p_afu->buf)); /* allocaiton length */
	p_cmd->sa.host_use_b[1] = 0; /* reset retry cnt */

	cflash_info("%s: sending cmd(0x%x) with RCB EA=%p data EA=0x%p\n",
		    __func__,
		    p_cmd->rcb.cdb[0],
		    &p_cmd->rcb,
		    (void *)p_cmd->rcb.data_ea);

	do {
		cflash_send_cmd(p_afu, p_cmd);
		cflash_wait_resp(p_afu, p_cmd);
	} while (check_status(&p_cmd->sa));

	if (p_cmd->sa.host_use_b[0] & B_ERROR) {
		return -1;
	}

	// report luns success 
	len = read_32((__u32*)&p_afu->buf[0]);
	hexdump ((void *)p_afu->buf, len+8, "report luns data");

	p_u64 = (__u64*)&p_afu->buf[8]; /* start of lun list */

	while (len) {
		lunidarray[i] =  read_64(p_u64);
		len -= 8;
		p_u64++;
		i++;
	}
	cflash_info("%s: found %d luns\n", __func__, i);
	for (j=0; j<i; j++)
	{
		cflash_info("%s: adding i=%d lun_id %llx last_index %d\n",
			    __func__, j, lunidarray[j], 
			    p_cflash->last_lun_index);

		scsi_add_device(p_cflash->host, CFLASH_BUS,
				port_sel, lunidarray[j]);
		// program FC_PORT LUN Tbl
		write_64(&p_afu->p_afu_map->global.fc_port[port_sel-1]
			 [p_cflash->last_lun_index], lunidarray[j]);

		 // record the lun_id to be used in discovery later
		 p_afu->lun_info[p_cflash->last_lun_index].lun_id = 
			 lunidarray[j];

		 read_cap16(p_afu, &p_afu->lun_info[p_cflash->last_lun_index], 
			    port_sel); 
		 
		 rc = cflash_init_ba(p_cflash, p_cflash->last_lun_index); 
		 if (rc) { 
			 cflash_err("call to cflash_init_ba failed rc=%d!\n", 
				    rc); 
			 goto out; 
		 }
		 p_cflash->last_lun_index++;
	}

out:
        cflash_info("in %s returning rc %d pcmd%p\n", __func__, rc,
		    p_cmd);
	return rc;
}


void cflash_send_scsi(afu_t *p_afu, struct scsi_cmnd *scp)
{
	struct afu_cmd *p_cmd = &p_afu->cmd[AFU_INIT_INDEX];

	/* XXX: Decide how to select port */
	__u64 port_sel = 0x1;
	int nseg, i, ncount;
        struct scatterlist *sg;
	short lflag = 0;

	memset(&p_afu->buf[0], 0, sizeof(p_afu->buf));
	memset(&p_cmd->rcb.cdb[0], 0, sizeof(p_cmd->rcb.cdb));

	p_cmd->rcb.ctx_id    = p_afu->ctx_hndl;

	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = scp->device->lun;

	if (scp->sc_data_direction == DMA_TO_DEVICE)
		lflag = SISL_REQ_FLAGS_HOST_WRITE;
	else
		lflag = SISL_REQ_FLAGS_HOST_READ;

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				lflag);
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	/* Stash the scp in the reserved field, for reuse during interrupt */
	p_cmd->rcb.rsvd2 = (__u64)scp;

	p_cmd->sa.host_use_b[1] = 0; /* reset retry cnt */

	nseg = scsi_dma_map(scp);
	ncount = scsi_sg_count(scp);
        scsi_for_each_sg(scp, sg, ncount, i) {
                p_cmd->rcb.data_len = (sg_dma_len(sg) & SISLITE_LEN_MASK);
                p_cmd->rcb.data_ea = (sg_phys(sg));
        }

	/* Copy the CDB from the scsi_cmnd passed in */
	memcpy(p_cmd->rcb.cdb, scp->cmnd, sizeof(p_cmd->rcb.cdb));

	/* Send the command */
	cflash_send_cmd(p_afu, p_cmd);
}
