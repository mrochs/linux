
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
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <misc/cxl.h>
#include <uapi/misc/cxl.h>
#include <linux/unistd.h>
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
#include "afu_fc.h"
#include "mserv.h"


int cflash_disk_attach(struct scsi_device *sdev, void __user *arg)
{
	int rc = 0;
	return rc;
}

/*
 * NAME:        cflash_mc_register
 *
 * FUNCTION:    Unregister a user AFU context with master.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to optional arg structure
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
int cflash_mc_register(struct scsi_device *sdev, void __user *arg)
{
	/* XXX: How is challenge, conn_info initialized */
	__u64            challenge = 0;
        conn_info_t  *p_conn_info = NULL;
	__u64 reg;
	ctx_info_t *p_ctx_info;
	cflash_t *p_cflash = (cflash_t *)sdev->host->hostdata;
	afu_t *p_afu = &p_cflash->p_afu_a->afu;
	int i;


	if (p_conn_info->ctx_hndl < MAX_CONTEXT) {
		p_ctx_info = &p_afu->ctx_info[p_conn_info->ctx_hndl];

		/* This code reads the mbox w/o knowing if the requester is 
		 * the true owner of the context it wants to register. The 
		 * read has no side effect and does not affect the true 
		 * owner if this is a fraudulent registration attempt.
	 	 */
		reg = read_64(&p_ctx_info->p_ctrl_map->mbox_r);

		if (reg == 0 || /* zeroed mbox is a locked mbox */ 
		    challenge != reg) {
			return EACCES; /* return Permission denied */
		}

		if (p_conn_info->mode == MCREG_DUP_REG && 
		    p_ctx_info->ref_cnt == 0) {
			return EINVAL; /* no prior registration to dup */
		}

		/* a fresh registration will cause all previous 
		 * registrations, if any, to be forcefully canceled. 
		 * This is important since a client can close the context 
		 * (AFU) but not unregister the mc_handle. A new owner of 
		 * the same context must be able to mc_register by 
		 * forcefully unregistering the previous owner.  
		 */
		if (p_conn_info->mode == MCREG_INITIAL_REG) {
			for (i = 0; i < MAX_CONNS; i++) { 
				if (p_afu->conn_tbl[i].p_ctx_info == 
				    p_ctx_info) { 
					do_mc_unregister(p_afu, 
							 &p_afu->conn_tbl[i]); 
				} 
			}

			if (p_ctx_info->ref_cnt != 0) { 
				cflash_err("%s: internal error: p_ctx_info->"
					"ref_cnt != 0", p_afu->name); 
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
				return EAGAIN; 
			}

			/* the context gets a dedicated RHT tbl unless it 
			 * is dup'ed later. 
			 */
			p_ctx_info->p_rht_info = 
				&p_afu->rht_info[p_conn_info->ctx_hndl];
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
		} 
		p_conn_info->p_ctx_info = p_ctx_info; 
		p_ctx_info->ref_cnt++; 
		p_conn_info->rx = rx_ready; 
		/* it is now registered, go to ready state */ 
		return 0; 
	} 
	else { 
		return EINVAL; 
	}
}

// rx fcn on a fresh connection waiting a MCREG.
// On receipt of a MCREG, it will go to the rx_ready state where
// all cmds except a MCREG is accepted.
//
int rx_mcreg(afu_t *p_afu, conn_info_t *p_conn_info, 
	     mc_req_t *p_req, mc_resp_t *p_resp)
{ 
	int status = EINVAL; 

	/* XXX: Dummy */
	return status;
}

int
do_mc_close(afu_t        *p_afu, 
	    conn_info_t  *p_conn_info, 
	    res_hndl_t   res_hndl)
{
	int status = EINVAL; 

	/* XXX: Dummy */
	return status;
}



/*
 * NAME:        cflash_mc_unregister
 *
 * FUNCTION:    Unregister a user AFU context with master.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to optional arg structure
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
 *               c. goes to rx_mcreg state to allow re-registration
 */
int cflash_mc_unregister(struct scsi_device *sdev, void __user *arg)
{
	int i;
        conn_info_t  *p_conn_info = NULL; 
	ctx_info_t *p_ctx_info = p_conn_info->p_ctx_info; 
	cflash_t *p_cflash = (cflash_t *)sdev->host->hostdata;
	afu_t *p_afu = &p_cflash->p_afu_a->afu;

	if (p_ctx_info->ref_cnt-- == 1) { 

		/* close the context */ 
		/* for any resource still open, dealloate LBAs and close 
		 * if nobody else is using it. 
		 */ 

		if (p_ctx_info->p_rht_info->ref_cnt-- == 1) { 
			for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) { 
				do_mc_close(p_afu, p_conn_info, i); 
				// will this p_conn_info work ?  
			}
		} 
		
		/* clear RHT registers for this context */ 
		write_64(&p_ctx_info->p_ctrl_map->rht_start, 0); 
		write_64(&p_ctx_info->p_ctrl_map->rht_cnt_id, 0); 
		/* drop all capabilities */ 
		write_64(&p_ctx_info->p_ctrl_map->ctx_cap, 0); 
	} 
	p_conn_info->p_ctx_info = NULL; 
	p_conn_info->rx = rx_mcreg; 
	/* client can now send another MCREG */ 

	return 0; 
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
		 cflash_dbg("%s: wait on port %d to go offline timed out\n", 
			    p_afu->name, port);
		 ret = -1; // but continue on to leave the port back online
	}

	if (ret == 0) {
		write_64(&p_fc_regs[FC_PNAME/8], wwpn);
	}

	set_port_online(p_fc_regs);

	if (!wait_port_online(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT)) {
		cflash_dbg("%s: wait on port %d to go online timed out\n", 
			   p_afu->name, port);
		ret = -1;
	}

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
	case UNDO_MLOCK:
	default:
		break;
	}
}

int cflash_terminate_afu(afu_t *p_afu)
{
	cflash_undo_start_afu(p_afu, UNDO_AFU_ALL);

	return 0;
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


#ifdef NEWCXL
static irqreturn_t cflash_dummy_irq_handler(int irq, void *data)
{
	/* XXX make unique handlers for each interrupt */
	return IRQ_HANDLED;
}

/*
 * Start the afu context.  This is calling into the generic CXL driver code
 * (except for the contents of the WED).
 */
int cflash_start_context(cflash_t *p_cflash)
{
        int rc = 0;

        rc =  cxl_start_context(p_cflash->p_ctx, p_cflash->p_afu_a->afu.work.work_element_descriptor, NULL);

        return rc;
}

/*
 * Stop the afu context.  This is calling into the generic CXL driver code
 */
void cflash_stop_context(cflash_t *p_cflash)
{
	cxl_stop_context(p_cflash->p_ctx);
}


int cflash_start_afu(cflash_t *p_cflash)
{
	afu_t *p_afu = &p_cflash->p_afu_a->afu;
	struct capikv_ini_elm *p_elm = &p_cflash->p_ini->elm[0];
	char version[16];
	__u64 reg;
	int i = 0;
	int rc = 0;
	enum undo_level level = UNDO_NONE;

	/* Map the entire MMIO space of the AFU. 
	 * XXX: What is the equivalent in the new interface?
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
	 * p_afu->ctx_hndl =  (__u16)p_cflash->p_ctx->pe; 
	 */
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
	cflash_dbg("%s: afu version %s, ctx_hndl %d\n", p_afu->name, version, p_afu->ctx_hndl);

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
		// program FC_PORT LUN Tbl
		write_64(&p_afu->p_afu_map->global.fc_port[i][0],
			p_elm->lun_id);
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
		  // set WWPNs. If already programmed, p_elm->wwpn[i] is 0
		if (p_elm->wwpn[i] != 0 &&
			afu_set_wwpn(p_afu, i,
			&p_afu->p_afu_map->global.fc_regs[i][0],
			p_elm->wwpn[i])) {
			cflash_dbg("%s: failed to set WWPN on port %d\n", 
				   p_afu->name, i);
			cflash_undo_start_afu(p_afu, level);
			return -1;
		 }

		 // record the lun_id to be used in discovery later
		 p_afu->lun_info[i].lun_id = p_elm->lun_id;
	 }

	 // set up master's own CTX_CAP to allow real mode, host translation
	 // tbls, afu cmds and non-read/write GSCSI cmds.
	 // First, unlock ctx_cap write by reading mbox
	 //
	 (void) read_64(&p_afu->p_ctrl_map->mbox_r); // unlock ctx_cap
	 asm volatile ( "eieio" : : );
	 write_64(&p_afu->p_ctrl_map->ctx_cap,
			SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE |
			SISL_CTX_CAP_AFU_CMD |
			SISL_CTX_CAP_GSCSI_CMD);
	  // init heartbeat
	  p_afu->hb = read_64(&p_afu->p_afu_map->global.regs.afu_hb);

out:
	return rc;
}

int cflash_init_afu(cflash_t *p_cflash)
{
	int rc;
	struct cxl_context *ctx;

	ctx = cxl_dev_context_init(p_cflash->p_dev);
	if (!ctx)
		return -ENOMEM;
	p_cflash->p_ctx = ctx;

	/* Allocate AFU generated interrupt handler */
	rc = cxl_allocate_afu_irqs(ctx, 4);
	if (rc)
		goto err1;

	/* Register AFU interrupt 1. */
	rc = cxl_map_afu_irq(ctx, 1, cflash_dummy_irq_handler, NULL,
			      "afu1");
	if (!rc)
		goto err2;
	/* Register AFU interrupt 2 for errors. */
	rc = cxl_map_afu_irq(ctx, 2, cflash_dummy_irq_handler, ctx,
			     "err1");
	if (!rc)
		goto err3;
	/* Register AFU interrupt 3 for errors. */
	rc = cxl_map_afu_irq(ctx, 3, cflash_dummy_irq_handler, ctx,
			     "err2");
	if (!rc)
		goto err4;

	/* Register AFU interrupt 4 for errors. */
	rc = cxl_map_afu_irq(ctx, 4, cflash_dummy_irq_handler, ctx,
			     "err3");
	if (!rc)
		goto err5;

	/* Register for PSL errors. TODO: implement this */
	//cxl_register_error_irq(dev, flags??, callback function, private data);
	
	/* This performs the equivalent of the CXL_IOCTL_START_WORK.
	 * The CXL_IOCTL_GET_PROCESS_ELEMENT is implicit in the process
	 * element (pe) that is embedded in the context (ctx)
	 */
        rc = cflash_start_context (p_cflash);
        if (!rc)
                goto err6;


        rc = cflash_start_afu (p_cflash);
        if (!rc)
                goto err7;

	return 0;
err7:
	cflash_stop_context(p_cflash);
err6:
	cxl_unmap_afu_irq(ctx, 4, NULL);
err5:
	cxl_unmap_afu_irq(ctx, 3, NULL);
err4:
	cxl_unmap_afu_irq(ctx, 2, NULL);
err3:
	cxl_unmap_afu_irq(ctx, 1, NULL);
err2:
	cxl_free_afu_irqs(ctx);
err1:
	cxl_release_context(ctx);
	p_cflash->p_ctx = NULL;
	return rc;
}
#endif /* NEWCXL */
