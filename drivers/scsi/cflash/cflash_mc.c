
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
#include "block_alloc.h"
#include "afu_fc.h"
#include "mserv.h"


int cflash_disk_attach(struct scsi_device *sdev, void __user *arg)
{
	int rc = 0;
	return rc;
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
int cflash_start_context(global_t *gbp)
{
        int rc = 0;

        rc =  cxl_start_context(gbp->p_ctx, gbp->p_afu_a->afu.work.work_element_descriptor, NULL);

        return rc;
}

/*
 * Stop the afu context.  This is calling into the generic CXL driver code
 */
void cflash_stop_context(global_t *gbp)
{
	cxl_stop_context(gbp->p_ctx);
}

int cflash_afu_start(global_t *gbp)
{
	afu_t *p_afu = &gbp->p_afu_a->afu;
	struct capikv_ini_elm *p_elm = &gbp->p_ini->elm[0];
	char version[16];
	__u64 reg;
	int i = 0;
	int rc = 0;
	enum undo_level level = UNDO_NONE;

	/* Map the entire MMIO space of the AFU. 
	 * XXX: What is the equivalent in the new interface?
	 */
	p_afu->p_afu_map =  cxl_psa_map(gbp->p_ctx);
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
	 * p_afu->ctx_hndl =  (__u16)gbp->p_ctx->pe; 
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
			undo_afu_init(p_afu, level);
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

int cflash_afu_init(global_t *gbp)
{
	int rc;
	struct cxl_context *ctx;

	ctx = cxl_dev_context_init(gbp->p_dev);
	if (!ctx)
		return -ENOMEM;
	gbp->p_ctx = ctx;

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
        rc = cflash_start_context (gbp);
        if (!rc)
                goto err6;


        rc = cflash_afu_start (gbp);
        if (!rc)
                goto err7;

	return 0;
err7:
	cflash_stop_context(gbp);
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
	gbp->p_ctx = NULL;
	return rc;
}
#endif /* NEWCXL */
