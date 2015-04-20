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

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/libata.h>
#include <linux/reboot.h>

#include <misc/cxl.h>
#include <uapi/misc/cxl.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_transport_fc.h>

#include "main.h"
#include "sislite.h"
#include "superpipe.h"

MODULE_DESCRIPTION(CXLFLASH_ADAPTER_NAME);
MODULE_AUTHOR("Manoj N. Kumar <manoj@linux.vnet.ibm.com>");
MODULE_AUTHOR("Matthew R. Ochs <mrochs@linux.vnet.ibm.com>");
MODULE_LICENSE("GPL");

u32 internal_lun = 0;
u32 fullqc = 0;
u32 checkpid = 0;
module_param_named(lun_mode, internal_lun, uint, 0);
MODULE_PARM_DESC(lun_mode, " 0 = external LUN[s](default),\n"
			   " 1 = internal LUN (1 x 64K, 512B blocks, id 0),\n"
			   " 2 = internal LUN (1 x 64K, 4K blocks, id 0),\n"
			   " 3 = internal LUN (2 x 32K, 512B blocks, ids 0,1),\n"
			   " 4 = internal LUN (2 x 32K, 4K blocks, ids 0,1)");

module_param_named(qc, fullqc, uint, 0);
MODULE_PARM_DESC(qc, " 1 = Regular SCSI queuecommand");

module_param_named(checkpid, checkpid, uint, 0);
MODULE_PARM_DESC(checkpid, " 1 = Enforce PID/context ownership policy");

/* Check out a command */
struct afu_cmd *cmd_checkout(struct afu *p_afu)
{
	int k, dec = CXLFLASH_NUM_CMDS;
	struct afu_cmd *p_cmd;
	unsigned long lock_flags = 0;

	while (dec--) {
		k = (p_afu->cmd_couts++ & (CXLFLASH_NUM_CMDS - 1));

		/* The last command structure is reserved for SYNC */
		if (k == AFU_SYNC_INDEX)
			continue;

		p_cmd = &p_afu->cmd[k];

		spin_lock_irqsave(p_cmd->slock, lock_flags);

		if (p_cmd->flag == CMD_FREE) {
			p_cmd->flag = CMD_IN_USE;
			spin_unlock_irqrestore(p_cmd->slock, lock_flags);
			cxlflash_dbg("returning found index=%d", p_cmd->slot);
			memset(p_cmd->buf, 0, CMD_BUFSIZE);
			memset(p_cmd->rcb.cdb, 0, sizeof(p_cmd->rcb.cdb));
			return p_cmd;
		}

		spin_unlock_irqrestore(p_cmd->slock, lock_flags);
	}

	return NULL;
}

/* Check in the command */
void cmd_checkin(struct afu_cmd *p_cmd)
{
	unsigned long lock_flags = 0;

	spin_lock_irqsave(p_cmd->slock, lock_flags);
	p_cmd->flag = CMD_FREE;
	p_cmd->special = 0;
	spin_unlock_irqrestore(p_cmd->slock, lock_flags);
	cxlflash_dbg("releasing cmd index=%d", p_cmd->slot);

}

/**
 * cxlflash_send_scsi - Send a generic SCSI CDB down
 * @p_afu:        struct afu pointer
 * @scp:          scsi command passed in 
 *
 * Returns:
 *      SUCCESS, BUSY
 */
int cxlflash_send_scsi(struct afu *p_afu, struct scsi_cmnd *scp)
{
	struct afu_cmd *p_cmd;

	u64 port_sel = scp->device->channel + 1;
	int nseg, i, ncount;
	struct scatterlist *sg;
	short lflag = 0;
	int rc = 0;

	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *p_cxlflash = (struct cxlflash *)host->hostdata;

	while (p_cxlflash->tmf_active)
		wait_event(p_cxlflash->tmf_wait_q, !p_cxlflash->tmf_active);

	p_cmd = cmd_checkout(p_afu);
	if (!p_cmd) {
		cxlflash_err("could not get a free command");
		rc = SCSI_MLQUEUE_HOST_BUSY;
		goto out;
	}

	p_cmd->rcb.ctx_id = p_afu->ctx_hndl;
	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = lun_to_lunid(scp->device->lun);

	if (scp->sc_data_direction == DMA_TO_DEVICE)
		lflag = SISL_REQ_FLAGS_HOST_WRITE;
	else
		lflag = SISL_REQ_FLAGS_HOST_READ;

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN | lflag);
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	/* Stash the scp in the reserved field, for reuse during interrupt */
	p_cmd->rcb.rsvd2 = (u64) scp;

	p_cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	nseg = scsi_dma_map(scp);
	ncount = scsi_sg_count(scp);
	scsi_for_each_sg(scp, sg, ncount, i) {
		p_cmd->rcb.data_len = (sg_dma_len(sg));
                p_cmd->rcb.data_ea = (sg_dma_address(sg));
	}

	/* Copy the CDB from the scsi_cmnd passed in */
	memcpy(p_cmd->rcb.cdb, scp->cmnd, sizeof(p_cmd->rcb.cdb));

	/* Send the command */
	cxlflash_send_cmd(p_afu, p_cmd);

out:
	return rc;
}

/**
 * cxlflash_send_tmf - Send a Task Management Function
 * @p_afu:        struct afu pointer
 * @scp:          scsi command passed in 
 * cmd:           Kind of TMF command
 *
 * Returns:
 *      SUCCESS, BUSY
 */
int cxlflash_send_tmf(struct afu *p_afu, struct scsi_cmnd *scp, u64 cmd)
{
	struct afu_cmd *p_cmd;

	u64 port_sel = scp->device->channel + 1;
	short lflag = 0;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *p_cxlflash = (struct cxlflash *)host->hostdata;
	int rc = 0;

	while (p_cxlflash->tmf_active)
		wait_event(p_cxlflash->tmf_wait_q, !p_cxlflash->tmf_active);

	p_cmd = cmd_checkout(p_afu);
	if (!p_cmd) {
		cxlflash_err("could not get a free command");
		rc = SCSI_MLQUEUE_HOST_BUSY;
		goto out;
	}

	p_cmd->rcb.ctx_id = p_afu->ctx_hndl;
	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = lun_to_lunid(scp->device->lun);

	lflag = SISL_REQ_FLAGS_TMF_CMD;

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN | lflag);
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	/* Stash the scp in the reserved field, for reuse during interrupt */
	p_cmd->rcb.rsvd2 = (u64) scp;
	p_cmd->special = 0x1;
	p_cxlflash->tmf_active = 0x1;

	p_cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	/* Copy the CDB from the cmd passed in */
	memcpy(p_cmd->rcb.cdb, &cmd, sizeof(cmd));

	/* Send the command */
	cxlflash_send_cmd(p_afu, p_cmd);
	wait_event(p_cxlflash->tmf_wait_q, !p_cxlflash->tmf_active);
out:
	return rc;

}

/**
 * cxlflash_driver_info - Get information about the card/driver
 * @scsi_host:       scsi host struct
 *
 * Return value:
 *      pointer to buffer with description string
 **/
static const char *cxlflash_driver_info(struct Scsi_Host *host)
{
	static char buffer[512];
	unsigned long lock_flags = 0;

	spin_lock_irqsave(host->host_lock, lock_flags);
	sprintf(buffer, CXLFLASH_ADAPTER_NAME);
	spin_unlock_irqrestore(host->host_lock, lock_flags);

	return buffer;
}

/**
 * cxlflash_queuecommand - Queue a mid-layer request
 * @shost:               scsi host struct
 * @scsi_cmd:            scsi command struct
 *
 * This function queues a request generated by the mid-layer.
 *
 * Return value:
 *      0 on success
 *      SCSI_MLQUEUE_DEVICE_BUSY if device is busy
 *      SCSI_MLQUEUE_HOST_BUSY if host is busy
 **/
static int cxlflash_queuecommand(struct Scsi_Host *host,
			       struct scsi_cmnd *scp)
{
	struct cxlflash *p_cxlflash = (struct cxlflash *)host->hostdata;
	struct afu *p_afu = p_cxlflash->afu;
	int rc = 0;

	if (!fullqc) {
		scp->scsi_done(scp);
	} else {
		cxlflash_dbg("(scp=%p) %d/%d/%d/%llu "
			"cdb=(%08x-%08x-%08x-%08x)", scp,
			host->host_no, scp->device->channel,
			scp->device->id, scp->device->lun,
			cpu_to_be32(((u32 *) scp->cmnd)[0]),
			cpu_to_be32(((u32 *) scp->cmnd)[1]),
			cpu_to_be32(((u32 *) scp->cmnd)[2]),
			cpu_to_be32(((u32 *) scp->cmnd)[3]));

		rc = cxlflash_send_scsi(p_afu, scp);
	}
	return rc;
}

/**
 * cxlflash_eh_device_reset_handler - Reset a single LUN
 * @cmd:        scsi command struct
 *
 * Returns:
 *      SUCCESS / FAST_IO_FAIL / FAILED
 **/
static int cxlflash_eh_device_reset_handler(struct scsi_cmnd *scp)
{
	int rc = SUCCESS;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *p_cxlflash = (struct cxlflash *)host->hostdata;
	struct afu *p_afu = p_cxlflash->afu;

	cxlflash_info("(scp=%p) %d/%d/%d/%llu "
		    "cdb=(%08x-%08x-%08x-%08x)", scp,
		    host->host_no, scp->device->channel,
		    scp->device->id, scp->device->lun,
		    cpu_to_be32(((u32 *) scp->cmnd)[0]),
		    cpu_to_be32(((u32 *) scp->cmnd)[1]),
		    cpu_to_be32(((u32 *) scp->cmnd)[2]),
		    cpu_to_be32(((u32 *) scp->cmnd)[3]));

	scp->result = (DID_OK << 16);;
	cxlflash_send_tmf(p_afu, scp, TMF_LUN_RESET);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_eh_host_reset_handler - Reset the connection to the server
 * @cmd:        struct scsi_cmnd having problems
 *
 **/
static int cxlflash_eh_host_reset_handler(struct scsi_cmnd *scp)
{
	int rc = SUCCESS;
	int rcr = 0;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *p_cxlflash = (struct cxlflash *)host->hostdata;

	cxlflash_info("(scp=%p) %d/%d/%d/%llu "
		    "cdb=(%08x-%08x-%08x-%08x)", scp,
		    host->host_no, scp->device->channel,
		    scp->device->id, scp->device->lun,
		    cpu_to_be32(((u32 *) scp->cmnd)[0]),
		    cpu_to_be32(((u32 *) scp->cmnd)[1]),
		    cpu_to_be32(((u32 *) scp->cmnd)[2]),
		    cpu_to_be32(((u32 *) scp->cmnd)[3]));

	scp->result = (DID_OK << 16);;
	rcr = afu_reset(p_cxlflash);
	if (rcr == 0)
		rc = SUCCESS;
	else
		rc = FAILED;

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

static struct lun_info *
create_lun_info(struct scsi_device *sdev)
{
	struct lun_info *p_lun_info = NULL;

	p_lun_info = kzalloc(sizeof(*p_lun_info), GFP_KERNEL);
	if (!p_lun_info) {
		cxlflash_err("could not allocate p_lun_info");
		goto create_lun_info_exit;
	}

	p_lun_info->sdev = sdev;

	spin_lock_init(&p_lun_info->_slock);
	p_lun_info->slock = &p_lun_info->_slock;

create_lun_info_exit:
	cxlflash_info("returning %p", p_lun_info);
	return p_lun_info;
}

/**
 * cxlflash_slave_alloc - Setup the device's task set value
 * @sdev:       struct scsi_device device to configure
 *
 * Set the device's task set value so that error handling works as
 * expected.
 *
 * Returns:
 *      0 on success / -ENXIO if device does not exist
 **/
static int cxlflash_slave_alloc(struct scsi_device *sdev)
{
	struct lun_info *p_lun_info = NULL;
	struct Scsi_Host *shost = sdev->host;
	struct cxlflash *p_cxlflash = shost_priv(shost);
	struct afu *p_afu = p_cxlflash->afu;
	unsigned long flags = 0;
	int rc = 0;

	spin_lock_irqsave(shost->host_lock, flags);

	p_lun_info = create_lun_info(sdev);
	if (!p_lun_info) {
		cxlflash_err("failed to allocate lun_info!");
		rc = -ENXIO;
		goto out;
	}

	sdev->hostdata = p_lun_info;
	list_add(&p_lun_info->list, &p_afu->luns);
out:
	spin_unlock_irqrestore(shost->host_lock, flags);

	cxlflash_info("returning task_set %d luninfo %p sdev %p",
		    p_cxlflash->task_set, p_lun_info, sdev);
	return rc;
}

/**
 * cxlflash_slave_configure - Configure the device
 * @sdev:       struct scsi_device device to configure
 *
 * Enable allow_restart for a device if it is a disk. Adjust the
 * queue_depth here also.
 *
 * Returns:
 *      0
 **/
static int cxlflash_slave_configure(struct scsi_device *sdev)
{
	struct lun_info *p_lun_info = sdev->hostdata;
	int rc = 0;

	cxlflash_info("ID = %08X", sdev->id);
	cxlflash_info("CHANNEL = %08X", sdev->channel);
	cxlflash_info("LUN = %016llX", sdev->lun);
	cxlflash_info("sector_size = %u", sdev->sector_size);

	/* Store off lun in unpacked, AFU-friendly format */
	p_lun_info->lun_id = lun_to_lunid(sdev->lun);
	cxlflash_info("LUN2 = %016llX", p_lun_info->lun_id);

	/*
	 * XXX - leaving this here for now as a reminder that read_cap16
	 * doesn't work in this path. We also need to figure out how and
	 * when to setup the LUN table (on attach coupled with where we
	 * now call read_cap16?) and also look into how we're skipping
	 * entries. The spec has a blurb about this but I'm not convinced
	 * we're doing it right.
	 */
	if (fullqc) {
		struct Scsi_Host *shost = sdev->host;
		struct cxlflash *p_cxlflash = shost_priv(shost);
		struct afu *p_afu = p_cxlflash->afu;


		writeq_be(p_lun_info->lun_id,
			  &p_afu->afu_map->global.fc_port[sdev->channel]
			  [p_cxlflash->last_lun_index++]);
		//read_cap16(p_afu, p_lun_info, sdev->channel + 1);
		cxlflash_info("LBA = %016llX", p_lun_info->max_lba);
		cxlflash_info("BLK_LEN = %08X", p_lun_info->blk_len);

#if 0
		rc = cxlflash_init_ba(p_lun_info);
		if (rc) {
			cxlflash_err("call to cxlflash_init_ba failed rc=%d!",
				   rc);
			rc = -ENOMEM;
			goto out;
		}
#endif
	}

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

static void ba_terminate(struct ba_lun *ba_lun)
{
	struct ba_lun_info *p_lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (p_lun_info) {
		if (p_lun_info->aun_clone_map)
			kfree(p_lun_info->aun_clone_map);
		if (p_lun_info->lun_alloc_map)
			kfree(p_lun_info->lun_alloc_map);
		kfree(p_lun_info);
		ba_lun->ba_lun_handle = NULL;
	}
}
static void cxlflash_slave_destroy(struct scsi_device *sdev)
{
	struct lun_info *p_lun_info = sdev->hostdata;

	if (p_lun_info) {
		sdev->hostdata = NULL;
		list_del(&p_lun_info->list);
		ba_terminate(&p_lun_info->blka.ba_lun);
		kfree(p_lun_info);
	}

	cxlflash_info("p_lun_info=%p", p_lun_info);
	return;
}

/**
 * cxlflash_scan_finished - Check if the device scan is done.
 * @shost:      scsi host struct
 * @time:       current elapsed time
 *
 * Returns:
 *      0 if scan is not done / 1 if scan is done
 **/
static int cxlflash_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	int done = 1;
	cxlflash_info("returning done=%d", done);
	return done;
}

/**
 * cxlflash_change_queue_depth - Change the device's queue depth
 * @sdev:       scsi device struct
 * @qdepth:     depth to set
 * @reason:     calling context
 *
 * Return value:
 *      actual depth set
 **/
static int cxlflash_change_queue_depth(struct scsi_device *sdev, int qdepth)
{

	if (qdepth > CXLFLASH_MAX_CMDS_PER_LUN)
		qdepth = CXLFLASH_MAX_CMDS_PER_LUN;

	scsi_change_queue_depth(sdev, qdepth);
	return sdev->queue_depth;
}


static ssize_t cxlflash_show_port_status(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *p_cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *p_afu = p_cxlflash->afu;

	char *disp_status;
	int rc;
	u32 port;
	u64 status;
	volatile u64 *p_fc_regs;

	rc = kstrtouint((attr->attr.name + 4), 10, &port);
	if (rc || (port > NUM_FC_PORTS))
		return 0;

	p_fc_regs = &p_afu->afu_map->global.fc_regs[port][0];
	status =
	    (readq_be(&p_fc_regs[FC_MTIP_STATUS / 8]) & FC_MTIP_STATUS_MASK);

	if (status == FC_MTIP_STATUS_ONLINE)
		disp_status = "online";
	else if (status == FC_MTIP_STATUS_OFFLINE)
		disp_status = "offline";
	else
		disp_status = "unknown";

	return snprintf(buf, PAGE_SIZE, "%s\n", disp_status);
}

static ssize_t cxlflash_show_lun_mode(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *p_cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *p_afu = p_cxlflash->afu;

	return snprintf(buf, PAGE_SIZE, "%u\n", p_afu->internal_lun);
}

static ssize_t cxlflash_store_lun_mode(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *p_cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *p_afu = p_cxlflash->afu;
	int rc;
	u32 lun_mode;

	rc = kstrtouint(buf, 10, &lun_mode);
	if (!rc && (lun_mode < 5) && (lun_mode != p_afu->internal_lun))
		p_afu->internal_lun = lun_mode;

	/* XXX - need to reset device w/ new lun mode */

	return count;
}

/**
 * cxlflash_wait_for_pci_err_recovery - Wait for any PCI error recovery to
 *					complete during probe time
 * @p_cxlflash:    cxlflash config struct
 *
 * Return value:
 *	None
 */
static void cxlflash_wait_for_pci_err_recovery(struct cxlflash *p_cxlflash)
{
	struct pci_dev *pdev = p_cxlflash->dev;

	if (pci_channel_offline(pdev)) {
		wait_event_timeout(p_cxlflash->eeh_wait_q,
				   !pci_channel_offline(pdev),
				   CXLFLASH_PCI_ERROR_RECOVERY_TIMEOUT);
		pci_restore_state(pdev);
	}
}

static DEVICE_ATTR(port0, S_IRUGO, cxlflash_show_port_status, NULL);
static DEVICE_ATTR(port1, S_IRUGO, cxlflash_show_port_status, NULL);
static DEVICE_ATTR(lun_mode, S_IRUGO | S_IWUSR, cxlflash_show_lun_mode,
		   cxlflash_store_lun_mode);

static struct device_attribute *cxlflash_attrs[] = {
	&dev_attr_port0,
	&dev_attr_port1,
	&dev_attr_lun_mode,
	NULL
};

static struct scsi_host_template driver_template = {
	.module = THIS_MODULE,
	.name = CXLFLASH_ADAPTER_NAME,
	.info = cxlflash_driver_info,
	.ioctl = cxlflash_ioctl,
	.proc_name = CXLFLASH_NAME,
	.queuecommand = cxlflash_queuecommand,
	.eh_device_reset_handler = cxlflash_eh_device_reset_handler,
	.eh_host_reset_handler = cxlflash_eh_host_reset_handler,
	.slave_alloc = cxlflash_slave_alloc,
	.slave_configure = cxlflash_slave_configure,
	.slave_destroy = cxlflash_slave_destroy,
	.scan_finished = cxlflash_scan_finished,
	.change_queue_depth = cxlflash_change_queue_depth,
	.cmd_per_lun = 16,
	.can_queue = CXLFLASH_MAX_CMDS,
	.this_id = -1,
	.sg_tablesize = SG_NONE,	/* No scatter gather support. */
	.max_sectors = CXLFLASH_MAX_SECTORS,
	.use_clustering = ENABLE_CLUSTERING,
	.shost_attrs = cxlflash_attrs,
};

static struct dev_dependent_vals dev_corsa_vals = { CXLFLASH_MAX_SECTORS };

static struct pci_device_id cxlflash_pci_table[] = {
	{ PCI_VENDOR_ID_IBM, PCI_DEVICE_ID_IBM_CORSA,
	  PCI_ANY_ID, PCI_ANY_ID, 0, 0, (kernel_ulong_t)&dev_corsa_vals
	},
	{}
};

MODULE_DEVICE_TABLE(pci, cxlflash_pci_table);

/**
 * cxlflash_free_mem - Frees memory allocated for an adapter
 * @p_cxlflash:    struct cxlflash reference
 *
 * Return value:
 *      nothing
 **/
static void cxlflash_free_mem(struct cxlflash *p_cxlflash)
{
	int i, nbytes;
	char *buf = NULL;
	struct afu *p_afu = p_cxlflash->afu;
	struct lun_info *p_lun_info, *p_temp;

	if (p_cxlflash->afu) {
		list_for_each_entry_safe(p_lun_info, p_temp, &p_afu->luns,
					 list) {
			list_del(&p_lun_info->list);
			ba_terminate(&p_lun_info->blka.ba_lun);
			kfree(p_lun_info);
		}

		for (i=0; i<CXLFLASH_NUM_CMDS; i++) {
			del_timer_sync(&p_cxlflash->afu->cmd[i].timer);
			buf = p_cxlflash->afu->cmd[i].buf;
			if (buf)
				free_pages((unsigned long)buf,
					   get_order(CMD_BUFSIZE));
		}

		nbytes = sizeof(struct afu);
		free_pages((unsigned long)p_cxlflash->afu, get_order(nbytes));
		p_cxlflash->afu = NULL;
	}

	return;
}

/**
 * cxlflash_stop_afu - Stop AFU
 * @p_cxlflash:       struct cxlflash
 *
 * Tear down timers, Unmap the MMIO space
 *
 * Return value:
 *      none
 **/
static void cxlflash_stop_afu(struct cxlflash *p_cxlflash)
{
	int i;
	struct afu *p_afu = p_cxlflash->afu;

	if (!p_afu) {
		cxlflash_info("returning because afu is NULl");
		return;
	}

	/* Need to stop timers before unmapping */
	for (i=0; i<CXLFLASH_NUM_CMDS; i++) {
		del_timer_sync(&p_cxlflash->afu->cmd[i].timer);
	}

	if (p_afu->afu_map) {
		cxl_psa_unmap((void *)p_afu->afu_map);
		p_afu->afu_map = NULL;
	}
}

/**
 * cxlflash_term_mc - Terminate the master context
 * @p_cxlflash:        struct cxlflash pointer
 * @level:           level to back out from
 *
 * Returns:
 *      NONE
 */
void cxlflash_term_mc(struct cxlflash *p_cxlflash, enum undo_level level)
{
	struct afu *p_afu = p_cxlflash->afu;

	if (!p_afu || !p_cxlflash->mcctx)
	{
		cxlflash_info("returning from term_mc with NULL afu or MC");
		return;
	}

	switch (level) { 
	case UNDO_START:
		cxl_stop_context(p_cxlflash->mcctx);
	case UNMAP_FOUR:
		cxlflash_info("before unmap 4");
		cxl_unmap_afu_irq(p_cxlflash->mcctx, 4, p_afu);
	case UNMAP_THREE:
		cxlflash_info("before unmap 3");
		cxl_unmap_afu_irq(p_cxlflash->mcctx, 3, p_afu);
	case UNMAP_TWO:
		cxlflash_info("before unmap 2");
		cxl_unmap_afu_irq(p_cxlflash->mcctx, 2, p_afu);
	case UNMAP_ONE:
		cxlflash_info("before unmap 1");
		cxl_unmap_afu_irq(p_cxlflash->mcctx, 1, p_afu);
	case FREE_IRQ:
		cxlflash_info("before cxl_free_afu_irqs");
		cxl_free_afu_irqs(p_cxlflash->mcctx);
		cxlflash_info("before cxl_release_context");
	case RELEASE_CONTEXT:
		cxl_release_context(p_cxlflash->mcctx);
		p_cxlflash->mcctx = NULL;
	}
}

static void cxlflash_term_afu(struct cxlflash *p_cxlflash)
{
	cxlflash_term_mc(p_cxlflash, UNDO_START);

	/* Need to stop timers before unmapping */
	if (p_cxlflash->afu) {
		cxlflash_stop_afu(p_cxlflash);

	}

	cxlflash_info("returning");
}
/**
 * cxlflash_remove - CXLFLASH hot plug remove entry point
 * @pdev:       pci device struct
 *
 * Adapter hot plug remove entry point.
 *
 * Return value:
 *      none
 **/
static void cxlflash_remove(struct pci_dev *pdev)
{
	struct cxlflash *p_cxlflash = pci_get_drvdata(pdev);

	cxlflash_dev_err(&pdev->dev, "enter cxlflash_remove!");

	while (p_cxlflash->tmf_active)
		wait_event(p_cxlflash->tmf_wait_q, !p_cxlflash->tmf_active);


	/* Use this for now to indicate that scsi_add_host() was performed */
	if (p_cxlflash->host->cmd_pool) {
		scsi_remove_host(p_cxlflash->host);
		cxlflash_dev_err(&pdev->dev, "after scsi_remove_host!");
	}
	flush_work(&p_cxlflash->work_q);


	cxlflash_term_afu(p_cxlflash);
	cxlflash_dev_dbg(&pdev->dev, "after struct cxlflash_term_afu!");

	if (p_cxlflash->cxlflash_regs)
		iounmap(p_cxlflash->cxlflash_regs);

	pci_release_regions(p_cxlflash->dev);

	cxlflash_free_mem(p_cxlflash);
	scsi_host_put(p_cxlflash->host);
	cxlflash_dev_dbg(&pdev->dev, "after scsi_host_put!");

	pci_disable_device(pdev);

	cxlflash_dbg("returning");
}

/**
 * cxlflash_gb_alloc - Global allocator
 * @p_cxlflash:       struct cxlflash
 *
 * Adapter hot plug remove entry point.
 *
 * Return value:
 *      none
 **/
static int cxlflash_gb_alloc(struct cxlflash *p_cxlflash)
{
	int nbytes;
	int rc = 0;
	int i;
	char *buf = NULL;

	nbytes = sizeof(struct afu);
	p_cxlflash->afu = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						 get_order(nbytes));
	if (!p_cxlflash->afu) {
		cxlflash_err("cannot get %d free pages", get_order(nbytes));
		rc = -ENOMEM;
		goto out;
	}
	p_cxlflash->afu->back = p_cxlflash;
	p_cxlflash->afu->afu_map = NULL;

	/* Allocate one extra, just in case the SYNC command needs a buffer */
	for (i=0; i<CXLFLASH_NUM_CMDS; i++) {
		buf = (void *)__get_free_pages (GFP_KERNEL | __GFP_ZERO,
						get_order(CMD_BUFSIZE));
		if (!buf) {
			cxlflash_err("cannot allocate command buffers %d",
				   CMD_BUFSIZE);
			rc = -ENOMEM;
			cxlflash_free_mem(p_cxlflash);
			goto out;
		}
		p_cxlflash->afu->cmd[i].buf = buf;
		p_cxlflash->afu->cmd[i].flag = CMD_FREE;
		p_cxlflash->afu->cmd[i].slot = i;
		p_cxlflash->afu->cmd[i].special = 0;
	}

	for  (i=0; i<MAX_CONTEXT; i++) {
		p_cxlflash->per_context[i].lfd = -1;
	}

out:
	return rc;
}

/**
 * cxlflash_init_pci - Initialize PCI
 * @p_cxlflash:       struct cxlflash
 *
 * All PCI setup
 *
 * Return value:
 *      none
 **/
static int cxlflash_init_pci(struct cxlflash *p_cxlflash)
{
	struct pci_dev *pdev = p_cxlflash->dev;
	int rc = 0;

	p_cxlflash->cxlflash_regs_pci = pci_resource_start(pdev, 0);
	rc = pci_request_regions(pdev, CXLFLASH_NAME);
	if (rc < 0) {
		cxlflash_dev_err(&pdev->dev,
			"Couldn't register memory range of registers");
		goto out;
	}

	rc = pci_enable_device(pdev);
	if (rc || pci_channel_offline(pdev)) {
		if (pci_channel_offline(pdev)) {
			cxlflash_wait_for_pci_err_recovery(p_cxlflash);
			rc = pci_enable_device(pdev);
		}

		if (rc) {
			cxlflash_dev_err(&pdev->dev, "Cannot enable adapter");
			cxlflash_wait_for_pci_err_recovery(p_cxlflash);
			goto out_release_regions;
		}
	}

	/*
	p_cxlflash->cxlflash_regs = pci_ioremap_bar(pdev, 0);
	if (!p_cxlflash->cxlflash_regs) {
		cxlflash_dev_err(&pdev->dev,
			       "Couldn't map memory range of registers");
		rc = -ENOMEM;
		goto out_disable;
	}
	*/

	rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (rc < 0) {
		cxlflash_dev_dbg(&pdev->dev, "Failed to set 64 bit PCI DMA mask");
		rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	}

	if (rc < 0) {
		cxlflash_dev_err(&pdev->dev, "Failed to set PCI DMA mask");
		goto out_disable;
	}

	rc = pci_write_config_byte(pdev, PCI_CACHE_LINE_SIZE, 0x20);

	if (rc != PCIBIOS_SUCCESSFUL) {
		cxlflash_dev_err(&pdev->dev, "Write of cache line size failed");
		cxlflash_wait_for_pci_err_recovery(p_cxlflash);

		rc = -EIO;
		goto out_disable;
	}

	pci_set_master(pdev);

	if (pci_channel_offline(pdev)) {
		cxlflash_wait_for_pci_err_recovery(p_cxlflash);
		if (pci_channel_offline(pdev)) {
			rc = -EIO;
			goto out_msi_disable;
		}
	}

	rc = pci_save_state(pdev);

	if (rc != PCIBIOS_SUCCESSFUL) {
		cxlflash_dev_err(&pdev->dev, "Failed to save PCI config space");
		rc = -EIO;
		goto cleanup_nolog;
	}

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;

cleanup_nolog:
out_msi_disable:
	cxlflash_wait_for_pci_err_recovery(p_cxlflash);
	iounmap(p_cxlflash->cxlflash_regs);
out_disable:
	pci_disable_device(pdev);
out_release_regions:
	pci_release_regions(pdev);
	goto out;

}

static int cxlflash_init_scsi(struct cxlflash *p_cxlflash)
{
	struct pci_dev *pdev = p_cxlflash->dev;
	int rc = 0;

	cxlflash_dev_dbg(&pdev->dev, "before scsi_add_host");
	rc = scsi_add_host(p_cxlflash->host, &pdev->dev);
	if (rc) {
		cxlflash_dev_err(&pdev->dev, "scsi_add_host failed (rc=%d)", rc);
		goto out;
	}

	cxlflash_dev_dbg(&pdev->dev, "before scsi_scan_host");
	scsi_scan_host(p_cxlflash->host);

	if (!fullqc)
		cxlflash_scan_luns(p_cxlflash);

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/* online means the FC link layer has sync and has completed the link
 * layer handshake. It is ready for login to start.
 */
static void set_port_online(volatile u64 * p_fc_regs)
{
	u64 cmdcfg;

	cmdcfg = readq_be(&p_fc_regs[FC_MTIP_CMDCONFIG / 8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_OFFLINE);	/* clear OFF_LINE */
	cmdcfg |= (FC_MTIP_CMDCONFIG_ONLINE);	/* set ON_LINE */
	writeq_be(cmdcfg, &p_fc_regs[FC_MTIP_CMDCONFIG / 8]);
}

static void set_port_offline(volatile u64 * p_fc_regs)
{
	u64 cmdcfg;

	cmdcfg = readq_be(&p_fc_regs[FC_MTIP_CMDCONFIG / 8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_ONLINE);	/* clear ON_LINE */
	cmdcfg |= (FC_MTIP_CMDCONFIG_OFFLINE);	/* set OFF_LINE */
	writeq_be(cmdcfg, &p_fc_regs[FC_MTIP_CMDCONFIG / 8]);
}

/* returns 1 - went online */
/* wait_port_xxx will timeout when cable is not pluggd in */
static int wait_port_online(volatile u64 * p_fc_regs,
			    useconds_t delay_us,
			    unsigned int nretry)
{
	u64 status;

	if (delay_us < 1000) {
		cxlflash_err("invalid delay specified %d", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us / 1000);
		status = readq_be(&p_fc_regs[FC_MTIP_STATUS / 8]);
	} while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_ONLINE &&
		 nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_ONLINE);
}

/* returns 1 - went offline */
static int wait_port_offline(volatile u64 * p_fc_regs,
			     useconds_t delay_us,
			     unsigned int nretry)
{
	u64 status;

	if (delay_us < 1000) {
		cxlflash_err("invalid delay specified %d", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us / 1000);
		status = readq_be(&p_fc_regs[FC_MTIP_STATUS / 8]);
	} while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_OFFLINE &&
		 nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_OFFLINE);
}

/* this function can block up to a few seconds */
static int afu_set_wwpn(struct afu *p_afu,
			int port,
			volatile u64 * p_fc_regs,
			u64 wwpn)
{
	int ret = 0;

	set_port_offline(p_fc_regs);

	if (!wait_port_offline(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			       FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_dbg("wait on port %d to go offline timed out", port);
		ret = -1; /* but continue on to leave the port back online */
	}

	if (ret == 0) {
		writeq_be(wwpn, &p_fc_regs[FC_PNAME / 8]);
	}

	set_port_online(p_fc_regs);

	if (!wait_port_online(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_dbg("wait on port %d to go online timed out", port);
		ret = -1;

		/*
		 * Override for internal lun!!!
		 */
		if (internal_lun) {
			cxlflash_info("Overriding port %d online timeout!!!",
				    port);
			ret = 0;
		}
	}

	cxlflash_info("returning rc=%d", ret);

	return ret;
}


// this function can block up to a few seconds
static void afu_link_reset(struct afu *p_afu,
			   int port,
			   volatile __u64 *p_fc_regs)
{
	__u64 port_sel;
	// first switch the AFU to the other links, if any 

	port_sel = readq_be(&p_afu->afu_map->global.regs.afu_port_sel);
	port_sel &= ~(1 << port);
	writeq_be(port_sel, &p_afu->afu_map->global.regs.afu_port_sel);
	afu_sync(p_afu, 0, 0, AFU_GSYNC);

	set_port_offline(p_fc_regs);
	if (!wait_port_offline(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			       FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_err("wait on port %d to go offline timed out", port);
	}

	set_port_online(p_fc_regs);
	if (!wait_port_online(p_fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_err("wait on port %d to go online timed out", port);
	}

	// switch back to include this port 
	port_sel |= (1 << port);
	writeq_be(port_sel, &p_afu->afu_map->global.regs.afu_port_sel);
	afu_sync(p_afu, 0, 0, AFU_GSYNC);

}

struct asyc_intr_info ainfo[] = {
	{ SISL_ASTATUS_FC0_OTHER,    "fc 0: other error", 0, CLR_FC_ERROR | LINK_RESET },
	{ SISL_ASTATUS_FC0_LOGO,     "fc 0: target initiated LOGO", 0, 0 },
	{ SISL_ASTATUS_FC0_CRC_T,    "fc 0: CRC threshold exceeded", 0, LINK_RESET },
	{ SISL_ASTATUS_FC0_LOGI_R,   "fc 0: login timed out, retrying", 0, 0 },
	{ SISL_ASTATUS_FC0_LOGI_F,   "fc 0: login failed", 0, CLR_FC_ERROR },
	{ SISL_ASTATUS_FC0_LOGI_S,   "fc 0: login succeeded", 0, 0 },
	{ SISL_ASTATUS_FC0_LINK_DN,  "fc 0: link down", 0, 0 },
	{ SISL_ASTATUS_FC0_LINK_UP,  "fc 0: link up", 0, 0 },

	{ SISL_ASTATUS_FC1_OTHER,    "fc 1: other error", 1, CLR_FC_ERROR | LINK_RESET },
	{ SISL_ASTATUS_FC1_LOGO,     "fc 1: target initiated LOGO", 1, 0 },
	{ SISL_ASTATUS_FC1_CRC_T,    "fc 1: CRC threshold exceeded", 1, LINK_RESET },
	{ SISL_ASTATUS_FC1_LOGI_R,   "fc 1: login timed out, retrying", 1, 0 },
	{ SISL_ASTATUS_FC1_LOGI_F,   "fc 1: login failed", 1, CLR_FC_ERROR },
	{ SISL_ASTATUS_FC1_LOGI_S,   "fc 1: login succeeded", 1, 0 },
	{ SISL_ASTATUS_FC1_LINK_DN,  "fc 1: link down", 1, 0 },
	{ SISL_ASTATUS_FC1_LINK_UP,  "fc 1: link up", 1, 0 },
	{ 0x0,                       "", 0, 0 } /* terminator */
};

static struct asyc_intr_info *find_ainfo(__u64 status)
{
	struct asyc_intr_info *p_info;

	for (p_info = &ainfo[0]; p_info->status; p_info++) {
		if (p_info->status == status) {
			return p_info;
		}
	}

	return NULL;
}

static void afu_err_intr_init(struct afu *p_afu)
{
	int i;
	volatile u64 reg;

	/* global async interrupts: AFU clears afu_ctrl on context exit
	 * if async interrupts were sent to that context. This prevents
	 * the AFU form sending further async interrupts when
	 * there is
	 * nobody to receive them.
	 */

	/* mask all */
	writeq_be(-1ULL, &p_afu->afu_map->global.regs.aintr_mask);
	/* set LISN# to send and point to master context */
	reg = ((u64)(((p_afu->ctx_hndl << 8) | SISL_MSI_ASYNC_ERROR)) << 40);

	if (internal_lun)
		reg |= 1; /* Bit 63 indicates local lun */
	writeq_be(reg, &p_afu->afu_map->global.regs.afu_ctrl);
	/* clear all */
	writeq_be(-1ULL, &p_afu->afu_map->global.regs.aintr_clear);
	/* unmask bits that are of interest */
	/* note: afu can send an interrupt after this step */
	writeq_be(SISL_ASTATUS_MASK, &p_afu->afu_map->global.regs.aintr_mask);
	/* clear again in case a bit came on after previous clear but before */
	/* unmask */
	writeq_be(-1ULL, &p_afu->afu_map->global.regs.aintr_clear);

	/* Clear/Set internal lun bits */
	reg = readq_be(&p_afu->afu_map->global.fc_regs[0][FC_CONFIG2 / 8]);
	cxlflash_info("ilun p0 = %016llX", reg);
	reg &= ~(0x3ULL << 32);
	if (internal_lun)
		reg |= ((u64)(internal_lun - 1) << 32);
	cxlflash_info("ilun p0 = %016llX", reg);
	writeq_be(reg, &p_afu->afu_map->global.fc_regs[0][FC_CONFIG2 / 8]);

	/* now clear FC errors */
	for (i = 0; i < NUM_FC_PORTS; i++) {
		writeq_be(((u32) - 1),
			  &p_afu->afu_map->global.fc_regs[i][FC_ERROR / 8]);
		writeq_be(0,
			  &p_afu->afu_map->global.fc_regs[i][FC_ERRCAP / 8]);
	}

	/* sync interrupts for master's IOARRIN write */
	/* note that unlike asyncs, there can be no pending sync interrupts */
	/* at this time (this is a fresh context and master has not written */
	/* IOARRIN yet), so there is nothing to clear. */

	/* set LISN#, it is always sent to the context that wrote IOARRIN */
	writeq_be(SISL_MSI_SYNC_ERROR, &p_afu->host_map->ctx_ctrl);
	writeq_be(SISL_ISTATUS_MASK, &p_afu->host_map->intr_mask);
}

static irqreturn_t cxlflash_dummy_irq_handler(int irq, void *data)
{
	/* XXX - to be removed once we settle the 4th interrupt */
	cxlflash_info("returning rc=%d", IRQ_HANDLED);
	return IRQ_HANDLED;
}

static irqreturn_t cxlflash_sync_err_irq(int irq, void *data)
{
	struct afu *p_afu = (struct afu *)data;
	u64 reg;
	u64 reg_unmasked;

	reg = readq_be(&p_afu->host_map->intr_status);
	reg_unmasked = (reg & SISL_ISTATUS_UNMASK);

	if (reg_unmasked == 0UL) {
		cxlflash_err("%llX: spurious interrupt, intr_status %016llX",
			   (u64) p_afu, reg);
		goto cxlflash_sync_err_irq_exit;
	}

	cxlflash_err("%llX: unexpected interrupt, intr_status %016llX",
		   (u64) p_afu, reg);

	writeq_be(reg_unmasked, &p_afu->host_map->intr_clear);

cxlflash_sync_err_irq_exit:
	cxlflash_info("returning rc=%d", IRQ_HANDLED);
	return IRQ_HANDLED;
}

static irqreturn_t cxlflash_rrq_irq(int irq, void *data)
{
	struct afu *p_afu = (struct afu *)data;
	struct cxlflash *p_cxlflash;
	struct afu_cmd *p_cmd;
	unsigned long lock_flags = 0UL;

	p_cxlflash = p_afu->back;
	/*
	 * XXX - might want to look at using locals for loop control
	 * as an optimization
	 */

	/* Process however many RRQ entries that are ready */
	while ((*p_afu->hrrq_curr & SISL_RESP_HANDLE_T_BIT) == p_afu->toggle) {
		struct scsi_cmnd *scp;

		p_cmd = (struct afu_cmd *)
		    ((*p_afu->hrrq_curr) & (~SISL_RESP_HANDLE_T_BIT));

		spin_lock_irqsave(p_cmd->slock, lock_flags);
		p_cmd->sa.host_use_b[0] |= B_DONE;
		spin_unlock_irqrestore(p_cmd->slock, lock_flags);

		/* already stopped if timer fired */
		del_timer(&p_cmd->timer);

		if (p_cmd->rcb.rsvd2) {
			scp = (struct scsi_cmnd *)p_cmd->rcb.rsvd2;
			if (p_cmd->sa.rc.afu_rc || p_cmd->sa.rc.scsi_rc ||
			    p_cmd->sa.rc.fc_rc) {
				/* XXX: Needs to be decoded to report errors */
				scp->result = (DID_OK << 16);
			} else {
				scp->result = (DID_OK << 16);
			}
			cxlflash_dbg("calling scsi_set_resid, scp=0x%llx "
				   "resid=%d afu_rc=%d scsi_rc=%d fc_rc=%d",
				    p_cmd->rcb.rsvd2, p_cmd->sa.resid,
				    p_cmd->sa.rc.afu_rc, p_cmd->sa.rc.scsi_rc,
				    p_cmd->sa.rc.fc_rc);

			scsi_set_resid(scp, p_cmd->sa.resid);
			scsi_dma_unmap(scp);
			scp->scsi_done(scp);
			p_cmd->rcb.rsvd2 = 0ULL;
			if (p_cmd->special) {
				p_cxlflash->tmf_active = 0;
				wake_up_all(&p_cxlflash->tmf_wait_q);
			}
		}

		/* Done with command */
		cmd_checkin(p_cmd);

		/* Advance to next entry or wrap and flip the toggle bit */
		if (p_afu->hrrq_curr < p_afu->hrrq_end) {
			p_afu->hrrq_curr++;
		} else {
			p_afu->hrrq_curr = p_afu->hrrq_start;
			p_afu->toggle ^= SISL_RESP_HANDLE_T_BIT;
		}
	}

	return IRQ_HANDLED;
}

static irqreturn_t cxlflash_async_err_irq(int irq, void *data)
{
	struct afu *p_afu = (struct afu *)data;
	struct cxlflash *p_cxlflash;
	__u64 reg_unmasked;
	struct asyc_intr_info *p_info;
	volatile struct sisl_global_map *p_global = &p_afu->afu_map->global;
	__u64 reg;
	int i;

	p_cxlflash = p_afu->back;

	reg = readq_be(&p_global->regs.aintr_status);
	reg_unmasked = (reg & SISL_ASTATUS_UNMASK);

	if (reg_unmasked == 0) {
		cxlflash_err("spurious interrupt, aintr_status 0x%016llx", reg);
		goto out;
	}

	/* it is OK to clear AFU status before FC_ERROR */
	writeq_be(reg_unmasked, &p_global->regs.aintr_clear);

	/* check each bit that is on */
	for (i = 0; reg_unmasked; i++, reg_unmasked = (reg_unmasked >> 1)) {
		if ((reg_unmasked & 0x1) == 0 ||
		    (p_info = find_ainfo(1ull << i)) == NULL) {
			continue;
		}

		cxlflash_err("%s, fc_status 0x%08llx", p_info->desc,
			   readq_be(&p_global->fc_regs
				   [p_info->port][FC_STATUS/8]));

		// do link reset first, some OTHER errors will set FC_ERROR 
		// again if cleared before or w/o a reset

		if (p_info->action & LINK_RESET) {
			cxlflash_err("fc %d: resetting link", p_info->port);
			p_cxlflash->lr_state = LINK_RESET_REQUIRED;
			p_cxlflash->lr_port = p_info->port;
			schedule_work(&p_cxlflash->work_q);
		}

		if (p_info->action & CLR_FC_ERROR) {
			reg = readq_be(&p_global->fc_regs[p_info->port]
				      [FC_ERROR/8]);

			// since all errors are unmasked, FC_ERROR and FC_ERRCAP
			// should be the same and tracing one is sufficient. 

			cxlflash_err("fc %d: clearing fc_error 0x%08llx",
				   p_info->port, reg);

			writeq_be(reg,
				  &p_global->fc_regs[p_info->port][FC_ERROR/8]);
			writeq_be(0,
				 &p_global->fc_regs[p_info->port][FC_ERRCAP/8]);
		}
	}

out:
	cxlflash_info("returning rc=%d, afu=%p", IRQ_HANDLED, p_afu);
	return IRQ_HANDLED;
}

/*
 * Start the afu context.  This is calling into the generic CXL driver code
 * (except for the contents of the WED).
 */
int cxlflash_start_context(struct cxlflash *p_cxlflash)
{
	int rc = 0;

	rc = cxl_start_context(p_cxlflash->mcctx,
			       p_cxlflash->afu->work.work_element_descriptor,
			       NULL);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_read_vpd - Read the Vital Product Data on the Card.
 * @p_cxlflash:       struct cxlflash
 *
 * Read and parse the VPD
 *
 * Return value:
 *      WWPN for each port
 **/
int cxlflash_read_vpd(struct cxlflash *p_cxlflash, u64 wwpn[])
{
	struct pci_dev *dev = p_cxlflash->parent_dev;
	int rc = 0;
	int ro_start, ro_size, i, j, k;
	ssize_t vpd_size;
	char vpd_data[CXLFLASH_VPD_LEN];
	char tmp_buf[WWPN_BUF_LEN] = { 0 };
	char *wwpn_vpd_tags[NUM_FC_PORTS] = { "V5", "V6" };

	/* Get the VPD data from the device */
	vpd_size = pci_read_vpd(dev, 0, sizeof(vpd_data), vpd_data);
	if (unlikely(vpd_size <= 0)) {
		cxlflash_err("Unable to read VPD (size = %ld)", vpd_size);
		rc = -ENODEV;
		goto out;
	}

	/* Get the read only section offset */
        ro_start = pci_vpd_find_tag(vpd_data, 0, vpd_size,
				    PCI_VPD_LRDT_RO_DATA);
        if (unlikely(ro_start < 0)) {
		cxlflash_err("VPD Read-only not found");
		rc = -ENODEV;
		goto out;
        }

	/* Get the read only section size, cap when extends beyond read VPD */
        ro_size = pci_vpd_lrdt_size(&vpd_data[ro_start]);
	j = ro_size;
	i = ro_start + PCI_VPD_LRDT_TAG_SIZE;
	if (unlikely((i + j) > vpd_size))
	{
		cxlflash_warn("Might need to read more VPD (%d > %ld)",
			    (i + j), vpd_size);
		ro_size = vpd_size - i;
	}

	/*
	 * Find the offset of the WWPN tag within the read only
	 * VPD data and validate the found field (partials are
	 * no good to us). Convert the ASCII data to an integer
	 * value. Note that we must copy to a temporary buffer
	 * because the conversion service requires that the ASCII
	 * string be terminated.
	 */
	for (k = 0; k < NUM_FC_PORTS; k++) {
		j = ro_size;
		i = ro_start + PCI_VPD_LRDT_TAG_SIZE;

		i = pci_vpd_find_info_keyword(vpd_data, i, j, wwpn_vpd_tags[k]);
		if (unlikely(i < 0)) {
			cxlflash_err("Port %d WWPN not found in VPD", k);
			rc = -ENODEV;
			goto out;
		}

		j = pci_vpd_info_field_size(&vpd_data[i]);
		i += PCI_VPD_INFO_FLD_HDR_SIZE;
		if (unlikely((i + j > vpd_size) || (j != WWPN_LEN))) {
			cxlflash_err("Port %d WWPN incomplete or VPD corrupt", k);
			rc = -ENODEV;
			goto out;
		}

		memcpy(tmp_buf, &vpd_data[i], WWPN_LEN);
		rc = kstrtoul(tmp_buf, WWPN_LEN, (unsigned long *)&wwpn[k]);
		if (unlikely(rc)) {
			cxlflash_err("Unable to convert port 0 WWPN to integer");
			rc = -ENODEV;
			goto out;
		}
	}

out:
	cxlflash_dbg("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_context_reset - perform a context reset
 * @p_afu:        struct afu pointer
 *
 * Returns:
 *      NONE
 */
void cxlflash_context_reset(struct afu *p_afu)
{
	int nretry = 0;
	u64 rrin = 0x1;

	cxlflash_info("p_afu=%p", p_afu);

	if (p_afu->room == 0) {
		do {
			p_afu->room = readq_be(&p_afu->host_map->cmd_room);
			udelay(nretry);
		} while ((p_afu->room == 0) && (nretry++ < MC_ROOM_RETRY_CNT));
	}

	if (p_afu->room) {
		writeq_be((u64)rrin, &p_afu->host_map->ioarrin);
		do {
			rrin = readq_be(&p_afu->host_map->ioarrin);
			/* Double delay each time */
			udelay(2^nretry);
		} while ((rrin == 0x1) && (nretry++ < MC_ROOM_RETRY_CNT));
	}
	else
		cxlflash_err("no cmd_room to send reset");
}


/**
 * init_pcr - Initialize the Provisioning and Control Registers.
 * @p_cxlflash:        struct cxlflash pointer
 *
 * Returns:
 *      NONE
 */
void init_pcr(struct cxlflash *p_cxlflash)
{
	struct afu *p_afu = p_cxlflash->afu;
	int i;

	for (i = 0; i < MAX_CONTEXT; i++) {
		p_afu->ctx_info[i].ctrl_map = &p_afu->afu_map->ctrls[i].ctrl;
		/* disrupt any clients that could be running */
		/* e. g. clients that survived a master restart */
		writeq_be(0, &p_afu->ctx_info[i].ctrl_map->rht_start);
		writeq_be(0, &p_afu->ctx_info[i].ctrl_map->rht_cnt_id);
		writeq_be(0, &p_afu->ctx_info[i].ctrl_map->ctx_cap);
	}

	/* copy frequently used fields into p_afu */
	p_afu->ctx_hndl = (u16) cxl_process_element(p_cxlflash->mcctx);
	/* ctx_hndl is 16 bits in CAIA */
	p_afu->host_map = &p_afu->afu_map->hosts[p_afu->ctx_hndl].host;
	p_afu->ctrl_map = &p_afu->afu_map->ctrls[p_afu->ctx_hndl].ctrl;

	/* initialize cmd fields that never change */
	for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
		p_afu->cmd[i].rcb.ctx_id = p_afu->ctx_hndl;
		p_afu->cmd[i].rcb.msi = SISL_MSI_RRQ_UPDATED;
		p_afu->cmd[i].rcb.rrq = 0x0;
	}

}

/**
 * init_global - Initialize the AFU Global Registers
 * @p_cxlflash:        struct cxlflash pointer
 *
 * Returns:
 *      NONE
 */
int init_global(struct cxlflash *p_cxlflash)
{
	struct afu *p_afu = p_cxlflash->afu;
	u64 wwpn[NUM_FC_PORTS];	/* wwpn of AFU ports */
	int i = 0;
	int rc = 0;
	u64 reg;

	rc = cxlflash_read_vpd(p_cxlflash, &wwpn[0]);
	if (rc) {
		cxlflash_err("could not read vpd rc=%d", rc);
		goto out;
	}
	cxlflash_info("wwpn0=0x%llx wwpn1=0x%llx", wwpn[0], wwpn[1]);

	/* set up RRQ in AFU for master issued cmds */
	writeq_be((u64)p_afu->hrrq_start, &p_afu->host_map->rrq_start);
	writeq_be((u64)p_afu->hrrq_end, &p_afu->host_map->rrq_end);

	/* AFU configuration */
	reg = readq_be(&p_afu->afu_map->global.regs.afu_config);
	reg |= 0x7F20; /* enable all auto retry options and LE */
	/* leave others at default: */
	/* CTX_CAP write protected, mbox_r does not clear on read and */
	/* checker on if dual afu */
	writeq_be(reg, &p_afu->afu_map->global.regs.afu_config);

	/* global port select: select either port */
#if 0   /* XXX - check with Andy/Todd b/c this doesn't work */
	if (internal_lun)
		writeq_be(0x1, &p_afu->afu_map->global.regs.afu_port_sel);
	else
#endif
		writeq_be(0x3, &p_afu->afu_map->global.regs.afu_port_sel);

	for (i = 0; i < NUM_FC_PORTS; i++) {
		/* unmask all errors (but they are still masked at AFU) */
		writeq_be(0,
			  &p_afu->afu_map->global.fc_regs[i][FC_ERRMSK / 8]);
		/* clear CRC error cnt & set a threshold */
		(void)readq_be(&p_afu->afu_map->
			      global.fc_regs[i][FC_CNT_CRCERR / 8]);
		writeq_be(MC_CRC_THRESH,
			  &p_afu->afu_map->global.fc_regs[i]
			  [FC_CRC_THRESH / 8]);

		/* set WWPNs. If already programmed, wwpn[i] is 0 */
		if (wwpn[i] != 0 &&
		    afu_set_wwpn(p_afu, i,
				 &p_afu->afu_map->global.fc_regs[i][0],
				 wwpn[i])) {
			cxlflash_dbg("failed to set WWPN on port %d", i);
			rc = -EIO;
			goto out;
		}

	}

	/* set up master's own CTX_CAP to allow real mode, host translation */
	/* tbls, afu cmds and read/write GSCSI cmds. */
	/* First, unlock ctx_cap write by reading mbox */
	(void)readq_be(&p_afu->ctrl_map->mbox_r);	/* unlock ctx_cap */
	writeq_be((SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE |
		  SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD |
		  SISL_CTX_CAP_AFU_CMD | SISL_CTX_CAP_GSCSI_CMD),
		  &p_afu->ctrl_map->ctx_cap);
	/* init heartbeat */
	p_afu->hb = readq_be(&p_afu->afu_map->global.regs.afu_hb);

out:
	return rc;
}

/**
 * cxlflash_start_afu - Start the AFU, in a pristine state
 * @p_cxlflash:        struct cxlflash pointer
 *
 * Returns:
 *      NONE
 */
int cxlflash_start_afu(struct cxlflash *p_cxlflash)
{
	struct afu *p_afu = p_cxlflash->afu;

	int i = 0;
	int rc = 0;

	for (i = 0; i < MAX_CONTEXT; i++) {
		p_afu->rht_info[i].rht_start = &p_afu->rht[i][0];
	}

	for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
		struct timer_list *p_timer = &p_afu->cmd[i].timer;

		init_timer(p_timer);
		p_timer->data = (unsigned long)p_afu;
		p_timer->function = (void (*)(unsigned long))
			cxlflash_context_reset;

		spin_lock_init(&p_afu->cmd[i]._slock);
		p_afu->cmd[i].slock = &p_afu->cmd[i]._slock;
	}
	init_pcr(p_cxlflash);

	/* initialize RRQ pointers */
	p_afu->hrrq_start = &p_afu->rrq_entry[0];
	p_afu->hrrq_end = &p_afu->rrq_entry[NUM_RRQ_ENTRY - 1];
	p_afu->hrrq_curr = p_afu->hrrq_start;
	p_afu->toggle = 1;

	rc = init_global(p_cxlflash);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}
/**
 * cxlflash_init_mc - setup the master context
 * @p_cxlflash:        struct cxlflash pointer
 *
 * Returns:
 *      NONE
 */
int cxlflash_init_mc(struct cxlflash *p_cxlflash)
{
	struct cxl_context *ctx;
	struct device *dev = &p_cxlflash->dev->dev;
	struct afu *p_afu = p_cxlflash->afu;
	int rc = 0;
	enum undo_level level;

	ctx = cxl_dev_context_init(p_cxlflash->dev);
	if (!ctx)
		return -ENOMEM;
	p_cxlflash->mcctx = ctx;

	/* Set it up as a master with the CXL */
	cxl_set_master(ctx);

	/* During initialization reset the AFU to start from a clean slate */
	rc = cxl_afu_reset(p_cxlflash->mcctx);
	if (rc) {
		cxlflash_dev_err(dev, "initial AFU reset failed rc=%d", rc);
		level =  RELEASE_CONTEXT;
		goto out;
	}

	/* Allocate AFU generated interrupt handler */
	rc = cxl_allocate_afu_irqs(ctx, 4);
	if (rc) {
		cxlflash_dev_err(dev, "call to allocate_afu_irqs failed rc=%d!",
			       rc);
		level =  RELEASE_CONTEXT;
		goto out;
	}

	/* Register AFU interrupt 1 (SISL_MSI_SYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 1, cxlflash_sync_err_irq, p_afu,
			     "SISL_MSI_SYNC_ERROR");
	if (!rc) {
		cxlflash_dev_err(dev,
			       "IRQ 1 (SISL_MSI_SYNC_ERROR) map failed!");
		level =  FREE_IRQ;
		goto out;
	}
	/* Register AFU interrupt 2 (SISL_MSI_RRQ_UPDATED) */
	rc = cxl_map_afu_irq(ctx, 2, cxlflash_rrq_irq, p_afu,
			     "SISL_MSI_RRQ_UPDATED");
	if (!rc) {
		cxlflash_dev_err(dev,
			       "IRQ 2 (SISL_MSI_RRQ_UPDATED) map failed!");
		level = UNMAP_ONE;
		goto out;
	}
	/* Register AFU interrupt 3 (SISL_MSI_ASYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 3, cxlflash_async_err_irq, p_afu,
			     "SISL_MSI_ASYNC_ERROR");
	if (!rc) {
		cxlflash_dev_err(dev,
			       "IRQ 3 (SISL_MSI_ASYNC_ERROR) map failed!");
		level = UNMAP_TWO;
		goto out;
	}

	/*
	 * XXX - why did we put a 4th interrupt? Were we thinking this is
	 * for the SISL_MSI_PSL_XLATE? Wouldn't that be covered under the
	 * cxl_register_error_irq() ?
	 */

	/* Register AFU interrupt 4 for errors. */
	rc = cxl_map_afu_irq(ctx, 4, cxlflash_dummy_irq_handler, p_afu, "err3");
	if (!rc) {
		cxlflash_dev_err(dev, "IRQ 4 map failed!");
		level = UNMAP_THREE;
		goto out;
	}
	rc = 0;

	/* Register for PSL errors. TODO: implement this */
	/* cxl_register_error_irq(dev,... ,callback function, private data); */

	/* This performs the equivalent of the CXL_IOCTL_START_WORK.
	 * The CXL_IOCTL_GET_PROCESS_ELEMENT is implicit in the process
	 * element (pe) that is embedded in the context (ctx)
	 */
	cxlflash_start_context(p_cxlflash);
ret:
	cxlflash_info("returning rc=%d", rc);
	return rc;
out:
	cxlflash_term_mc(p_cxlflash, level);
	goto ret;
}


static int cxlflash_init_afu(struct cxlflash *p_cxlflash)
{
	u64 reg;
	int rc = 0;
	struct afu *p_afu = p_cxlflash->afu;
	struct device *dev = &p_cxlflash->dev->dev;

	rc = cxlflash_init_mc(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(dev, "call to init_mc failed, rc=%d!", rc);
		goto err1;
	}

	INIT_LIST_HEAD(&p_afu->luns);

	/* Map the entire MMIO space of the AFU.
	 */
	p_afu->afu_map = cxl_psa_map(p_cxlflash->mcctx);
	if (!p_afu->afu_map) {
		rc = -ENOMEM;
		cxlflash_term_mc(p_cxlflash, UNDO_START);
		cxlflash_dev_err(dev, "call to cxl_psa_map failed!");
		goto err1;
	}


	/* don't byte reverse on reading afu_version, else the string form */
	/*     will be backwards */
	reg = p_afu->afu_map->global.regs.afu_version;
	memcpy(p_afu->version, &reg, 8);
	p_afu->interface_version = readq_be(&p_afu->afu_map->
					   global.regs.interface_version);
	cxlflash_info("afu version %s, interface version 0x%llx",
		    p_afu->version, p_afu->interface_version);

	rc = cxlflash_start_afu(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(dev, "call to start_afu failed, rc=%d!", rc);
		cxlflash_term_mc(p_cxlflash, UNDO_START);
		cxl_psa_unmap((void *)p_afu->afu_map);
		p_afu->afu_map = NULL;
	}

	/* XXX: Add threads for afu_rrq_rx and afu_err_rx */
	/* after creating afu_err_rx thread, unmask error interrupts */
	afu_err_intr_init(p_cxlflash->afu);

err1:
	cxlflash_info("returning rc=%d", rc);
	return rc;
}


/* do we need to retry AFU_CMDs (sync) on afu_rc = 0x30 ? */
/* can we not avoid that ? */
/* not retrying afu timeouts (B_TIMEOUT) */
/* returns 1 if the cmd should be retried, 0 otherwise */
/* sets B_ERROR flag based on IOASA */
int check_status(struct sisl_ioasa_s *p_ioasa)
{
	if (p_ioasa->ioasc == 0)
		return 0;

	p_ioasa->host_use_b[0] |= B_ERROR;

	if (!(p_ioasa->host_use_b[1]++ < MC_RETRY_CNT))
		return 0;

	switch (p_ioasa->rc.afu_rc) {
	case SISL_AFU_RC_NO_CHANNELS:
	case SISL_AFU_RC_OUT_OF_DATA_BUFS:
		msleep(1);	/* 1 msec */
		return 1;

	case 0:
		/* no afu_rc, but either scsi_rc and/or fc_rc is set */
		/* retry all scsi_rc and fc_rc after a small delay */
		msleep(1);	/* 1 msec */
		return 1;
	}

	return 0;
}

void cxlflash_send_cmd(struct afu *p_afu, struct afu_cmd *p_cmd)
{
	int nretry = 0;

	if (p_afu->room == 0) {
		do {
			p_afu->room = readq_be(&p_afu->host_map->cmd_room);
			udelay(nretry);
		} while ((p_afu->room == 0) && (nretry++ < MC_ROOM_RETRY_CNT));
	}

	p_cmd->sa.host_use_b[0] = 0;	/* 0 means active */
	p_cmd->sa.ioasc = 0;

	/* make memory updates visible to AFU before MMIO */
	smp_wmb();

	p_cmd->timer.expires = (jiffies + (p_cmd->rcb.timeout * 2 * HZ));
	add_timer(&p_cmd->timer);

	/* Write IOARRIN */
	if (p_afu->room)
		writeq_be((u64)&p_cmd->rcb, &p_afu->host_map->ioarrin);
	else
		cxlflash_err("no cmd_room to send 0x%X", p_cmd->rcb.cdb[0]);

	cxlflash_dbg("p_cmd=%p len=%d ea=%p", p_cmd, p_cmd->rcb.data_len,
		    (void *)p_cmd->rcb.data_ea);

	/* Let timer fire to complete the response... */
}

void cxlflash_wait_resp(struct afu *p_afu, struct afu_cmd *p_cmd)
{
	unsigned long lock_flags = 0;

	spin_lock_irqsave(p_cmd->slock, lock_flags);
	while (!(p_cmd->sa.host_use_b[0] & B_DONE)) {
		spin_unlock_irqrestore(p_cmd->slock, lock_flags);
		udelay(10);
		spin_lock_irqsave(p_cmd->slock, lock_flags);
	}
	spin_unlock_irqrestore(p_cmd->slock, lock_flags);

	del_timer(&p_cmd->timer); /* already stopped if timer fired */

	if (p_cmd->sa.ioasc != 0)
		cxlflash_err("CMD 0x%x failed, IOASC: flags 0x%x, afu_rc 0x%x, "
			   "scsi_rc 0x%x, fc_rc 0x%x",
			   p_cmd->rcb.cdb[0],
			   p_cmd->sa.rc.flags,
			   p_cmd->sa.rc.afu_rc,
			   p_cmd->sa.rc.scsi_rc, p_cmd->sa.rc.fc_rc);
}

/*
 * afu_sync can be called from interrupt thread and the main processing
 * thread. Caller is responsible for any serialization.
 * Also, it can be called even before/during discovery, so we must use
 * a dedicated cmd not used by discovery.
 *
 * AFU takes only 1 sync cmd at a time.
 */
int afu_sync(struct afu *p_afu,
	     ctx_hndl_t ctx_hndl_u, res_hndl_t res_hndl_u, u8 mode)
{
	u16 *p_u16;
	u32 *p_u32;
	struct afu_cmd *p_cmd = &p_afu->cmd[AFU_SYNC_INDEX];
	int rc = 0;

	cxlflash_info("p_afu=%p p_cmd=%p %d", p_afu, p_cmd, ctx_hndl_u);

	memset(p_cmd->rcb.cdb, 0, sizeof(p_cmd->rcb.cdb));

	p_cmd->rcb.req_flags = SISL_REQ_FLAGS_AFU_CMD;
	p_cmd->rcb.port_sel = 0x0;	/* NA */
	p_cmd->rcb.lun_id = 0x0;	/* NA */
	p_cmd->rcb.data_len = 0x0;
	p_cmd->rcb.data_ea = 0x0;
	p_cmd->rcb.timeout = MC_AFU_SYNC_TIMEOUT;

	p_cmd->rcb.cdb[0] = 0xC0;	/* AFU Sync */
	p_cmd->rcb.cdb[1] = mode;
	p_u16 = (u16 *) & p_cmd->rcb.cdb[2];
	writew_be(ctx_hndl_u, p_u16);	/* context to sync up */
	p_u32 = (u32 *) & p_cmd->rcb.cdb[4];
	writel_be(res_hndl_u, p_u32);	/* res_hndl to sync up */

	cxlflash_send_cmd(p_afu, p_cmd);
	cxlflash_wait_resp(p_afu, p_cmd);

	if ((p_cmd->sa.ioasc != 0) || (p_cmd->sa.host_use_b[0] & B_ERROR)) {
		rc = -1;
		/* B_ERROR is set on timeout */
	}

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

int afu_reset(struct cxlflash *p_cxlflash)
{
	int rc = 0;
	/* Stop the context before the reset. Since the context is
	 * no longer available restart it after the reset is complete 
	 */

	cxlflash_term_afu(p_cxlflash);

	rc = cxlflash_init_afu(p_cxlflash);

	/* XXX: Need to restart/reattach all user contexts */
	cxlflash_info("returning rc=%d", rc);
	return rc;
}


/**
 * cxlflash_worker_thread - Worker thread
 * @work:               work queue pointer
 *
 * Called at task level from a work thread. This function takes care
 * of adding and removing device from the mid-layer as configuration
 * changes are detected by the adapter.
 *
 * Return value:
 *      nothing
 **/
static void cxlflash_worker_thread(struct work_struct *work)
{
        struct cxlflash *p_cxlflash =
                container_of(work, struct cxlflash, work_q);
	struct afu *p_afu = p_cxlflash->afu;
	int port;
	unsigned long lock_flags;

	spin_lock_irqsave(p_cxlflash->host->host_lock, lock_flags);

	if (p_cxlflash->lr_state == LINK_RESET_REQUIRED) {
		port = p_cxlflash->lr_port;
		if (port < 0)
			cxlflash_err("invalid port index %d", port);
		else
			afu_link_reset(p_afu, port, &p_afu->afu_map->global.
				       fc_regs[port][0]);
		p_cxlflash->lr_state = LINK_RESET_COMPLETE;
	}

	spin_unlock_irqrestore(p_cxlflash->host->host_lock, lock_flags);
}

/**
 * cxlflash_probe - Adapter hot plug add entry point
 * @pdev:       pci device struct
 * @dev_id:     pci device id
 *
 * Return value:
 *      0 on success / non-zero on failure
 **/
static int cxlflash_probe(struct pci_dev *pdev,
			const struct pci_device_id *dev_id)
{
	struct Scsi_Host *host;
	struct cxlflash *p_cxlflash = NULL;
	struct device *phys_dev;
	struct dev_dependent_vals *p_ddv;
	int rc = 0;

	cxlflash_dev_dbg(&pdev->dev, "Found CXLFLASH with IRQ: %d", pdev->irq);

	if (fullqc)
		driver_template.scan_finished = NULL;

	p_ddv = (struct dev_dependent_vals *)dev_id->driver_data;
	driver_template.max_sectors = p_ddv->max_sectors;

	host = scsi_host_alloc(&driver_template, sizeof(struct cxlflash));
	if (!host) {
		cxlflash_dev_err(&pdev->dev, "call to scsi_host_alloc failed!");
		rc = -ENOMEM;
		goto out;
	}

	host->max_id = CXLFLASH_MAX_NUM_TARGETS_PER_BUS;
	host->max_lun = CXLFLASH_MAX_NUM_LUNS_PER_TARGET;
	host->max_channel =  NUM_FC_PORTS-1;
	host->unique_id = host->host_no;
	host->max_cmd_len = CXLFLASH_MAX_CDB_LEN;

	p_cxlflash = (struct cxlflash *)host->hostdata;
	p_cxlflash->host = host;
	rc = cxlflash_gb_alloc(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev, "call to scsi_host_alloc failed!");
		rc = -ENOMEM;
		goto out;
	}

	p_cxlflash->dev = pdev;
	p_cxlflash->last_lun_index = 0;
	p_cxlflash->task_set = 0;
	p_cxlflash->dev_id = (struct pci_device_id *)dev_id;
	p_cxlflash->tmf_active = 0;
	p_cxlflash->mcctx = NULL;
	p_cxlflash->context_reset_active = 0;
	p_cxlflash->num_user_contexts = 0;

	init_waitqueue_head(&p_cxlflash->tmf_wait_q);
	init_waitqueue_head(&p_cxlflash->eeh_wait_q);

	INIT_WORK(&p_cxlflash->work_q, cxlflash_worker_thread);
	p_cxlflash->lr_state = LINK_RESET_INVALID;
	p_cxlflash->lr_port = -1;

	pci_set_drvdata(pdev, p_cxlflash);

	/* Use the special service provided to look up the physical
	 * PCI device, since we are called on the probe of the virtual
	 * PCI host bus (vphb)
	 */
	phys_dev = cxl_get_phys_dev(pdev);
	if (!dev_is_pci(phys_dev)) {	/* make sure it's pci */
		cxlflash_err("not a pci dev");
		rc = ENODEV;
		goto out_remove;
	}
	p_cxlflash->parent_dev = to_pci_dev(phys_dev);

	p_cxlflash->cxl_afu = cxl_pci_to_afu(pdev, NULL);
	rc = cxlflash_init_afu(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
			       "call to cxlflash_init_afu failed rc=%d!", rc);
		goto out_remove;
	}

	rc = cxlflash_init_pci(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
			       "call to cxlflash_init_pci failed rc=%d!", rc);
		goto out_remove;
	}

	rc = cxlflash_init_scsi(p_cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
			"call to cxlflash_init_scsi failed rc=%d!", rc);
		goto out_remove;
	}

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;

out_remove:
	cxlflash_remove(pdev);
	goto out;
}

static struct pci_driver cxlflash_driver = {
	.name = CXLFLASH_NAME,
	.id_table = cxlflash_pci_table,
	.probe = cxlflash_probe,
	.remove = cxlflash_remove,
};

static int __init init_cxlflash(void)
{
	cxlflash_info("IBM Power CXL Flash Adapter version: %s %s",
		    CXLFLASH_DRIVER_VERSION, CXLFLASH_DRIVER_DATE);

	/* Validate module parameters */
	if (internal_lun > 4) {
		cxlflash_err("Invalid lun_mode parameter! (%d > 4)",
			   internal_lun);
		return(-EINVAL);
	}

	return pci_register_driver(&cxlflash_driver);
}

static void exit_cxlflash(void)
{
	pci_unregister_driver(&cxlflash_driver);
}

module_init(init_cxlflash);
module_exit(exit_cxlflash);
