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
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>

#include <asm/unaligned.h>

#include <misc/cxl.h>

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>

#include "main.h"
#include "sislite.h"
#include "common.h"

MODULE_DESCRIPTION(CXLFLASH_ADAPTER_NAME);
MODULE_AUTHOR("Manoj N. Kumar <manoj@linux.vnet.ibm.com>");
MODULE_AUTHOR("Matthew R. Ochs <mrochs@linux.vnet.ibm.com>");
MODULE_LICENSE("GPL");

struct cxlflash_global global;

/**
 * cxlflash_cmd_checkout() - checks out an AFU command
 * @afu:	AFU to checkout from.
 *
 * Commands are checked out in a round-robin fashion. The buffer and
 * CDB within the command are initialized (zeroed) prior to returning.
 *
 * Return: The checked out command or NULL when command pool is empty.
 */
struct afu_cmd *cxlflash_cmd_checkout(struct afu *afu)
{
	int k, dec = CXLFLASH_NUM_CMDS;
	struct afu_cmd *cmd;

	while (dec--) {
		k = (afu->cmd_couts++ & (CXLFLASH_NUM_CMDS - 1));

		cmd = &afu->cmd[k];

		if (!atomic_dec_if_positive(&cmd->free)) {
			cxlflash_dbg("returning found index=%d", cmd->slot);
			memset(cmd->buf, 0, CMD_BUFSIZE);
			memset(cmd->rcb.cdb, 0, sizeof(cmd->rcb.cdb));
			return cmd;
		}
	}

	return NULL;
}

/**
 * cxlflash_cmd_checkin() - checks in an AFU command
 * @cmd:	AFU command to checkin.
 *
 * Safe to pass commands that have already been checked in. Several
 * internal tracking fields are reset as part of the checkin.
 */
void cxlflash_cmd_checkin(struct afu_cmd *cmd)
{
	if (unlikely(atomic_inc_return(&cmd->free) != 1)) {
		cxlflash_err("Freeing cmd (%d) that is not in use!", cmd->slot);
		return;
	}

	cmd->special = 0;
	cmd->internal = false;
	cmd->sync = false;
	cmd->rcb.timeout = 0;

	cxlflash_dbg("releasing cmd index=%d", cmd->slot);
}

/**
 * process_cmd_err() - command error handler
 * @cmd:	AFU command that experienced the error.
 * @scp:	SCSI command associated with the AFU command in error.
 *
 * Translates error bits from AFU command to SCSI command results.
 */
static void process_cmd_err(struct afu_cmd *cmd, struct scsi_cmnd *scp)
{
	struct sisl_ioarcb *ioarcb;
	struct sisl_ioasa *ioasa;

	if (unlikely(!cmd))
		return;

	ioarcb = &(cmd->rcb);
	ioasa = &(cmd->sa);

	if (ioasa->rc.flags & SISL_RC_FLAGS_UNDERRUN) {
		cxlflash_dbg("cmd underrun cmd = %p scp = %p", cmd, scp);
		scp->result = (DID_ERROR << 16);
	}

	if (ioasa->rc.flags & SISL_RC_FLAGS_OVERRUN) {
		cxlflash_dbg("cmd underrun cmd = %p scp = %p", cmd, scp);
		scp->result = (DID_ERROR << 16);
	}

	cxlflash_dbg("cmd failed afu_rc=%d scsi_rc=%d fc_rc=%d "
		     "afu_extra=0x%x, scsi_entra=0x%x, fc_extra=0x%x",
		     ioasa->rc.afu_rc, ioasa->rc.scsi_rc, ioasa->rc.fc_rc,
		     ioasa->afu_extra, ioasa->scsi_extra, ioasa->fc_extra);

	if (ioasa->rc.scsi_rc) {
		/* We have a SCSI status */
		if (ioasa->rc.flags & SISL_RC_FLAGS_SENSE_VALID)
			memcpy(scp->sense_buffer, ioasa->sense_data,
			       SISL_SENSE_DATA_LEN);
		scp->result = ioasa->rc.scsi_rc | (DID_ERROR << 16);
	}

	/*
	 * We encountered an error. For now return
	 * EIO for all errors.
	 */
	if (ioasa->rc.fc_rc) {
		/* We have an FC status */
		switch (ioasa->rc.fc_rc) {
		case SISL_FC_RC_RESIDERR:
			/* Resid mismatch between adapter and device */
		case SISL_FC_RC_TGTABORT:
		case SISL_FC_RC_ABORTOK:
		case SISL_FC_RC_ABORTFAIL:
		case SISL_FC_RC_LINKDOWN:
		case SISL_FC_RC_NOLOGI:
		case SISL_FC_RC_ABORTPEND:
			scp->result = (DID_IMM_RETRY << 16);
			break;
		case SISL_FC_RC_RESID:
			/* This indicates an FCP resid underrun */
			if (!(ioasa->rc.flags & SISL_RC_FLAGS_OVERRUN)) {
				/* If the SISL_RC_FLAGS_OVERRUN flag was set,
				 * then we will handle this error else where.
				 * If not then we must handle it here.
				 * This is probably an AFU bug. We will
				 * attempt a retry to see if that resolves it.
				 */
				scp->result = (DID_IMM_RETRY << 16);
			}
			break;
		case SISL_FC_RC_WRABORTPEND:
		case SISL_FC_RC_NOEXP:
		case SISL_FC_RC_INUSE:
			scp->result = (DID_ERROR << 16);
			break;
		}
	}

	if (ioasa->rc.afu_rc) {
		/* We have an AFU error */
		switch (ioasa->rc.afu_rc) {
		case SISL_AFU_RC_NO_CHANNELS:
			scp->result = (DID_MEDIUM_ERROR << 16);
			break;
		case SISL_AFU_RC_DATA_DMA_ERR:
			switch (ioasa->afu_extra) {
			case SISL_AFU_DMA_ERR_PAGE_IN:
				/* Retry */
				scp->result = (DID_IMM_RETRY << 16);
				break;
			case SISL_AFU_DMA_ERR_INVALID_EA:
			default:
				scp->result = (DID_ERROR << 16);
			}
			break;
		case SISL_AFU_RC_OUT_OF_DATA_BUFS:
			/* Retry */
			scp->result = (DID_ALLOC_FAILURE << 16);
			break;
		default:
			scp->result = (DID_ERROR << 16);
		}
	}

	return;
}

/**
 * cmd_complete() - command completion handler
 * @cmd:	AFU command that has completed.
 *
 * Prepares and submits command that has either completed or timed out to
 * the SCSI stack. Checks AFU command back into command pool.
 */
static void cmd_complete(struct afu_cmd *cmd)
{
	unsigned long lock_flags = 0UL;
	struct scsi_cmnd *scp;
	struct afu *afu = cmd->back;
	struct cxlflash *cxlflash = afu->back;

	spin_lock_irqsave(&cmd->slock, lock_flags);
	cmd->sa.host_use_b[0] |= B_DONE;
	spin_unlock_irqrestore(&cmd->slock, lock_flags);

	/* already stopped if timer fired */
	del_timer(&cmd->timer);

	if (cmd->rcb.scp) {
		scp = cmd->rcb.scp;
		if (cmd->sa.rc.afu_rc || cmd->sa.rc.scsi_rc ||
		    cmd->sa.rc.fc_rc)
			process_cmd_err(cmd, scp);
		else
			scp->result = (DID_OK << 16);

		cxlflash_dbg("calling scsi_set_resid, scp=%p "
			     "result=%x resid=%d",
			     cmd->rcb.scp, scp->result, cmd->sa.resid);

		scsi_set_resid(scp, cmd->sa.resid);
		scsi_dma_unmap(scp);
		scp->scsi_done(scp);
		cmd->rcb.scp = NULL;
		if (cmd->special) {
			cxlflash->tmf_active = false;
			wake_up_all(&cxlflash->tmf_wait_q);
		}
	}
	if (cmd->sync) {
		cxlflash->sync_active = false;
		wake_up_all(&cxlflash->sync_wait_q);
	}

	/* Done with command */
	cxlflash_cmd_checkin(cmd);
}

/**
 * cxlflash_send_tmf() - sends a Task Management Function (TMF)
 * @afu:	AFU to checkout from.
 * @scp:	SCSI command from stack.
 * @tmfcmd:	TMF command to send.
 *
 * Return:
 *	0 on success
 *	SCSI_MLQUEUE_HOST_BUSY when host is busy
 */
int cxlflash_send_tmf(struct afu *afu, struct scsi_cmnd *scp, u64 tmfcmd)
{
	struct afu_cmd *cmd;

	u32 port_sel = scp->device->channel + 1;
	short lflag = 0;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *cxlflash = (struct cxlflash *)host->hostdata;
	int rc = 0;

	while (cxlflash->tmf_active)
		wait_event(cxlflash->tmf_wait_q, !cxlflash->tmf_active);

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		cxlflash_err("could not get a free command");
		rc = SCSI_MLQUEUE_HOST_BUSY;
		goto out;
	}

	cmd->rcb.ctx_id = afu->ctx_hndl;
	cmd->rcb.port_sel = port_sel;
	cmd->rcb.lun_id = lun_to_lunid(scp->device->lun);

	lflag = SISL_REQ_FLAGS_TMF_CMD;

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN | lflag);

	/* Stash the scp in the reserved field, for reuse during interrupt */
	cmd->rcb.scp = scp;
	cmd->special = 0x1;
	cxlflash->tmf_active = true;

	cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	/* Copy the CDB from the cmd passed in */
	memcpy(cmd->rcb.cdb, &tmfcmd, sizeof(tmfcmd));

	/* Send the command */
	rc = cxlflash_send_cmd(afu, cmd);
	if (!rc)
		wait_event(cxlflash->tmf_wait_q, !cxlflash->tmf_active);
out:
	return rc;

}

/**
 * cxlflash_driver_info() - information handler for this host driver
 * @host:	SCSI host associated with device.
 *
 * Return: A string describing the device.
 */
static const char *cxlflash_driver_info(struct Scsi_Host *host)
{
	return CXLFLASH_ADAPTER_NAME;
}

/**
 * cxlflash_queuecommand() - sends a mid-layer request
 * @host:	SCSI host associated with device.
 * @scp:	SCSI command to send.
 *
 * Return:
 *	0 on success
 *	SCSI_MLQUEUE_DEVICE_BUSY when device is busy
 *	SCSI_MLQUEUE_HOST_BUSY when host is busy
 */
static int cxlflash_queuecommand(struct Scsi_Host *host, struct scsi_cmnd *scp)
{
	struct cxlflash *cxlflash = (struct cxlflash *)host->hostdata;
	struct afu *afu = cxlflash->afu;
	struct pci_dev *pdev = cxlflash->dev;
	struct afu_cmd *cmd;
	u32 port_sel = scp->device->channel + 1;
	int nseg, i, ncount;
	struct scatterlist *sg;
	short lflag = 0;
	int rc = 0;

	cxlflash_dbg("(scp=%p) %d/%d/%d/%llu cdb=(%08x-%08x-%08x-%08x)",
		     scp, host->host_no, scp->device->channel,
		     scp->device->id, scp->device->lun,
		     get_unaligned_be32(&((u32 *)scp->cmnd)[0]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[1]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[2]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[3]));

	while (cxlflash->tmf_active)
		wait_event(cxlflash->tmf_wait_q, !cxlflash->tmf_active);

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		cxlflash_err("could not get a free command");
		rc = SCSI_MLQUEUE_HOST_BUSY;
		goto out;
	}

	cmd->rcb.ctx_id = afu->ctx_hndl;
	cmd->rcb.port_sel = port_sel;
	cmd->rcb.lun_id = lun_to_lunid(scp->device->lun);

	if (scp->sc_data_direction == DMA_TO_DEVICE)
		lflag = SISL_REQ_FLAGS_HOST_WRITE;
	else
		lflag = SISL_REQ_FLAGS_HOST_READ;

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN | lflag);

	/* Stash the scp in the reserved field, for reuse during interrupt */
	cmd->rcb.scp = scp;

	cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	nseg = scsi_dma_map(scp);
	if (unlikely(nseg < 0)) {
		cxlflash_dev_err(&pdev->dev, "Fail DMA map! nseg=%d", nseg);
		rc = SCSI_MLQUEUE_DEVICE_BUSY;
		goto out;
	}

	ncount = scsi_sg_count(scp);
	scsi_for_each_sg(scp, sg, ncount, i) {
		cmd->rcb.data_len = (sg_dma_len(sg));
		cmd->rcb.data_ea = (sg_dma_address(sg));
	}

	/* Copy the CDB from the scsi_cmnd passed in */
	memcpy(cmd->rcb.cdb, scp->cmnd, sizeof(cmd->rcb.cdb));

	/* Send the command */
	rc = cxlflash_send_cmd(afu, cmd);

out:
	return rc;
}

/**
 * cxlflash_eh_device_reset_handler() - reset a single LUN
 * @scp:	SCSI command to send.
 *
 * Return:
 *	SUCCESS as defined in scsi/scsi.h
 *	FAILED as defined in scsi/scsi.h
 */
static int cxlflash_eh_device_reset_handler(struct scsi_cmnd *scp)
{
	int rc = SUCCESS;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *cxlflash = (struct cxlflash *)host->hostdata;
	struct afu *afu = cxlflash->afu;

	cxlflash_dbg("(scp=%p) %d/%d/%d/%llu "
		     "cdb=(%08x-%08x-%08x-%08x)", scp,
		     host->host_no, scp->device->channel,
		     scp->device->id, scp->device->lun,
		     get_unaligned_be32(&((u32 *)scp->cmnd)[0]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[1]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[2]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[3]));

	scp->result = (DID_OK << 16);;
	cxlflash_send_tmf(afu, scp, TMF_LUN_RESET);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_eh_host_reset_handler() - reset the host adapter
 * @scp:	SCSI command from stack identifying host.
 *
 * Return:
 *	SUCCESS as defined in scsi/scsi.h
 *	FAILED as defined in scsi/scsi.h
 */
static int cxlflash_eh_host_reset_handler(struct scsi_cmnd *scp)
{
	int rc = SUCCESS;
	int rcr = 0;
	struct Scsi_Host *host = scp->device->host;
	struct cxlflash *cxlflash = (struct cxlflash *)host->hostdata;

	cxlflash_dbg("(scp=%p) %d/%d/%d/%llu "
		     "cdb=(%08x-%08x-%08x-%08x)", scp,
		     host->host_no, scp->device->channel,
		     scp->device->id, scp->device->lun,
		     get_unaligned_be32(&((u32 *)scp->cmnd)[0]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[1]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[2]),
		     get_unaligned_be32(&((u32 *)scp->cmnd)[3]));

	scp->result = (DID_OK << 16);;
	rcr = cxlflash_afu_reset(cxlflash);
	if (rcr == 0)
		rc = SUCCESS;
	else
		rc = FAILED;

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_slave_alloc - Allocate a per LUN structure
 * @sdev:       struct scsi_device device to configure
 *
 * Returns:
 *      0 on success / -ENOMEM when memory allocation fails
 **/
static int cxlflash_slave_alloc(struct scsi_device *sdev)
{
	int rc = 0;
	rc = cxlflash_alloc_lun(sdev);

	cxlflash_info("returning sdev %p rc=%d", sdev, rc);
	return rc;
}

/**
 * cxlflash_slave_configure - Configure the device
 * @sdev:       struct scsi_device device to configure
 *
 * Store the lun_id field, and program the LUN mapping table on the AFU.
 *
 * Returns:
 *      0
 **/
static int cxlflash_slave_configure(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;

	cxlflash_info("id = %d/%d/%d/%llu", shost->host_no, sdev->channel,
		      sdev->id, sdev->lun);

	cxlflash_init_lun(sdev);
	return 0;
}

static void cxlflash_slave_destroy(struct scsi_device *sdev)
{
	void *lun_info = (void *)sdev->hostdata;

	cxlflash_info("lun_info=%p", lun_info);

	return;
}

/**
 * cxlflash_change_queue_depth() - change the queue depth for the device
 * @sdev:	SCSI device destined for queue depth change.
 * @qdepth:	Requested queue depth value to set.
 *
 * The requested queue depth is capped to the maximum supported value.
 *
 * Return: The actual queue depth set.
 */
static int cxlflash_change_queue_depth(struct scsi_device *sdev, int qdepth)
{

	if (qdepth > CXLFLASH_MAX_CMDS_PER_LUN)
		qdepth = CXLFLASH_MAX_CMDS_PER_LUN;

	scsi_change_queue_depth(sdev, qdepth);
	return sdev->queue_depth;
}

/**
 * cxlflash_show_port_status() - queries and presents the current port status
 * @dev:	Generic device associated with the host owning the port.
 * @attr:	Device attribute representing the port.
 * @buf:	Buffer of length PAGE_SIZE to report back port status in ASCII.
 *
 * Return: The size of the ASCII string returned in @buf.
 */
static ssize_t cxlflash_show_port_status(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *afu = cxlflash->afu;

	char *disp_status;
	int rc;
	u32 port;
	u64 status;
	volatile u64 *fc_regs;

	rc = kstrtouint((attr->attr.name + 4), 10, &port);
	if (rc || (port > NUM_FC_PORTS))
		return 0;

	fc_regs = &afu->afu_map->global.fc_regs[port][0];
	status =
	    (readq_be(&fc_regs[FC_MTIP_STATUS / 8]) & FC_MTIP_STATUS_MASK);

	if (status == FC_MTIP_STATUS_ONLINE)
		disp_status = "online";
	else if (status == FC_MTIP_STATUS_OFFLINE)
		disp_status = "offline";
	else
		disp_status = "unknown";

	return snprintf(buf, PAGE_SIZE, "%s\n", disp_status);
}

/**
 * cxlflash_show_lun_mode() - presents the current LUN mode of the host
 * @dev:	Generic device associated with the host.
 * @attr:	Device attribute representing the lun mode.
 * @buf:	Buffer of length PAGE_SIZE to report back the LUN mode in ASCII.
 *
 * Return: The size of the ASCII string returned in @buf.
 */
static ssize_t cxlflash_show_lun_mode(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *afu = cxlflash->afu;

	return snprintf(buf, PAGE_SIZE, "%u\n", afu->internal_lun);
}

/**
 * cxlflash_store_lun_mode() - sets the LUN mode of the host
 * @dev:	Generic device associated with the host.
 * @attr:	Device attribute representing the lun mode.
 * @buf:	Buffer of length PAGE_SIZE containing the LUN mode in ASCII.
 * @count:	Length of data resizing in @buf.
 *
 * The CXL Flash AFU supports a dummy LUN mode where the external
 * links and storage are not required. Space on the FPGA is used
 * to create 1 or 2 small LUNs which are presented to the system
 * as if they were a normal storage device. This feature is useful
 * during development and also provides manufacturing with a way
 * to test the AFU without an actual device.
 *
 * 0 = external LUN[s] (default)
 * 1 = internal LUN (1 x 64K, 512B blocks, id 0)
 * 2 = internal LUN (1 x 64K, 4K blocks, id 0)
 * 3 = internal LUN (2 x 32K, 512B blocks, ids 0,1)
 * 4 = internal LUN (2 x 32K, 4K blocks, ids 0,1)
 * 
 * Return: The size of the ASCII string returned in @buf.
 */
static ssize_t cxlflash_store_lun_mode(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(dev);
	struct cxlflash *cxlflash = (struct cxlflash *)shost->hostdata;
	struct afu *afu = cxlflash->afu;
	int rc;
	u32 lun_mode;

	rc = kstrtouint(buf, 10, &lun_mode);
	if (!rc && (lun_mode < 5) && (lun_mode != afu->internal_lun)) {
		afu->internal_lun = lun_mode;
		cxlflash_afu_reset(cxlflash);
		scsi_scan_host(cxlflash->host);
	}

	return count;
}

/**
 * cxlflash_show_dev_mode() - presents the current mode of the device
 * @dev:	Generic device associated with the device.
 * @attr:	Device attribute representing the device mode.
 * @buf:	Buffer of length PAGE_SIZE to report back the dev mode in ASCII.
 *
 * Return: The size of the ASCII string returned in @buf.
 */
static ssize_t cxlflash_show_dev_mode(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
        struct scsi_device *sdev = to_scsi_device(dev);
	void *lun_info = (void *)sdev->hostdata;
	char *legacy = "legacy",
	     *superpipe = "superpipe";

	return snprintf(buf, PAGE_SIZE, "%s\n", lun_info ? superpipe : legacy);
}

/**
 * cxlflash_wait_for_pci_err_recovery() - wait for error recovery during probe
 * @cxlflash:	Internal structure associated with the host.
 */
static void cxlflash_wait_for_pci_err_recovery(struct cxlflash *cxlflash)
{
	struct pci_dev *pdev = cxlflash->dev;

	if (pci_channel_offline(pdev))
		wait_event_timeout(cxlflash->eeh_wait_q,
				   !pci_channel_offline(pdev),
				   CXLFLASH_PCI_ERROR_RECOVERY_TIMEOUT);
}

/*
 * Host attributes
 */
static DEVICE_ATTR(port0, S_IRUGO, cxlflash_show_port_status, NULL);
static DEVICE_ATTR(port1, S_IRUGO, cxlflash_show_port_status, NULL);
static DEVICE_ATTR(lun_mode, S_IRUGO | S_IWUSR, cxlflash_show_lun_mode,
		   cxlflash_store_lun_mode);

static struct device_attribute *cxlflash_host_attrs[] = {
	&dev_attr_port0,
	&dev_attr_port1,
	&dev_attr_lun_mode,
	NULL
};

/*
 * Device attributes
 */
static DEVICE_ATTR(mode, S_IRUGO, cxlflash_show_dev_mode, NULL);

static struct device_attribute *cxlflash_dev_attrs[] = {
	&dev_attr_mode,
	NULL
};

/*
 * Host template
 */
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
	.change_queue_depth = cxlflash_change_queue_depth,
	.cmd_per_lun = 16,
	.can_queue = CXLFLASH_MAX_CMDS,
	.this_id = -1,
	.sg_tablesize = SG_NONE,	/* No scatter gather support. */
	.max_sectors = CXLFLASH_MAX_SECTORS,
	.use_clustering = ENABLE_CLUSTERING,
	.shost_attrs = cxlflash_host_attrs,
	.sdev_attrs = cxlflash_dev_attrs,
};

/*
 * Device dependent values
 */
static struct dev_dependent_vals dev_corsa_vals = { CXLFLASH_MAX_SECTORS };

/*
 * PCI device binding table
 */
static struct pci_device_id cxlflash_pci_table[] = {
	{PCI_VENDOR_ID_IBM, PCI_DEVICE_ID_IBM_CORSA,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, (kernel_ulong_t)&dev_corsa_vals},
	{}
};

#if 0 /* Temporarily disable auto-load */
MODULE_DEVICE_TABLE(pci, cxlflash_pci_table);
#endif

/**
 * cxlflash_free_mem() - free memory associated with the AFU
 * @cxlflash:	Internal structure associated with the host.
 *
 * As part of draining the AFU command pool, the timers of each
 * command are ensured to be stopped.
 */
static void cxlflash_free_mem(struct cxlflash *cxlflash)
{
	int i;
	char *buf = NULL;
	struct afu *afu = cxlflash->afu;

	if (cxlflash->afu) {
		for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
			if (afu->cmd[i].timer.function)
				del_timer_sync(&afu->cmd[i].timer);
			buf = afu->cmd[i].buf;
			if (!((u64)buf & (PAGE_SIZE - 1)))
				free_page((unsigned long)buf);
		}

		free_pages((unsigned long)afu,
			   get_order(sizeof(struct afu)));
		cxlflash->afu = NULL;
	}

	return;
}

/**
 * cxlflash_stop_afu() - stops the AFU command timers and unmaps the MMIO space
 * @cxlflash:	Internal structure associated with the host.
 *
 * Safe to call with AFU in a partially allocated/initialized state.
 */
static void cxlflash_stop_afu(struct cxlflash *cxlflash)
{
	int i;
	struct afu *afu = cxlflash->afu;

	if (!afu) {
		cxlflash_info("returning because afu is NULl");
		return;
	}

	/* Need to stop timers before unmapping */
	for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
		if (afu->cmd[i].timer.function)
			del_timer_sync(&afu->cmd[i].timer);
	}

	if (afu->afu_map) {
		cxl_psa_unmap((void *)afu->afu_map);
		afu->afu_map = NULL;
	}
}

/**
 * cxlflash_term_mc() - terminates the master context
 * @cxlflash:	Internal structure associated with the host.
 * @level:	Depth of allocation, where to begin waterfall tear down.
 *
 * Safe to call with AFU/MC in partially allocated/initialized state.
 */
void cxlflash_term_mc(struct cxlflash *cxlflash, enum undo_level level)
{
	struct afu *afu = cxlflash->afu;

	if (!afu || !cxlflash->mcctx) {
		cxlflash_info("returning from term_mc with NULL afu or MC");
		return;
	}

	switch (level) {
	case UNDO_START:
		cxl_stop_context(cxlflash->mcctx);
	case UNMAP_THREE:
		cxlflash_info("before unmap 3");
		cxl_unmap_afu_irq(cxlflash->mcctx, 3, afu);
	case UNMAP_TWO:
		cxlflash_info("before unmap 2");
		cxl_unmap_afu_irq(cxlflash->mcctx, 2, afu);
	case UNMAP_ONE:
		cxlflash_info("before unmap 1");
		cxl_unmap_afu_irq(cxlflash->mcctx, 1, afu);
	case FREE_IRQ:
		cxlflash_info("before cxl_free_afu_irqs");
		cxl_free_afu_irqs(cxlflash->mcctx);
		cxlflash_info("before cxl_release_context");
	case RELEASE_CONTEXT:
		cxl_release_context(cxlflash->mcctx);
		cxlflash->mcctx = NULL;
	}
}

/**
 * cxlflash_term_afu() - terminates the AFU
 * @cxlflash:	Internal structure associated with the host.
 *
 * Safe to call with AFU/MC in partially allocated/initialized state.
 */
static void cxlflash_term_afu(struct cxlflash *cxlflash)
{
	cxlflash_term_mc(cxlflash, UNDO_START);

	/* Need to stop timers before unmapping */
	if (cxlflash->afu)
		cxlflash_stop_afu(cxlflash);

	cxlflash_info("returning");
}

/**
 * cxlflash_remove() - PCI entry point to tear down host
 * @pdev:	PCI device associated with the host.
 *
 * Safe to use as a cleanup in partially allocated/initialized state.
 */
static void cxlflash_remove(struct pci_dev *pdev)
{
	struct cxlflash *cxlflash = pci_get_drvdata(pdev);

	cxlflash_dev_err(&pdev->dev, "enter cxlflash_remove!");

	while (cxlflash->tmf_active)
		wait_event(cxlflash->tmf_wait_q, !cxlflash->tmf_active);

	switch (cxlflash->init_state) {
	case INIT_STATE_SCSI:
		scsi_remove_host(cxlflash->host);
		cxlflash_dev_err(&pdev->dev, "after scsi_remove_host!");
		scsi_host_put(cxlflash->host);
		cxlflash_dev_dbg(&pdev->dev, "after scsi_host_put!");
		/* Fall through */
	case INIT_STATE_PCI:
		if (cxlflash->cxlflash_regs)
			iounmap(cxlflash->cxlflash_regs);
		pci_release_regions(cxlflash->dev);
		pci_disable_device(pdev);
	case INIT_STATE_AFU:
		cxlflash_term_afu(cxlflash);
		cxlflash_dev_dbg(&pdev->dev, "after struct cxlflash_term_afu!");
	case INIT_STATE_NONE:
		flush_work(&cxlflash->work_q);
		cxlflash_free_mem(cxlflash);
		break;
	}

	cxlflash_dbg("returning");
}

/**
 * cxlflash_gb_alloc() - allocates the AFU and its command pool
 * @cxlflash:	Internal structure associated with the host.
 *
 * A partially allocated state remains on failure.
 *
 * Return:
 *	0 on success
 *	-ENOMEM on failure to allocate memory
 */
static int cxlflash_gb_alloc(struct cxlflash *cxlflash)
{
	int rc = 0;
	int i;
	char *buf = NULL;

	cxlflash->afu = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						 get_order(sizeof(struct afu)));
	if (unlikely(!cxlflash->afu)) {
		cxlflash_err("cannot get %d free pages",
			     get_order(sizeof(struct afu)));
		rc = -ENOMEM;
		goto out;
	}
	cxlflash->afu->back = cxlflash;
	cxlflash->afu->afu_map = NULL;

	/* Allocate one extra, just in case the SYNC command needs a buffer */
	for (i = 0; i < CXLFLASH_NUM_CMDS; buf+=CMD_BUFSIZE, i++) {
		if (!((u64)buf & (PAGE_SIZE - 1))) {
			buf = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
			if (unlikely(!buf)) {
				cxlflash_err("Allocate command buffers fail!");
				rc = -ENOMEM;
				cxlflash_free_mem(cxlflash);
				goto out;
			}
		}

		cxlflash->afu->cmd[i].buf = buf;
		atomic_set(&cxlflash->afu->cmd[i].free, 1);
		cxlflash->afu->cmd[i].slot = i;
		cxlflash->afu->cmd[i].special = 0;
	}

out:
	return rc;
}

/**
 * cxlflash_init_pci() - initializes the host as a PCI device
 * @cxlflash:	Internal structure associated with the host.
 *
 * Return:
 *	0 on success
 *	-EIO on unable to communicate with device
 *	A return code from the PCI sub-routines
 */
static int cxlflash_init_pci(struct cxlflash *cxlflash)
{
	struct pci_dev *pdev = cxlflash->dev;
	int rc = 0;

	cxlflash->cxlflash_regs_pci = pci_resource_start(pdev, 0);
	rc = pci_request_regions(pdev, CXLFLASH_NAME);
	if (rc < 0) {
		cxlflash_dev_err(&pdev->dev,
				 "Couldn't register memory range of registers");
		goto out;
	}

	rc = pci_enable_device(pdev);
	if (rc || pci_channel_offline(pdev)) {
		if (pci_channel_offline(pdev)) {
			cxlflash_wait_for_pci_err_recovery(cxlflash);
			rc = pci_enable_device(pdev);
		}

		if (rc) {
			cxlflash_dev_err(&pdev->dev, "Cannot enable adapter");
			cxlflash_wait_for_pci_err_recovery(cxlflash);
			goto out_release_regions;
		}
	}

	/*
	   cxlflash->cxlflash_regs = pci_ioremap_bar(pdev, 0);
	   if (!cxlflash->cxlflash_regs) {
	   cxlflash_dev_err(&pdev->dev,
	   "Couldn't map memory range of registers");
	   rc = -ENOMEM;
	   goto out_disable;
	   }
	 */

	rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (rc < 0) {
		cxlflash_dev_dbg(&pdev->dev,
				 "Failed to set 64 bit PCI DMA mask");
		rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	}

	if (rc < 0) {
		cxlflash_dev_err(&pdev->dev, "Failed to set PCI DMA mask");
		goto out_disable;
	}

	pci_set_master(pdev);

	if (pci_channel_offline(pdev)) {
		cxlflash_wait_for_pci_err_recovery(cxlflash);
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
	cxlflash_wait_for_pci_err_recovery(cxlflash);
	iounmap(cxlflash->cxlflash_regs);
out_disable:
	pci_disable_device(pdev);
out_release_regions:
	pci_release_regions(pdev);
	goto out;

}

/**
 * cxlflash_init_scsi() - adds the host to the SCSI stack and kicks off host scan
 * @cxlflash:	Internal structure associated with the host.
 *
 * Return:
 *	0 on success
 *	A return code from adding the host
 */
static int cxlflash_init_scsi(struct cxlflash *cxlflash)
{
	struct pci_dev *pdev = cxlflash->dev;
	int rc = 0;

	cxlflash_dev_dbg(&pdev->dev, "before scsi_add_host");
	rc = scsi_add_host(cxlflash->host, &pdev->dev);
	if (rc) {
		cxlflash_dev_err(&pdev->dev, "scsi_add_host failed (rc=%d)",
				 rc);
		goto out;
	}

	cxlflash_dev_dbg(&pdev->dev, "before scsi_scan_host");
	scsi_scan_host(cxlflash->host);

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * set_port_online() - transitions the specified host FC port to online state
 * @fc_regs:	Top of MMIO region defined for specified port.
 *
 * The provided MMIO region must be mapped prior to call. Online state means
 * that the FC link layer has synced, completed the handshaking process, and
 * is ready for login to start.
 */
static void set_port_online(volatile u64 *fc_regs)
{
	u64 cmdcfg;

	cmdcfg = readq_be(&fc_regs[FC_MTIP_CMDCONFIG / 8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_OFFLINE);	/* clear OFF_LINE */
	cmdcfg |= (FC_MTIP_CMDCONFIG_ONLINE);	/* set ON_LINE */
	writeq_be(cmdcfg, &fc_regs[FC_MTIP_CMDCONFIG / 8]);
}

/**
 * set_port_offline() - transitions the specified host FC port to offline state
 * @fc_regs:	Top of MMIO region defined for specified port.
 *
 * The provided MMIO region must be mapped prior to call.
 */
static void set_port_offline(volatile u64 *fc_regs)
{
	u64 cmdcfg;

	cmdcfg = readq_be(&fc_regs[FC_MTIP_CMDCONFIG / 8]);
	cmdcfg &= (~FC_MTIP_CMDCONFIG_ONLINE);	/* clear ON_LINE */
	cmdcfg |= (FC_MTIP_CMDCONFIG_OFFLINE);	/* set OFF_LINE */
	writeq_be(cmdcfg, &fc_regs[FC_MTIP_CMDCONFIG / 8]);
}

/**
 * wait_port_online() - waits for the specified host FC port come online
 * @fc_regs:	Top of MMIO region defined for specified port.
 * @delay_us:	Number of microseconds to delay between reading port status.
 * @nretry:	Number of cycles to retry reading port status.
 *
 * The provided MMIO region must be mapped prior to call. This will timeout
 * when the cable is not plugged in.
 *
 * Return:
 *	TRUE (1) when the specified port is online
 *	FALSE (0) when the specified port fails to come online after timeout
 *	-EINVAL when @delay_us is less than 1000
 */
static int wait_port_online(volatile u64 *fc_regs,
			    useconds_t delay_us, unsigned int nretry)
{
	u64 status;

	if (delay_us < 1000) {
		cxlflash_err("invalid delay specified %d", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us / 1000);
		status = readq_be(&fc_regs[FC_MTIP_STATUS / 8]);
	} while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_ONLINE &&
		 nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_ONLINE);
}

/**
 * wait_port_offline() - waits for the specified host FC port go offline
 * @fc_regs:	Top of MMIO region defined for specified port.
 * @delay_us:	Number of microseconds to delay between reading port status.
 * @nretry:	Number of cycles to retry reading port status.
 *
 * The provided MMIO region must be mapped prior to call.
 *
 * Return:
 *	TRUE (1) when the specified port is offline
 *	FALSE (0) when the specified port fails to go offline after timeout
 *	-EINVAL when @delay_us is less than 1000
 */
static int wait_port_offline(volatile u64 *fc_regs,
			     useconds_t delay_us, unsigned int nretry)
{
	u64 status;

	if (delay_us < 1000) {
		cxlflash_err("invalid delay specified %d", delay_us);
		return -EINVAL;
	}

	do {
		msleep(delay_us / 1000);
		status = readq_be(&fc_regs[FC_MTIP_STATUS / 8]);
	} while ((status & FC_MTIP_STATUS_MASK) != FC_MTIP_STATUS_OFFLINE &&
		 nretry--);

	return ((status & FC_MTIP_STATUS_MASK) == FC_MTIP_STATUS_OFFLINE);
}

/**
 * afu_set_wwpn() - configures the WWPN for the specified host FC port
 * @afu:	AFU associated with the host that owns the specified FC port.
 * @port:	Port number being configured.
 * @fc_regs:	Top of MMIO region defined for specified port.
 * @wwpn:	The world-wide-port-number previously discovered for port.
 *
 * The provided MMIO region must be mapped prior to call. As part of the
 * sequence to configure the WWPN, the port is toggled offline and then back
 * online. This toggling action can cause this routine to delay up to a few
 * seconds. When configured to use the internal LUN feature of the AFU, a
 * failure to come online is overridden.
 *
 * Return:
 *	0 when the WWPN is successfully written and the port comes back online
 *	-1 when the port fails to go offline or come back up online
 */
static int afu_set_wwpn(struct afu *afu, int port,
			volatile u64 *fc_regs, u64 wwpn)
{
	int ret = 0;

	set_port_offline(fc_regs);

	if (!wait_port_offline(fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			       FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_dbg("wait on port %d to go offline timed out", port);
		ret = -1;	/* but continue on to leave the port back online */
	}

	if (ret == 0)
		writeq_be(wwpn, &fc_regs[FC_PNAME / 8]);

	set_port_online(fc_regs);

	if (!wait_port_online(fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT)) {
		cxlflash_dbg("wait on port %d to go online timed out", port);
		ret = -1;

		/*
		 * Override for internal lun!!!
		 */
		if (afu->internal_lun) {
			cxlflash_info("Overriding port %d online timeout!!!",
				      port);
			ret = 0;
		}
	}

	cxlflash_info("returning rc=%d", ret);

	return ret;
}

/**
 * afu_link_reset() - resets the specified host FC port
 * @afu:	AFU associated with the host that owns the specified FC port.
 * @port:	Port number being configured.
 * @fc_regs:	Top of MMIO region defined for specified port.
 *
 * The provided MMIO region must be mapped prior to call. The sequence to
 * reset the port involves toggling it offline and then back online. This
 * action can cause this routine to delay up to a few seconds. An effort
 * is made to maintain link with the device by switching to host to use
 * the alternate port exclusively while the reset takes place.
 * failure to come online is overridden.
 */
static void afu_link_reset(struct afu *afu, int port, volatile u64 *fc_regs)
{
	u64 port_sel;

	/* first switch the AFU to the other links, if any */
	port_sel = readq_be(&afu->afu_map->global.regs.afu_port_sel);
	port_sel &= ~(1 << port);
	writeq_be(port_sel, &afu->afu_map->global.regs.afu_port_sel);
	cxlflash_afu_sync(afu, 0, 0, AFU_GSYNC);

	set_port_offline(fc_regs);
	if (!wait_port_offline(fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			       FC_PORT_STATUS_RETRY_CNT))
		cxlflash_err("wait on port %d to go offline timed out", port);

	set_port_online(fc_regs);
	if (!wait_port_online(fc_regs, FC_PORT_STATUS_RETRY_INTERVAL_US,
			      FC_PORT_STATUS_RETRY_CNT))
		cxlflash_err("wait on port %d to go online timed out", port);

	/* switch back to include this port */
	port_sel |= (1 << port);
	writeq_be(port_sel, &afu->afu_map->global.regs.afu_port_sel);
	cxlflash_afu_sync(afu, 0, 0, AFU_GSYNC);

	cxlflash_info("returning port_sel=%lld", port_sel);
}

/*
 * Asynchronous interrupt information table
 */
static const struct asyc_intr_info ainfo[] = {
	{SISL_ASTATUS_FC0_OTHER, "fc 0: other error", 0,
		CLR_FC_ERROR | LINK_RESET},
	{SISL_ASTATUS_FC0_LOGO, "fc 0: target initiated LOGO", 0, 0},
	{SISL_ASTATUS_FC0_CRC_T, "fc 0: CRC threshold exceeded", 0, LINK_RESET},
	{SISL_ASTATUS_FC0_LOGI_R, "fc 0: login timed out, retrying", 0, 0},
	{SISL_ASTATUS_FC0_LOGI_F, "fc 0: login failed", 0, CLR_FC_ERROR},
	{SISL_ASTATUS_FC0_LOGI_S, "fc 0: login succeeded", 0, 0},
	{SISL_ASTATUS_FC0_LINK_DN, "fc 0: link down", 0, 0},
	{SISL_ASTATUS_FC0_LINK_UP, "fc 0: link up", 0, 0},

	{SISL_ASTATUS_FC1_OTHER, "fc 1: other error", 1,
	 CLR_FC_ERROR | LINK_RESET},
	{SISL_ASTATUS_FC1_LOGO, "fc 1: target initiated LOGO", 1, 0},
	{SISL_ASTATUS_FC1_CRC_T, "fc 1: CRC threshold exceeded", 1, LINK_RESET},
	{SISL_ASTATUS_FC1_LOGI_R, "fc 1: login timed out, retrying", 1, 0},
	{SISL_ASTATUS_FC1_LOGI_F, "fc 1: login failed", 1, CLR_FC_ERROR},
	{SISL_ASTATUS_FC1_LOGI_S, "fc 1: login succeeded", 1, 0},
	{SISL_ASTATUS_FC1_LINK_DN, "fc 1: link down", 1, 0},
	{SISL_ASTATUS_FC1_LINK_UP, "fc 1: link up", 1, 0},
	{0x0, "", 0, 0}		/* terminator */
};

/**
 * find_ainfo() - locates and returns asynchronous interrupt information
 * @status:	Status code set by AFU on error.
 *
 * Return: The located information or NULL when the status code is invalid.
 */
static const struct asyc_intr_info *find_ainfo(u64 status)
{
	const struct asyc_intr_info *info;

	for (info = &ainfo[0]; info->status; info++)
		if (info->status == status)
			return info;

	return NULL;
}

/**
 * afu_err_intr_init() - clears and initializes the AFU for error interrupts
 * @afu:	AFU associated with the host.
 */
static void afu_err_intr_init(struct afu *afu)
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
	writeq_be(-1ULL, &afu->afu_map->global.regs.aintr_mask);
	/* set LISN# to send and point to master context */
	reg = ((u64) (((afu->ctx_hndl << 8) | SISL_MSI_ASYNC_ERROR)) << 40);

	if (afu->internal_lun)
		reg |= 1;	/* Bit 63 indicates local lun */
	writeq_be(reg, &afu->afu_map->global.regs.afu_ctrl);
	/* clear all */
	writeq_be(-1ULL, &afu->afu_map->global.regs.aintr_clear);
	/* unmask bits that are of interest */
	/* note: afu can send an interrupt after this step */
	writeq_be(SISL_ASTATUS_MASK, &afu->afu_map->global.regs.aintr_mask);
	/* clear again in case a bit came on after previous clear but before */
	/* unmask */
	writeq_be(-1ULL, &afu->afu_map->global.regs.aintr_clear);

	/* Clear/Set internal lun bits */
	reg = readq_be(&afu->afu_map->global.fc_regs[0][FC_CONFIG2 / 8]);
	cxlflash_info("ilun p0 = %016llX", reg);
	reg &= SISL_FC_INTERNAL_MASK;
	if (afu->internal_lun)
		reg |= ((u64)(afu->internal_lun - 1) << SISL_FC_INTERNAL_SHIFT);
	cxlflash_info("ilun p0 = %016llX", reg);
	writeq_be(reg, &afu->afu_map->global.fc_regs[0][FC_CONFIG2 / 8]);

	/* now clear FC errors */
	for (i = 0; i < NUM_FC_PORTS; i++) {
		writeq_be(0xFFFFFFFFU,
			  &afu->afu_map->global.fc_regs[i][FC_ERROR / 8]);
		writeq_be(0, &afu->afu_map->global.fc_regs[i][FC_ERRCAP / 8]);
	}

	/* sync interrupts for master's IOARRIN write */
	/* note that unlike asyncs, there can be no pending sync interrupts */
	/* at this time (this is a fresh context and master has not written */
	/* IOARRIN yet), so there is nothing to clear. */

	/* set LISN#, it is always sent to the context that wrote IOARRIN */
	writeq_be(SISL_MSI_SYNC_ERROR, &afu->host_map->ctx_ctrl);
	writeq_be(SISL_ISTATUS_MASK, &afu->host_map->intr_mask);
}

/**
 * cxlflash_sync_err_irq() - interrupt handler for synchronous errors
 * @irq:	Interrupt number.
 * @data:	Private data provided at interrupt registration, the AFU.
 *
 * Return: Always return IRQ_HANDLED.
 */
static irqreturn_t cxlflash_sync_err_irq(int irq, void *data)
{
	struct afu *afu = (struct afu *)data;
	u64 reg;
	u64 reg_unmasked;

	reg = readq_be(&afu->host_map->intr_status);
	reg_unmasked = (reg & SISL_ISTATUS_UNMASK);

	if (reg_unmasked == 0UL) {
		cxlflash_err("%llX: spurious interrupt, intr_status %016llX",
			     (u64) afu, reg);
		goto cxlflash_sync_err_irq_exit;
	}

	cxlflash_err("%llX: unexpected interrupt, intr_status %016llX",
		     (u64) afu, reg);

	writeq_be(reg_unmasked, &afu->host_map->intr_clear);

cxlflash_sync_err_irq_exit:
	cxlflash_info("returning rc=%d", IRQ_HANDLED);
	return IRQ_HANDLED;
}

/**
 * cxlflash_rrq_irq() - interrupt handler for read-response queue (normal path)
 * @irq:	Interrupt number.
 * @data:	Private data provided at interrupt registration, the AFU.
 *
 * Return: Always return IRQ_HANDLED.
 */
static irqreturn_t cxlflash_rrq_irq(int irq, void *data)
{
	struct afu *afu = (struct afu *)data;
	struct afu_cmd *cmd;
	u32 toggle = afu->toggle;
	u64 entry;
	u64 *hrrq_start = afu->hrrq_start,
	    *hrrq_end = afu->hrrq_end;
	volatile u64 *hrrq_curr = afu->hrrq_curr;

	/* Process however many RRQ entries that are ready */
	while (true) {
		entry = *hrrq_curr;

		if ((entry & SISL_RESP_HANDLE_T_BIT) != toggle)
			break;

		cmd = (struct afu_cmd *)(entry & ~SISL_RESP_HANDLE_T_BIT);
		cmd_complete(cmd);

		/* Advance to next entry or wrap and flip the toggle bit */
		if (hrrq_curr < hrrq_end)
			hrrq_curr++;
		else {
			hrrq_curr = hrrq_start;
			toggle ^= SISL_RESP_HANDLE_T_BIT;
		}
	}

	afu->hrrq_curr = hrrq_curr;
	afu->toggle = toggle;

	return IRQ_HANDLED;
}

/**
 * cxlflash_async_err_irq() - interrupt handler for asynchronous errors
 * @irq:	Interrupt number.
 * @data:	Private data provided at interrupt registration, the AFU.
 *
 * Return: Always return IRQ_HANDLED.
 */
static irqreturn_t cxlflash_async_err_irq(int irq, void *data)
{
	struct afu *afu = (struct afu *)data;
	struct cxlflash *cxlflash;
	u64 reg_unmasked;
	const struct asyc_intr_info *info;
	volatile struct sisl_global_map *global = &afu->afu_map->global;
	u64 reg;
	int i;

	cxlflash = afu->back;

	reg = readq_be(&global->regs.aintr_status);
	reg_unmasked = (reg & SISL_ASTATUS_UNMASK);

	if (reg_unmasked == 0) {
		cxlflash_err("spurious interrupt, aintr_status 0x%016llx", reg);
		goto out;
	}

	/* it is OK to clear AFU status before FC_ERROR */
	writeq_be(reg_unmasked, &global->regs.aintr_clear);

	/* check each bit that is on */
	for (i = 0; reg_unmasked; i++, reg_unmasked = (reg_unmasked >> 1)) {
		if ((reg_unmasked & 0x1) == 0 ||
		    (info = find_ainfo(1ull << i)) == NULL) {
			continue;
		}

		cxlflash_err("%s, fc_status 0x%08llx", info->desc,
			     readq_be(&global->fc_regs
				      [info->port][FC_STATUS / 8]));

		/*
		 * do link reset first, some OTHER errors will set FC_ERROR
		 * again if cleared before or w/o a reset
		 */
		if (info->action & LINK_RESET) {
			cxlflash_err("fc %d: resetting link", info->port);
			cxlflash->lr_state = LINK_RESET_REQUIRED;
			cxlflash->lr_port = info->port;
			schedule_work(&cxlflash->work_q);
		}

		if (info->action & CLR_FC_ERROR) {
			reg = readq_be(&global->fc_regs[info->port]
				       [FC_ERROR / 8]);

			/*
			 * since all errors are unmasked, FC_ERROR and FC_ERRCAP
			 * should be the same and tracing one is sufficient.
			 */

			cxlflash_err("fc %d: clearing fc_error 0x%08llx",
				     info->port, reg);

			writeq_be(reg,
				  &global->fc_regs[info->port][FC_ERROR /
								   8]);
			writeq_be(0,
				  &global->fc_regs[info->port][FC_ERRCAP /
								   8]);
		}
	}

out:
	cxlflash_info("returning rc=%d, afu=%p", IRQ_HANDLED, afu);
	return IRQ_HANDLED;
}

/**
 * cxlflash_start_context() - starts the master context
 * @cxlflash:	Internal structure associated with the host.
 *
 * Return: A success or failure value from CXL services.
 */
int cxlflash_start_context(struct cxlflash *cxlflash)
{
	int rc = 0;

	rc = cxl_start_context(cxlflash->mcctx,
			       cxlflash->afu->work.work_element_descriptor,
			       NULL);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_read_vpd() - obtains the WWPNs from VPD
 * @cxlflash:	Internal structure associated with the host.
 * @wwpn:	Array of size NUM_FC_PORTS to pass back WWPNs
 *
 * Return:
 *	0 on success
 *	-ENODEV when VPD or WWPN keywords not found
 */
int cxlflash_read_vpd(struct cxlflash *cxlflash, u64 wwpn[])
{
	struct pci_dev *dev = cxlflash->parent_dev;
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
	if (unlikely((i + j) > vpd_size)) {
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
			cxlflash_err("Port %d WWPN incomplete or VPD corrupt",
				     k);
			rc = -ENODEV;
			goto out;
		}

		memcpy(tmp_buf, &vpd_data[i], WWPN_LEN);
		rc = kstrtoul(tmp_buf, WWPN_LEN, (unsigned long *)&wwpn[k]);
		if (unlikely(rc)) {
			cxlflash_err
			    ("Unable to convert port 0 WWPN to integer");
			rc = -ENODEV;
			goto out;
		}
	}

out:
	cxlflash_dbg("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_context_reset() - timeout handler for AFU commands
 * @cmd:	AFU command that timed out.
 *
 * Sends a reset to the AFU.
 */
void cxlflash_context_reset(struct afu_cmd *cmd)
{
	int nretry = 0;
	u64 rrin = 0x1;
	struct afu *afu = cmd->back;

	cxlflash_info("cmd=%p", cmd);

	/* First process completion of the command that timed out */
	cmd_complete(cmd);

	if (afu->room == 0) {
		do {
			afu->room = readq_be(&afu->host_map->cmd_room);
			udelay(nretry);
		} while ((afu->room == 0) && (nretry++ < MC_ROOM_RETRY_CNT));
	}

	if (afu->room) {
		writeq_be((u64) rrin, &afu->host_map->ioarrin);
		do {
			rrin = readq_be(&afu->host_map->ioarrin);
			/* Double delay each time */
			udelay(2 ^ nretry);
		} while ((rrin == 0x1) && (nretry++ < MC_ROOM_RETRY_CNT));
	} else
		cxlflash_err("no cmd_room to send reset");
}

/**
 * init_pcr() - initialize the provisioning and control registers
 * @cxlflash:	Internal structure associated with the host.
 *
 * Also sets up fast access to the mapped registers and initializes AFU
 * command fields that never change.
 */
void init_pcr(struct cxlflash *cxlflash)
{
	struct afu *afu = cxlflash->afu;
	volatile struct sisl_ctrl_map *ctrl_map;
	int i;

	for (i = 0; i < MAX_CONTEXT; i++) {
		ctrl_map = &afu->afu_map->ctrls[i].ctrl;
		/* disrupt any clients that could be running */
		/* e. g. clients that survived a master restart */
		writeq_be(0, &ctrl_map->rht_start);
		writeq_be(0, &ctrl_map->rht_cnt_id);
		writeq_be(0, &ctrl_map->ctx_cap);
	}

	/* copy frequently used fields into afu */
	afu->ctx_hndl = (u16) cxl_process_element(cxlflash->mcctx);
	/* ctx_hndl is 16 bits in CAIA */
	afu->host_map = &afu->afu_map->hosts[afu->ctx_hndl].host;
	afu->ctrl_map = &afu->afu_map->ctrls[afu->ctx_hndl].ctrl;

	/* initialize cmd fields that never change */
	for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
		afu->cmd[i].rcb.ctx_id = afu->ctx_hndl;
		afu->cmd[i].rcb.msi = SISL_MSI_RRQ_UPDATED;
		afu->cmd[i].rcb.rrq = 0x0;
	}

}

/**
 * init_global() - initialize AFU global registers
 * @cxlflash:	Internal structure associated with the host.
 */
int init_global(struct cxlflash *cxlflash)
{
	struct afu *afu = cxlflash->afu;
	u64 wwpn[NUM_FC_PORTS];	/* wwpn of AFU ports */
	int i = 0, num_ports = 0;
	int rc = 0;
	u64 reg;

	rc = cxlflash_read_vpd(cxlflash, &wwpn[0]);
	if (rc) {
		cxlflash_err("could not read vpd rc=%d", rc);
		goto out;
	}
	cxlflash_info("wwpn0=0x%llx wwpn1=0x%llx", wwpn[0], wwpn[1]);

	/* set up RRQ in AFU for master issued cmds */
	writeq_be((u64) afu->hrrq_start, &afu->host_map->rrq_start);
	writeq_be((u64) afu->hrrq_end, &afu->host_map->rrq_end);

	/* AFU configuration */
	reg = readq_be(&afu->afu_map->global.regs.afu_config);
	reg |= 0x7F20;		/* enable all auto retry options and LE */
	/* leave others at default: */
	/* CTX_CAP write protected, mbox_r does not clear on read and */
	/* checker on if dual afu */
	writeq_be(reg, &afu->afu_map->global.regs.afu_config);

	/* global port select: select either port */
	if (afu->internal_lun) {
		/* only use port 0 */
		writeq_be(0x1, &afu->afu_map->global.regs.afu_port_sel);
		num_ports = NUM_FC_PORTS - 1;
	}
	else
	{
		writeq_be(0x3, &afu->afu_map->global.regs.afu_port_sel);
		num_ports = NUM_FC_PORTS;
	}

	for (i = 0; i < num_ports; i++) {
		/* unmask all errors (but they are still masked at AFU) */
		writeq_be(0, &afu->afu_map->global.fc_regs[i][FC_ERRMSK / 8]);
		/* clear CRC error cnt & set a threshold */
		(void)readq_be(&afu->afu_map->global.
			       fc_regs[i][FC_CNT_CRCERR / 8]);
		writeq_be(MC_CRC_THRESH, &afu->afu_map->global.fc_regs[i]
			  [FC_CRC_THRESH / 8]);

		/* set WWPNs. If already programmed, wwpn[i] is 0 */
		if (wwpn[i] != 0 &&
		    afu_set_wwpn(afu, i,
				 &afu->afu_map->global.fc_regs[i][0],
				 wwpn[i])) {
			cxlflash_dbg("failed to set WWPN on port %d", i);
			rc = -EIO;
			goto out;
		}
		/* Programming WWPN back to back causes additional
		 * offline/online transitions and a PLOGI
		 */
		msleep(100);

	}

	/* set up master's own CTX_CAP to allow real mode, host translation */
	/* tbls, afu cmds and read/write GSCSI cmds. */
	/* First, unlock ctx_cap write by reading mbox */
	(void)readq_be(&afu->ctrl_map->mbox_r);	/* unlock ctx_cap */
	writeq_be((SISL_CTX_CAP_REAL_MODE | SISL_CTX_CAP_HOST_XLATE |
		   SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD |
		   SISL_CTX_CAP_AFU_CMD | SISL_CTX_CAP_GSCSI_CMD),
		  &afu->ctrl_map->ctx_cap);
	/* init heartbeat */
	afu->hb = readq_be(&afu->afu_map->global.regs.afu_hb);

out:
	return rc;
}

/**
 * cxlflash_start_afu() - initializes and starts the AFU
 * @cxlflash:	Internal structure associated with the host.
 */
int cxlflash_start_afu(struct cxlflash *cxlflash)
{
	struct afu *afu = cxlflash->afu;

	int i = 0;
	int rc = 0;

	for (i = 0; i < CXLFLASH_NUM_CMDS; i++) {
		struct timer_list *timer = &afu->cmd[i].timer;

		init_timer(timer);
		timer->data = (unsigned long)&afu->cmd[i];
		timer->function = (void (*)(unsigned long))
		    cxlflash_context_reset;

		spin_lock_init(&afu->cmd[i].slock);
		afu->cmd[i].back = afu;
	}
	init_pcr(cxlflash);

	/* initialize RRQ pointers */
	afu->hrrq_start = &afu->rrq_entry[0];
	afu->hrrq_end = &afu->rrq_entry[NUM_RRQ_ENTRY - 1];
	afu->hrrq_curr = afu->hrrq_start;
	afu->toggle = 1;

	rc = init_global(cxlflash);

	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_init_mc() - create and register as the master context
 * @cxlflash:	Internal structure associated with the host.
 *
 * Return:
 *	0 on success
 *	-ENOMEM when unable to obtain a context from CXL services
 *	A failure value from CXL services.
 */
int cxlflash_init_mc(struct cxlflash *cxlflash)
{
	struct cxl_context *ctx;
	struct device *dev = &cxlflash->dev->dev;
	struct afu *afu = cxlflash->afu;
	int rc = 0;
	enum undo_level level;

	ctx = cxl_dev_context_init(cxlflash->dev);
	if (!ctx)
		return -ENOMEM;
	cxlflash->mcctx = ctx;

	/* Set it up as a master with the CXL */
	cxl_set_master(ctx);

	/* During initialization reset the AFU to start from a clean slate */
	rc = cxl_afu_reset(cxlflash->mcctx);
	if (rc) {
		cxlflash_dev_err(dev, "initial AFU reset failed rc=%d", rc);
		level = RELEASE_CONTEXT;
		goto out;
	}

	/* Allocate AFU generated interrupt handler */
	rc = cxl_allocate_afu_irqs(ctx, 3);
	if (rc) {
		cxlflash_dev_err(dev, "call to allocate_afu_irqs failed rc=%d!",
				 rc);
		level = RELEASE_CONTEXT;
		goto out;
	}

	/* Register AFU interrupt 1 (SISL_MSI_SYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 1, cxlflash_sync_err_irq, afu,
			     "SISL_MSI_SYNC_ERROR");
	if (!rc) {
		cxlflash_dev_err(dev,
				 "IRQ 1 (SISL_MSI_SYNC_ERROR) map failed!");
		level = FREE_IRQ;
		goto out;
	}
	/* Register AFU interrupt 2 (SISL_MSI_RRQ_UPDATED) */
	rc = cxl_map_afu_irq(ctx, 2, cxlflash_rrq_irq, afu,
			     "SISL_MSI_RRQ_UPDATED");
	if (!rc) {
		cxlflash_dev_err(dev,
				 "IRQ 2 (SISL_MSI_RRQ_UPDATED) map failed!");
		level = UNMAP_ONE;
		goto out;
	}
	/* Register AFU interrupt 3 (SISL_MSI_ASYNC_ERROR) */
	rc = cxl_map_afu_irq(ctx, 3, cxlflash_async_err_irq, afu,
			     "SISL_MSI_ASYNC_ERROR");
	if (!rc) {
		cxlflash_dev_err(dev,
				 "IRQ 3 (SISL_MSI_ASYNC_ERROR) map failed!");
		level = UNMAP_TWO;
		goto out;
	}

	rc = 0;

	/* This performs the equivalent of the CXL_IOCTL_START_WORK.
	 * The CXL_IOCTL_GET_PROCESS_ELEMENT is implicit in the process
	 * element (pe) that is embedded in the context (ctx)
	 */
	rc = cxlflash_start_context(cxlflash);
	if (rc) {
		cxlflash_dev_err(dev, "start context failed rc=%d", rc);
		level = UNMAP_THREE;
		goto out;
	}
ret:
	cxlflash_info("returning rc=%d", rc);
	return rc;
out:
	cxlflash_term_mc(cxlflash, level);
	goto ret;
}

/**
 * cxlflash_init_afu() - setup as master context and start AFU
 * @cxlflash:	Internal structure associated with the host.
 *
 * This routine is a higher level of control for configuring the
 * AFU on probe and reset paths.
 *
 * Return:
 *	0 on success
 *	-ENOMEM when unable to map the AFU MMIO space
 *	A failure value from internal services.
 */
static int cxlflash_init_afu(struct cxlflash *cxlflash)
{
	u64 reg;
	int rc = 0;
	struct afu *afu = cxlflash->afu;
	struct device *dev = &cxlflash->dev->dev;


	rc = cxlflash_init_mc(cxlflash);
	if (rc) {
		cxlflash_dev_err(dev, "call to init_mc failed, rc=%d!", rc);
		goto err1;
	}

	/* Map the entire MMIO space of the AFU.
	 */
	afu->afu_map = cxl_psa_map(cxlflash->mcctx);
	if (!afu->afu_map) {
		rc = -ENOMEM;
		cxlflash_term_mc(cxlflash, UNDO_START);
		cxlflash_dev_err(dev, "call to cxl_psa_map failed!");
		goto err1;
	}

	/* don't byte reverse on reading afu_version, else the string form */
	/*     will be backwards */
	reg = afu->afu_map->global.regs.afu_version;
	memcpy(afu->version, &reg, 8);
	afu->interface_version =
	    readq_be(&afu->afu_map->global.regs.interface_version);
	cxlflash_info("afu version %s, interface version 0x%llx",
		      afu->version, afu->interface_version);

	rc = cxlflash_start_afu(cxlflash);
	if (rc) {
		cxlflash_dev_err(dev, "call to start_afu failed, rc=%d!", rc);
		cxlflash_term_mc(cxlflash, UNDO_START);
		cxl_psa_unmap((void *)afu->afu_map);
		afu->afu_map = NULL;
	}

	afu_err_intr_init(cxlflash->afu);

err1:
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_send_cmd() - sends an AFU command
 * @afu:	AFU associated with the host.
 * @cmd:	AFU command to send.
 *
 * Return:
 *	0 on success
 *	-1 on failure
 */
int cxlflash_send_cmd(struct afu *afu, struct afu_cmd *cmd)
{
	int nretry = 0;
	int rc = 0;

	if (afu->room == 0)
		do {
			afu->room = readq_be(&afu->host_map->cmd_room);
			udelay(nretry);
		} while ((afu->room == 0) && (nretry++ < MC_ROOM_RETRY_CNT));

	cmd->sa.host_use_b[0] = 0;	/* 0 means active */
	cmd->sa.ioasc = 0;

	/* make memory updates visible to AFU before MMIO */
	smp_wmb();

	/* Only kick off the timer for internal commands */
	if (cmd->internal) {
		cmd->timer.expires = (jiffies +
					(cmd->rcb.timeout * 2 * HZ));
		add_timer(&cmd->timer);
	} else if (cmd->rcb.timeout)
		cxlflash_err("timer not started %d", cmd->rcb.timeout);

	/* Write IOARRIN */
	if (afu->room)
		writeq_be((u64)&cmd->rcb, &afu->host_map->ioarrin);
	else {
		cxlflash_err("no cmd_room to send 0x%X", cmd->rcb.cdb[0]);
		rc = -1;
	}

	cxlflash_dbg("cmd=%p len=%d ea=%p rc=%d", cmd, cmd->rcb.data_len,
		     (void *)cmd->rcb.data_ea, rc);

	/* Let timer fire to complete the response... */
	return rc;
}

/**
 * cxlflash_wait_resp() - polls for a response or timeout to a sent AFU command
 * @afu:	AFU associated with the host.
 * @cmd:	AFU command that was sent.
 */
void cxlflash_wait_resp(struct afu *afu, struct afu_cmd *cmd)
{
	unsigned long lock_flags = 0;

	spin_lock_irqsave(&cmd->slock, lock_flags);
	while (!(cmd->sa.host_use_b[0] & B_DONE)) {
		spin_unlock_irqrestore(&cmd->slock, lock_flags);
		udelay(10);
		spin_lock_irqsave(&cmd->slock, lock_flags);
	}
	spin_unlock_irqrestore(&cmd->slock, lock_flags);

	del_timer(&cmd->timer);	/* already stopped if timer fired */

	if (cmd->sa.ioasc != 0)
		cxlflash_err("CMD 0x%x failed, IOASC: flags 0x%x, afu_rc 0x%x, "
			     "scsi_rc 0x%x, fc_rc 0x%x",
			     cmd->rcb.cdb[0],
			     cmd->sa.rc.flags,
			     cmd->sa.rc.afu_rc,
			     cmd->sa.rc.scsi_rc, cmd->sa.rc.fc_rc);
}

/**
 * cxlflash_afu_sync() - builds and sends an AFU sync command
 * @afu:	AFU associated with the host.
 * @ctx_hndl_u:	Identifies context requesting sync.
 * @res_hndl_u:	Identifies resource requesting sync.
 * @mode:	Type of sync to issue (lightweight, heavyweight, global).
 *
 * The AFU can only take 1 sync command at a time. This routine can be
 * called from both interrupt and process context. The caller is responsible
 * for any serialization.
 *
 * Return:
 *	0 on success
 *	-1 on failure
 */
int cxlflash_afu_sync(struct afu *afu, ctx_hndl_t ctx_hndl_u,
		      res_hndl_t res_hndl_u, u8 mode)
{
	struct cxlflash *cxlflash = afu->back;
	struct afu_cmd *cmd;
	int rc = 0;
	int retry_cnt = 0;

	while (cxlflash->sync_active) {
		cxlflash_dbg("sync issued while one is active");
		wait_event(cxlflash->sync_wait_q, !cxlflash->sync_active);
	}

retry:
	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		retry_cnt++;
		cxlflash_dbg("could not get command on attempt %d", retry_cnt);
		udelay(1000*retry_cnt);
		if (retry_cnt < MC_RETRY_CNT)
			goto retry;
		cxlflash_err("could not get a free command");
		rc = -1;
		goto out;
	}

	cxlflash_dbg("afu=%p cmd=%p %d", afu, cmd, ctx_hndl_u);

	memset(cmd->rcb.cdb, 0, sizeof(cmd->rcb.cdb));

	cmd->rcb.req_flags = SISL_REQ_FLAGS_AFU_CMD;
	cmd->rcb.port_sel = 0x0;	/* NA */
	cmd->rcb.lun_id = 0x0;	/* NA */
	cmd->rcb.data_len = 0x0;
	cmd->rcb.data_ea = 0x0;
	cmd->internal = true;
	cmd->sync = true;
	cmd->rcb.timeout = MC_AFU_SYNC_TIMEOUT;

	cmd->rcb.cdb[0] = 0xC0;	/* AFU Sync */
	cmd->rcb.cdb[1] = mode;

	cxlflash->sync_active = true;

	/* The cdb is aligned, no unaligned accessors required */
	*((u16 *)&cmd->rcb.cdb[2]) = swab16(ctx_hndl_u);
	*((u32 *)&cmd->rcb.cdb[4]) = swab32(res_hndl_u);

	rc = cxlflash_send_cmd(afu, cmd);
	if (!rc)
		cxlflash_wait_resp(afu, cmd);

	if ((cmd->sa.ioasc != 0) || (cmd->sa.host_use_b[0] & B_ERROR)) {
		rc = -1;
		/* B_ERROR is set on timeout */
	}

out:
	cxlflash_dbg("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_afu_reset() - resets the AFU
 * @cxlflash:	Internal structure associated with the host.
 *
 * Return:
 *	0 on success
 *	A failure value from internal services.
 */
int cxlflash_afu_reset(struct cxlflash *cxlflash)
{
	int rc = 0;
	/* Stop the context before the reset. Since the context is
	 * no longer available restart it after the reset is complete
	 */

	cxlflash_term_afu(cxlflash);

	rc = cxlflash_init_afu(cxlflash);

	/* XXX: Need to restart/reattach all user contexts */
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/**
 * cxlflash_worker_thread() - work thread handler for the AFU
 * @work:	Work structure contained within cxlflash associated with host.
 *
 * Handles link reset which cannot be performed on interrupt context due to
 * blocking up to a few seconds.
 */
static void cxlflash_worker_thread(struct work_struct *work)
{
	struct cxlflash *cxlflash =
	    container_of(work, struct cxlflash, work_q);
	struct afu *afu = cxlflash->afu;
	int port;
	unsigned long lock_flags;

	spin_lock_irqsave(cxlflash->host->host_lock, lock_flags);

	if (cxlflash->lr_state == LINK_RESET_REQUIRED) {
		port = cxlflash->lr_port;
		if (port < 0)
			cxlflash_err("invalid port index %d", port);
		else
			afu_link_reset(afu, port,
				       &afu->afu_map->
				       global.fc_regs[port][0]);
		cxlflash->lr_state = LINK_RESET_COMPLETE;
	}

	spin_unlock_irqrestore(cxlflash->host->host_lock, lock_flags);
}

/**
 * cxlflash_probe() - PCI entry point to add host
 * @pdev:	PCI device associated with the host.
 * @dev_id:	PCI device id associated with device.
 *
 * Return: 0 on success / non-zero on failure
 */
static int cxlflash_probe(struct pci_dev *pdev,
			  const struct pci_device_id *dev_id)
{
	struct Scsi_Host *host;
	struct cxlflash *cxlflash = NULL;
	struct device *phys_dev;
	struct dev_dependent_vals *ddv;
	int rc = 0;

	cxlflash_dev_dbg(&pdev->dev, "Found CXLFLASH with IRQ: %d", pdev->irq);

	ddv = (struct dev_dependent_vals *)dev_id->driver_data;
	driver_template.max_sectors = ddv->max_sectors;

	host = scsi_host_alloc(&driver_template, sizeof(struct cxlflash));
	if (!host) {
		cxlflash_dev_err(&pdev->dev, "call to scsi_host_alloc failed!");
		rc = -ENOMEM;
		goto out;
	}

	host->max_id = CXLFLASH_MAX_NUM_TARGETS_PER_BUS;
	host->max_lun = CXLFLASH_MAX_NUM_LUNS_PER_TARGET;
	host->max_channel = NUM_FC_PORTS - 1;
	host->unique_id = host->host_no;
	host->max_cmd_len = CXLFLASH_MAX_CDB_LEN;

	cxlflash = (struct cxlflash *)host->hostdata;
	cxlflash->host = host;
	rc = cxlflash_gb_alloc(cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev, "call to scsi_host_alloc failed!");
		rc = -ENOMEM;
		goto out;
	}

	cxlflash->init_state = INIT_STATE_NONE;
	cxlflash->dev = pdev;
	cxlflash->last_lun_index = 0;
	cxlflash->dev_id = (struct pci_device_id *)dev_id;
	cxlflash->tmf_active = 0;
	cxlflash->mcctx = NULL;
	cxlflash->context_reset_active = 0;
	cxlflash->num_user_contexts = 0;

	init_waitqueue_head(&cxlflash->tmf_wait_q);
	init_waitqueue_head(&cxlflash->eeh_wait_q);
	init_waitqueue_head(&cxlflash->sync_wait_q);

	INIT_WORK(&cxlflash->work_q, cxlflash_worker_thread);
	cxlflash->lr_state = LINK_RESET_INVALID;
	cxlflash->lr_port = -1;

	pci_set_drvdata(pdev, cxlflash);

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
	cxlflash->parent_dev = to_pci_dev(phys_dev);

	cxlflash->cxl_afu = cxl_pci_to_afu(pdev, NULL);
	rc = cxlflash_init_afu(cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
				 "call to cxlflash_init_afu failed rc=%d!", rc);
		goto out_remove;
	}
	cxlflash->init_state = INIT_STATE_AFU;

	rc = cxlflash_init_pci(cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
				 "call to cxlflash_init_pci failed rc=%d!", rc);
		goto out_remove;
	}
	cxlflash->init_state = INIT_STATE_PCI;

	rc = cxlflash_init_scsi(cxlflash);
	if (rc) {
		cxlflash_dev_err(&pdev->dev,
				 "call to cxlflash_init_scsi failed rc=%d!",
				 rc);
		goto out_remove;
	}
	cxlflash->init_state = INIT_STATE_SCSI;

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;

out_remove:
	cxlflash_remove(pdev);
	goto out;
}

/*
 * PCI device structure
 */
static struct pci_driver cxlflash_driver = {
	.name = CXLFLASH_NAME,
	.id_table = cxlflash_pci_table,
	.probe = cxlflash_probe,
	.remove = cxlflash_remove,
};

/**
 * init_cxlflash() - module entry point
 *
 * Return: 0 on success / non-zero on failure
 */
static int __init init_cxlflash(void)
{
	cxlflash_info("IBM Power CXL Flash Adapter version: %s %s",
		      CXLFLASH_DRIVER_VERSION, CXLFLASH_DRIVER_DATE);

	INIT_LIST_HEAD(&global.luns);
	spin_lock_init(&global.slock);

	return pci_register_driver(&cxlflash_driver);
}

/**
 * exit_cxlflash() - module exit point
 */
static void __exit exit_cxlflash(void)
{
	cxlflash_lun_terminate(&global);

	pci_unregister_driver(&cxlflash_driver);
}

module_init(init_cxlflash);
module_exit(exit_cxlflash);
