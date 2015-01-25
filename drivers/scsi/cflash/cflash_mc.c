
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

#include "mserv.h"

int cflash_disk_attach(struct scsi_device *sdev, void __user *arg)
{
	int rc = 0;
	return rc;
}

#ifdef NEWCXL
int cflash_afu_init(global_t gbp)
{
	struct cxl_context *ctx;
	void __iomem *psa;

	ctx = cxl_dev_context_init(gbp->pdev);
	if (!ctx)
		+ return -ENOMEM;

	/* Allocate AFU generated interrupt handler */
	rc = cxl_allocate_afu_irqs(ctx, 3);
	if (rc)
		goto err1;

	/* Register AFU interrupt 1. */
	rc = cxl_map_afu_irq(ctx, 1, cxl_memcpy_irq_afu, info,
			      "afu1");
	if (!rc)
		goto err2;
	/* Register AFU interrupt 2 for errors. */
		rc = cxl_map_afu_irq(ctx, 2, cxl_memcpy_copy_error, ctx,
				     "err1");
	if (!rc)
		goto err3;
	/* Register AFU interrupt 3 for errors. */
	rc = cxl_map_afu_irq(ctx, 3, cxl_memcpy_psl_error, ctx,
			     "err2");
	if (!rc)
		goto err4;

	/* Register for PSL errors. TODO: implement this */
	//cxl_register_error_irq(dev, flags??, callback function, private data);
	
	/* Map AFU MMIO/Problem space area */
	psa = cxl_psa_map(ctx);
	if (!psa)
		goto err5;
	
	/* Write configuration info to the AFU PSA space */
	out_be64(psa + 0, 0x8000000000000000ULL);


	/* XXX: How do you send the equivalent of CXL_IOCTL_START_WORK
	 * and CXL_IOCTL_GET_PROCESS_ELEMENT
	 */
}
#endif /* NEWCXL */
