
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

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_cmnd.h>

#include "cflash.h"

int cflash_disk_attach(struct scsi_device *sdev, void __user *arg)
{
	int rc = 0;
	return rc;
}

