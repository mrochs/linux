/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>

#include "cxl.h"

struct cxl_context *cxl_dev_context_init(struct pci_dev *dev)
{
	struct cxl_afu *afu;
	struct cxl_context  *ctx;
	int rc;

	afu = cxl_pci_to_afu(dev, NULL);

	ctx = cxl_context_alloc();
	if (IS_ERR(ctx))
		return ctx;

	/* Make it a slave context.  We can promote it later? */
	rc = cxl_context_init(ctx, afu, false);
	if (rc) {
		kfree(ctx);
		return ERR_PTR(-ENOMEM);
	}

	return ctx;
}
EXPORT_SYMBOL_GPL(cxl_dev_context_init);

struct device *cxl_get_phys_dev(struct pci_dev *dev)
{
	struct cxl_afu *afu;

	afu = cxl_pci_to_afu(dev, NULL);

	return afu->adapter->dev.parent;
}
EXPORT_SYMBOL_GPL(cxl_get_phys_dev);

void cxl_release_context(struct cxl_context *ctx)
{
	cxl_context_free(ctx);
}
EXPORT_SYMBOL_GPL(cxl_release_context);

int cxl_allocate_afu_irqs(struct cxl_context *ctx, int num)
{
	if (num == 0)
		num = ctx->afu->pp_irqs;
	return afu_allocate_irqs(ctx, num);
}
EXPORT_SYMBOL_GPL(cxl_allocate_afu_irqs);

void cxl_free_afu_irqs(struct cxl_context *ctx)
{
	cxl_release_irq_ranges(&ctx->irqs, ctx->afu->adapter);
}
EXPORT_SYMBOL_GPL(cxl_free_afu_irqs);

static irq_hw_number_t cxl_find_afu_irq(struct cxl_context *ctx, int num)
{
	__u16 range;
	int r;

	WARN_ON(num == 0);

	for (r = 0; r < CXL_IRQ_RANGES; r++) {
		range = ctx->irqs.range[r];
		if (num < range) {
			return ctx->irqs.offset[r] + num;
		}
		num -= range;
	}
	return 0;
}

int cxl_map_afu_irq(struct cxl_context *ctx, int num,
		    irq_handler_t handler, void *cookie, char *name)
{
	irq_hw_number_t hwirq;

	/*
	 * Find interrupt we are to register.
	 */
	hwirq = cxl_find_afu_irq(ctx, num);
	if (!hwirq)
		return -ENOENT;

	return cxl_map_irq(ctx->afu->adapter, hwirq, handler, cookie, name);
}
EXPORT_SYMBOL_GPL(cxl_map_afu_irq);

void cxl_unmap_afu_irq(struct cxl_context *ctx, int num, void *cookie)
{
	irq_hw_number_t hwirq;
	unsigned int virq;

	hwirq = cxl_find_afu_irq(ctx, num);
	if (!hwirq)
		return;

	virq = irq_find_mapping(NULL, hwirq);
	if (virq)
		cxl_unmap_irq(virq, cookie);
}
EXPORT_SYMBOL_GPL(cxl_unmap_afu_irq);

/*
 * Start a context
 * Code here similar to afu_ioctl_start_work().
 */
int cxl_start_context(struct cxl_context *ctx, u64 wed,
		      struct task_struct *task)
{
	int rc;
	bool kernel = true;

	pr_devel("%s: pe: %i\n", __func__, ctx->pe);

	mutex_lock(&ctx->status_mutex);
	if (ctx->status != OPENED) {
		rc = -EIO;
		goto out;
	}
	if (task) {
		ctx->pid = get_task_pid(task, PIDTYPE_PID);
		get_pid(ctx->pid);
		kernel = false;
	}

	/* FIXME: if userspace, then set amr here */
	if ((rc = cxl_attach_process(ctx, kernel, wed , 0)))
		goto out;

	ctx->status = STARTED;
	rc = 0;
out:
	mutex_unlock(&ctx->status_mutex);
	return rc;
}
EXPORT_SYMBOL_GPL(cxl_start_context);

/* Stop a context */
void cxl_stop_context(struct cxl_context *ctx)
{
	___detach_context(ctx);
}
EXPORT_SYMBOL_GPL(cxl_stop_context);

void cxl_set_master(struct cxl_context *ctx)
{
	ctx->master = true;
	assign_psn_space(ctx);
}
EXPORT_SYMBOL_GPL(cxl_set_master);

int cxl_attach_fd(struct cxl_context *ctx, struct cxl_ioctl_start_work *work)
{
	struct file *file;
	int rc, flags, fd;

	flags = O_RDWR | O_CLOEXEC;

	/* This code is similar to anon_inode_getfd() */
	rc = get_unused_fd_flags(flags);
	if (rc < 0)
		return rc;
	fd = rc;

	file = anon_inode_getfile("cxl", &afu_fops, ctx, flags);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		goto err;
	}

	/* code taken from afu_ioctl_start_work */
	if (!(work->flags & CXL_START_WORK_NUM_IRQS))
		work->num_interrupts = ctx->afu->pp_irqs;
	else if ((work->num_interrupts < ctx->afu->pp_irqs) ||
		 (work->num_interrupts > ctx->afu->irqs_max)) {
		rc = -EINVAL;
		goto err1;
	}
	if ((rc = afu_register_irqs(ctx, work->num_interrupts)))
		goto err1;

	rc = cxl_start_context(ctx, work->work_element_descriptor, current);
	if (rc < 0)
		goto err2;

	fd_install(fd, file);
	/* once we do fd_install we are not allowed to fail */
	return fd;

err2:
	afu_release_irqs(ctx, ctx);
err1:
	fput(file);
err:
	put_unused_fd(fd);
	return rc;
}
EXPORT_SYMBOL_GPL(cxl_attach_fd);

void __iomem *cxl_psa_map(struct cxl_context *ctx)
{
	struct cxl_afu *afu = ctx->afu;
	int rc;

	rc = afu_check_and_enable(afu);
	if (rc)
		return NULL;

	pr_devel("%s: psn_phys%llx size:%llx\n",
		 __func__, afu->psn_phys, afu->adapter->ps_size);
	return ioremap(afu->psn_phys, afu->adapter->ps_size);
}
EXPORT_SYMBOL_GPL(cxl_psa_map);

void cxl_psa_unmap(void __iomem *addr)
{
	iounmap(addr);
}
EXPORT_SYMBOL_GPL(cxl_psa_unmap);
