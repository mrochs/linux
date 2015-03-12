/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _MISC_CXL_H
#define _MISC_CXL_H

#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/interrupt.h>
#include <uapi/misc/cxl.h>

#ifdef CONFIG_CXL_BASE

#define CXL_IRQ_RANGES 4

struct cxl_irq_ranges {
	irq_hw_number_t offset[CXL_IRQ_RANGES];
	irq_hw_number_t range[CXL_IRQ_RANGES];
};

extern atomic_t cxl_use_count;

static inline bool cxl_ctx_in_use(void)
{
       return (atomic_read(&cxl_use_count) != 0);
}

static inline void cxl_ctx_get(void)
{
       atomic_inc(&cxl_use_count);
}

static inline void cxl_ctx_put(void)
{
       atomic_dec(&cxl_use_count);
}

void cxl_slbia(struct mm_struct *mm);

#else /* CONFIG_CXL_BASE */

static inline bool cxl_ctx_in_use(void) { return false; }
static inline void cxl_slbia(struct mm_struct *mm) {}

#endif /* CONFIG_CXL_BASE */


/*
 * Functions to implement vPHB
 *
 * FIXME Remove from here and put these in struct pci_controller and have then
 * override the ppc_md versions.
 */
void cxl_pci_dma_dev_setup(struct pci_dev *pdev);
int cxl_pci_probe_mode(struct pci_bus *bus);
int cxl_msi_check_device(struct pci_dev* pdev, int nvec, int type);
int cxl_setup_msi_irqs(struct pci_dev *pdev, int nvec, int type);
int cxl_teardown_msi_irqs(struct pci_dev *pdev);
int cxl_pci_enable_device_hook(struct pci_dev *dev);
resource_size_t cxl_pci_window_alignment(struct pci_bus *bus,
                                         unsigned long type);
void cxl_pci_reset_secondary_bus(struct pci_dev *dev);



/**** In kernel API below here *******/

/*
 * Get the AFU and configuration record number associated with a particular
 * PCI_dev.  NULL may be pased to cfg_record if it's not required.
 */
struct cxl_afu *cxl_pci_to_afu(struct pci_dev *dev, unsigned int *cfg_record);

/*
 * Get the physical device which the AFU is attached.  We return a device here
 * not a pci_dev.
 */
struct device *cxl_get_phys_dev(struct pci_dev *dev);

/*
 * Initalise a context from a AFU PCI device
 * Should this take a pci_dev or cxl_afu?
 * FIXME: should we specify some context info here like the memory
 */
extern struct cxl_context *cxl_dev_context_init(struct pci_dev *dev);

/*
 * Cleanup context and free it
 */
void cxl_release_context(struct cxl_context *ctx);

/*
 * Allocate AFU interrupts for this context. num=0 will allocate the default
 * for this AFU as given in the AFU descriptor.  Each interrupt to be used must
 * register a handler with cxl_register_afu_irq.  Must be freed after.
 */
int cxl_allocate_afu_irqs(struct cxl_context *cxl, int num);
void cxl_free_afu_irqs(struct cxl_context *cxl);

/*
 * Map a handler for an AFU interrupt associated with a particular
 * context. AFU interrupt numbers start from 1. cookie is private data is that
 * will be provided to the interrupt handler.  Each irq must be unmapped.
 * FIXME: do we want a single unmap call here to free all IRQs at once?
 */
int cxl_map_afu_irq(struct cxl_context *cxl, int num,
		    irq_handler_t handler, void *cookie, char *name);
void cxl_unmap_afu_irq(struct cxl_context *cxl, int num, void *cookie);

/*
 * Start work on the AFU.  This starts an cxl context and associates it with a
 * task.  task == NULL will attach to the kernel context.
 */
int cxl_start_context(struct cxl_context *ctx, u64 wed,
		      struct task_struct *task);

/*
 * Stop a context and remove it from the PSL
 */
void cxl_stop_context(struct cxl_context *ctx);

/*
 * Set a context as a master context
 * NOTE: no way to degrade back to slave, but do we need this?
 */
void cxl_set_master(struct cxl_context *ctx);

/* Attach an fd to a context. */
/* Export all the existing fops so drivers can use them */
int cxl_fd_open(struct inode *inode, struct file *file);
int cxl_fd_release(struct inode *inode, struct file *file);
long cxl_fd_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int cxl_fd_mmap(struct file *file, struct vm_area_struct *vm);
unsigned int cxl_fd_poll(struct file *file, struct poll_table_struct *poll);
ssize_t cxl_fd_read(struct file *file, char __user *buf, size_t count,
			   loff_t *off);

struct file *cxl_get_fd(struct cxl_context *ctx, struct file_operations *fops,
			int *fd);
int cxl_start_work(struct cxl_context *ctx,
		   struct cxl_ioctl_start_work *work);

/* Map and unmap the AFU Problem Space area */
void __iomem *cxl_psa_map(struct cxl_context *ctx);
void cxl_psa_unmap(void __iomem *addr);

/*
 * Register callback on errors.  PSL may generate different types of errors
 * (like slice errors). This will register a callback to get notified of
 * certain types of these errors.  Since multiple drivers may want to register
 * for these interrupts, drivers can't access the raw irq_handler_t.
 * TODO: implement this.
 */
//int cxl_register_error_irq(dev, flags, callback function, private data);

#endif
