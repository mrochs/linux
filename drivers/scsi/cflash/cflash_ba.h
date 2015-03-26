/*
 * CAPI Flash Device Driver
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

#ifndef _CFLASH_BA_H
#define _CFLASH_BA_H

#include <linux/types.h>

struct ba_lun {
	u64 lun_id;
	u64 wwpn;
	size_t lsize;		/* Lun size in number of LBAs             */
	size_t lba_size;	/* LBA size in number of bytes            */
	size_t au_size;		/* Allocation Unit size in number of LBAs */
	void *ba_lun_handle;
};

int ba_init(struct ba_lun *ba_lun);
void ba_terminate(struct ba_lun *ba_lun);
u64 ba_alloc(struct ba_lun *ba_lun);
int ba_free(struct ba_lun *ba_lun, u64 to_free);
int ba_clone(struct ba_lun *ba_lun, u64 to_clone);
u64 ba_space(struct ba_lun *ba_lun);

#ifdef BA_DEBUG
void dump_ba_map(struct ba_lun *ba_lun);
void dump_ba_clone_map(struct ba_lun *ba_lun);
#endif

#endif /* _CFLASH_BA_H */
