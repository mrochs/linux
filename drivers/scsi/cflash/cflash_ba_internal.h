/*
 * CAPI Flash Device Driver
 *
 * Written by: Manoj N. Kumar <kumarmn@us.ibm.com>, IBM Corporation
 *             Matthew R. Ochs <mrochs@us.ibm.com>, IBM Corporation
 *
 * Copyright (C) 2015 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _CFLASH_BA_INTERNAL_H
#define _CFLASH_BA_INTERNAL_H

#include <linux/types.h>

#define MAX_AUN_CLONE_CNT    0xFF

struct ba_lun_info {
	u64 *lun_alloc_map;
	u32 lun_bmap_size;
	u32 total_aus;
	u64 free_aun_cnt;

	/* indices to be used for elevator lookup of free map */
	u32 free_low_idx;
	u32 free_curr_idx;
	u32 free_high_idx;

	unsigned char *aun_clone_map;
};

#endif /* ifndef _CFLASH_BA_INTERNAL_H */
