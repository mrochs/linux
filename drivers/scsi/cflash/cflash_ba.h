//  IBM_PROLOG_BEGIN_TAG
//  This is an automatically generated prolog.
//
//  $Source: drivers/scsi/cflash/cflash_ba.h $
//
//  IBM CONFIDENTIAL
//
//  COPYRIGHT International Business Machines Corp. 2015
//
//  p1
//
//  Object Code Only (OCO) source materials
//  Licensed Internal Code Source Materials
//  IBM Surelock Licensed Internal Code
//
//  The source code for this program is not published or other-
//  wise divested of its trade secrets, irrespective of what has
//  been deposited with the U.S. Copyright Office.
//
//  Origin: 30
//
//  IBM_PROLOG_END
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
