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

typedef size_t aun_t;

typedef struct ba_lun {
	uint64_t	lun_id;
	uint64_t	wwpn;
	size_t		lsize;     /* Lun size in number of LBAs             */
	size_t		lba_size;  /* LBA size in number of bytes            */
	size_t		au_size;   /* Allocation Unit size in number of LBAs */
	void	       *ba_lun_handle;
} ba_lun_t;

int ba_init(ba_lun_t *ba_lun);
void ba_terminate(ba_lun_t *ba_lun);
aun_t ba_alloc(ba_lun_t *ba_lun);
int ba_free(ba_lun_t *ba_lun, aun_t to_free);
int ba_clone(ba_lun_t *ba_lun, aun_t to_clone);
uint64_t ba_space(ba_lun_t *ba_lun);

#ifdef BA_DEBUG
void dump_ba_map(ba_lun_t *ba_lun);
void dump_ba_clone_map(ba_lun_t *ba_lun);
#endif

#endif /* _CFLASH_BA_H */
