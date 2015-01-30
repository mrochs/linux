//  IBM_PROLOG_BEGIN_TAG
//  This is an automatically generated prolog.
//
//  $Source: driver/scsi/cflash/cflash_ba_internal.h $
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
#ifndef _CFLASH_BA_INTERNAL_H
#define _CFLASH_BA_INTERNAL_H

#include <linux/types.h>

#define MAX_AUN_CLONE_CNT    0xFF

typedef struct lun_info {
    uint64_t      *lun_alloc_map;
    uint32_t       lun_bmap_size;
    uint32_t       total_aus;
    uint64_t       free_aun_cnt;

    /* indices to be used for elevator lookup of free map */
    uint32_t       free_low_idx;
    uint32_t       free_curr_idx;
    uint32_t       free_high_idx;

    unsigned char *aun_clone_map;
} lun_info_t;

#endif /* ifndef _CFLASH_BA_INTERNAL_H */
