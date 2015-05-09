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

#ifndef _CXLFLASH_SUPERPIPE_H
#define _CXLFLASH_SUPERPIPE_H

extern u32 checkpid;
extern u32 internal_lun;
extern u32 ws;

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

#define MAX_AUN_CLONE_CNT    0xFF

/*
 * Terminology: use afu (and not adapter) to refer to the HW.
 * Adapter is the entire slot and includes PSL out of which
 * only the AFU is visible to user space.
 */

/* Chunk size parms: note sislite minimum chunk size is
   0x10000 LBAs corresponding to a NMASK or 16.
*/
#define MC_RHT_NMASK      16	/* in bits */
#define MC_CHUNK_SIZE     (1 << MC_RHT_NMASK)	/* in LBAs, see mclient.h */
#define MC_CHUNK_SHIFT    MC_RHT_NMASK	/* shift to go from LBA to chunk# */
#define MC_CHUNK_OFF_MASK (MC_CHUNK_SIZE - 1)	/* apply to LBA get offset
						   into a chunk */
#define LXT_LUNIDX_SHIFT  8	/* LXT entry, shift for LUN index */

/* LXT tables are allocated dynamically in groups. This is done to
   avoid a malloc/free overhead each time the LXT has to grow
   or shrink.

   Based on the current lxt_cnt (used), it is always possible to
   know how many are allocated (used+free). The number of allocated
   entries is not stored anywhere.

   The LXT table is re-allocated whenever it needs to cross into
   another group.
*/
#define LXT_GROUP_SIZE          8
#define LXT_NUM_GROUPS(lxt_cnt) (((lxt_cnt) + 7)/8)	/* alloc'ed groups */

#define MC_DISCOVERY_TIMEOUT 5  /* 5 secs */

/* SCSI Defines                                                          */

struct request_sense_data  {
	uint8_t     err_code;        /* error class and code   */
	uint8_t     rsvd0;
	uint8_t     sense_key;
#define CXLFLASH_VENDOR_UNIQUE         0x09
#define CXLFLASH_EQUAL_CMD             0x0C
	uint8_t     sense_byte0;
	uint8_t     sense_byte1;
	uint8_t     sense_byte2;
	uint8_t     sense_byte3;
	uint8_t     add_sense_length;
	uint8_t     add_sense_byte0;
	uint8_t     add_sense_byte1;
	uint8_t     add_sense_byte2;
	uint8_t     add_sense_byte3;
	uint8_t     add_sense_key;
	uint8_t     add_sense_qualifier;
	uint8_t     fru;
	uint8_t     flag_byte;
	uint8_t     field_ptrM;
	uint8_t     field_ptrL;
};

#endif /* ifndef _CXLFLASH_SUPERPIPE_H */
