//  IBM_PROLOG_BEGIN_TAG
//  This is an automatically generated prolog.
//
//  $Source: drivers/scsi/cflash/cflash_ba.c $
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

#include "cflash_ba.h"
#include "cflash_ba_internal.h"

/**************************************************************
 *                                                            *
 *            LUN BIT map table                               *
 *                                                            *
 *     0    1    2   3   4   5   6   ...    63                *
 *    64   65   66  67  68  69  70   ...   127                *
 *    ......                                                  *
 *                                                            *
 **************************************************************/


/**************************************************************
 *                                                            *
 *                      Defines                               *
 *                                                            *
 **************************************************************/

/* Bit operations */
#define SET_BIT(num, bit_pos)  num |= (uint64_t)0x01 << (63-bit_pos);
#define CLR_BIT(num, bit_pos)  num &= ~((uint64_t)0x01 << (63-bit_pos));
#define TEST_BIT(num, bit_pos)  (num & ((uint64_t)0x01 << (63-bit_pos)))


/**************************************************************
 *                                                            *
 *                Function Prototypes                         *
 *                                                            *
 **************************************************************/
static int find_free_bit(uint64_t lun_map_entry);


/**************************************************************
 *                                                            *
 *                Extern variables                            *
 *                                                            *
 **************************************************************/

extern unsigned int trc_lvl;

static int find_free_bit(uint64_t lun_map_entry) {
    int pos = -1;

    asm volatile ( "cntlzd %0, %1": "=r"(pos) : "r"(lun_map_entry) );
    return pos;
}

int dummy_ba(void) {
	return(find_free_bit(0x0ULL));
}
