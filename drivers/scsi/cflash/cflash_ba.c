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

#include <linux/module.h>
#include <linux/slab.h>

#include "cflash.h"
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


int ba_init(ba_lun_t *ba_lun)
{
	lun_info_t     *lun_info = NULL;
	int		lun_size_au = 0, i = 0;
	int		last_word_underflow = 0;

	/* Allocate lun_fino */
	lun_info = kzalloc(sizeof(lun_info_t), GFP_KERNEL);
	if (!lun_info) {
		cflash_err("block_alloc: Failed to allocate lun_info for lun_id %llX\n",
			ba_lun->lun_id);
		return -ENOMEM;
        }

	cflash_info("block_alloc: Initializing LUN: lun_id = %llX, ba_lun->lsize = %lX, ba_lun->au_size = %lX\n",
		ba_lun->lun_id, ba_lun->lsize, ba_lun->au_size);

	/* Calculate bit map size */
	lun_size_au = ba_lun->lsize / ba_lun->au_size;

	/* XXX - do we need this? Thinking no...how should we handle a 0 lun
	 * size, just return?
	 */
#ifdef _FILEMODE_
	if (lun_size_au == 0)
		lun_size_au = 1;
#endif /* _FILEMODE_ */

	lun_info->total_aus = lun_size_au;
	lun_info->lun_bmap_size = lun_size_au / 64;

	if (lun_size_au % 64)
		lun_info->lun_bmap_size++;

	/* Allocate bitmap space */
	lun_info->lun_alloc_map = kzalloc((lun_info->lun_bmap_size * sizeof(uint64_t)), GFP_KERNEL);
	if (!lun_info->lun_alloc_map) {
		cflash_err("block_alloc: Failed to allocate lun allocation map: lun_id = %llX\n",
			   ba_lun->lun_id);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Initialize the bit map size and set all bits to '1' */
	lun_info->free_aun_cnt = lun_size_au;

	for (i = 0; i < lun_info->lun_bmap_size; i++) {
		lun_info->lun_alloc_map[i] = (uint64_t)~0;
        }

	/* If the last word is not fully utilized, mark the extra bits as allocated */
	last_word_underflow = (lun_info->lun_bmap_size * 64) - lun_info->free_aun_cnt;
	if (last_word_underflow > 0) {
		for (i = (63 - last_word_underflow + 1); i < 64 ; i++) {
			CLR_BIT(lun_info->lun_alloc_map[lun_info->lun_bmap_size-1], i);
		}
        }

	/* Initialize high elevator index, low/curr already at 0 from kzalloc */
	lun_info->free_high_idx = lun_info->lun_bmap_size;

	/* Allocate clone map */
	lun_info->aun_clone_map = kzalloc((lun_info->total_aus * sizeof(uint8_t)), GFP_KERNEL);
	if (!lun_info->aun_clone_map) {
		cflash_err("block_alloc: Failed to allocate clone map: lun_id = %llX\n",
			   ba_lun->lun_id);
            kfree(lun_info->lun_alloc_map);
            kfree(lun_info);
            return -ENOMEM;
        }

	/* Pass the allocated lun info as a handle to the user */
	ba_lun->ba_lun_handle = (void *)lun_info;

	cflash_info("block_alloc: Successfully initialized the LUN: lun_id = %llX, bitmap size = %X, free_aun_cnt = %llX\n",
		ba_lun->lun_id, lun_info->lun_bmap_size, lun_info->free_aun_cnt);
	return 0;
}

static int find_free_bit(uint64_t lun_map_entry)
{
    int pos = -1;

    asm volatile ( "cntlzd %0, %1": "=r"(pos) : "r"(lun_map_entry) );
    return pos;
}

int dummy_ba(void)
{
	return(find_free_bit(0x0ULL));
}
