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

#ifndef _CFLASHMC_H
#define _CFLASHMC_H

typedef unsigned int useconds_t;	/* time in microseconds */

/* Max pathlen - e.g. for AFU device path */
#define MC_PATHLEN       64

#define CFLASH_NAFU      2

/*----------------------------------------------------------------------------*/
/* Constants                                                                  */
/*----------------------------------------------------------------------------*/

#define SL_INI_SINI_MARKER      0x53494e49
#define SL_INI_ELMD_MARKER      0x454c4d44
/*----------------------------------------------------------------------------*/
/* Types                                                                      */
/*----------------------------------------------------------------------------*/

struct cflash {
	struct afu *p_afu;
	struct cxl_context *p_ctx;

	struct pci_dev *p_dev;
	struct pci_device_id *p_dev_id;
	struct Scsi_Host *host;

	unsigned long cflash_regs_pci;
	void __iomem *cflash_regs;

	wait_queue_head_t reset_wait_q;
	wait_queue_head_t msi_wait_q;
	wait_queue_head_t eeh_wait_q;

	struct cxl_afu *afu;
	timer_t timer_hb;
	timer_t timer_fc;

	int task_set;
	struct pci_pool *cflash_cmd_pool;
	struct pci_dev *parent_dev;

	int last_lun_index;
};

/* The write_nn or read_nn routines can be used to do byte reversed MMIO
   or byte reversed SCSI CDB/data.
*/
static inline void write_64(volatile u64 * addr, u64 val)
{
	u64 zero = 0;
	asm volatile ("stdbrx %0, %1, %2"::"r" (val), "r"(zero), "r"(addr));
}

static inline void write_32(volatile u32 * addr, u32 val)
{
	u32 zero = 0;
	asm volatile ("stwbrx %0, %1, %2"::"r" (val), "r"(zero), "r"(addr));
}

static inline void write_16(volatile u16 * addr, u16 val)
{
	u16 zero = 0;
	asm volatile ("sthbrx %0, %1, %2"::"r" (val), "r"(zero), "r"(addr));
}

static inline u64 read_64(volatile u64 * addr)
{
	u64 val;
	u64 zero = 0;
	asm volatile ("ldbrx %0, %1, %2":"=r" (val):"r"(zero), "r"(addr));

	return val;
}

static inline u32 read_32(volatile u32 * addr)
{
	u32 val;
	u32 zero = 0;
	asm volatile ("lwbrx %0, %1, %2":"=r" (val):"r"(zero), "r"(addr));

	return val;
}

static inline u16 read_16(volatile u16 * addr)
{
	u16 val;
	u16 zero = 0;
	asm volatile ("lhbrx %0, %1, %2":"=r" (val):"r"(zero), "r"(addr));

	return val;
}

/* mc_stat is analogous to fstat in POSIX. It returns information on
 * a virtual disk.
 *
 * Inputs:
 *   mc_hndl         - client handle that specifies a (context + AFU)
 *   res_hndl        - resource handle identifying the virtual disk
 *                     to query
 *
 * Output:
 *   p_mc_stat       - pointer to location that will contain the
 *                     output data
 */
typedef struct mc_stat_s {
	u32 blk_len;		/* length of 1 block in bytes as reported by
				   device */
	u8 nmask;		/* chunk_size = (1 << nmask) in device blocks */
	u8 rsvd[3];
	u64 size;		/* current size of the res_hndl in chunks */
	u64 flags;		/* permission flags */
} mc_stat_t;

/* In the course of doing IOs, the user may be the first to notice certain
 * critical events on the AFU or the backend storage. mc_notify allows a
 * user to pass such information to the master. The master will verify the
 * events and can take appropriate action.
 *
 * Inputs:
 *   mc_hndl         - client handle that specifies a (context + AFU)
 *                     The event pertains to this AFU.
 *
 *   p_mc_notify     - pointer to location that contains the event
 *
 * Output:
 */
typedef struct mc_notify_s {
	u8 event;		/* MC_NOTIF_xxx */
#define MC_NOTIFY_CMD_TIMEOUT    0x01	/* user command timeout */
#define MC_NOTIFY_SCSI_SENSE     0x02	/* interesting sense data */
#define MC_NOTIFY_AFU_EEH        0x03	/* user detected AFU is frozen */
#define MC_NOTIFY_AFU_RST        0x04	/* user detected AFU has been reset */
#define MC_NOTIFY_AFU_ERR        0x05	/* other AFU error, unexpected response */
	/*
	 * Note: the event must be sent on a mc_hndl_t that pertains to the
	 * affected AFU. This is important when the user interacts with multiple
	 * AFUs.
	 */

	union {
		struct {
			res_hndl_t res_hndl;
		} cmd_timeout;

		struct {
			res_hndl_t res_hndl;
			char data[20];	/* 20 bytes of sense data */
		} scsi_sense;

		struct {
		} afu_eeh;

		struct {
		} afu_rst;

		struct {
		} afu_err;
	};
} mc_notify_t;

int cflash_init_afu(struct cflash *);
void cflash_term_afu(struct cflash *);
struct afu_cmd *get_next_cmd(struct afu *p_afu);
void release_cmd(struct afu_cmd *p_cmd);
#endif /* ifndef _CFLASHMC_H */
