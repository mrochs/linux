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

#ifndef _MSERVE_H
#define _MSERVE_H

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

/* Sizing parms: same context can be registered multiple times.
   Therefore we allow MAX_CONNS > MAX_CONTEXT.
*/
#define MAX_CONTEXT  SURELOCK_MAX_CONTEXT	/* num contexts per afu */
#define MAX_RHT_PER_CONTEXT 16	/* num resource hndls per context */
#define MAX_CONNS (MAX_CONTEXT*2)	/* num client connections per AFU */
#define MAX_CONN_TO_POLL 64	/* num fds to poll once */
#define NUM_RRQ_ENTRY    16	/* for master issued cmds */
#define NUM_CMDS         16	/* must be <= NUM_RRQ_ENTRY */
#define NUM_FC_PORTS     SURELOCK_NUM_FC_PORTS	/* ports per AFU */

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

/* port online retry intervals */
#define FC_PORT_STATUS_RETRY_CNT 100	/* 100 100ms retries = 10 seconds */
#define FC_PORT_STATUS_RETRY_INTERVAL_US 100000	/* microseconds */

/* flags in IOA status area for host use */
#define B_DONE       0x01
#define B_ERROR      0x02	/* set with B_DONE */
#define B_TIMEOUT    0x04	/* set with B_DONE & B_ERROR */

/* AFU command timeout values */
#define MC_DISCOVERY_TIMEOUT 5	/* 5 secs */
#define MC_AFU_SYNC_TIMEOUT  5	/* 5 secs */

/* AFU command retry limit */
#define MC_RETRY_CNT         5	/* sufficient for SCSI check and
				   certain AFU errors */

/* AFU command room retry limit */
#define MC_ROOM_RETRY_CNT    10

/* AFU heartbeat periodic timer */
#define MC_HB_PERIOD 5		/* 5 secs */

/* FC CRC clear periodic timer */
#define MC_FC_PERIOD  300	/* 5 mins */
#define MC_CRC_THRESH 100	/* threshold in 5 mins */

#define CL_SIZE             128	/* Processor cache line size */
#define CL_SIZE_MASK        0x7F	/* Cache line size mask */

struct scsi_inquiry_page_83_hdr {
	u8 peri_qual_dev_type;
	u8 page_code;
	u16 adtl_page_length;	/* not counting 4 byte hdr */
	/* Identification Descriptor list */
};

struct scsi_inquiry_p83_id_desc_hdr {
	u8 prot_code;		/* Protocol Identifier & Code Set */
#define TEXAN_PAGE_83_DESC_PROT_CODE             0x01u
	u8 assoc_id;		/* PIV/Association/Identifier type */
#define TEXAN_PAGE_83_ASSC_ID_LUN_WWID           0x03u
	u8 reserved;
	u8 adtl_id_length;
	/* Identifier Data */
};

/*
 * A resource handle table (RHT) can be pointed to by multiple contexts.
 * This happens when one context is duped to another.
 * W/o dup, each context has its own resource handles that is visible
 * only from that context.
 *
 * The rht_info refers to all resource handles of a context and not to
 * a particular RHT entry or a single resource handle.
 */
struct rht_info {
	struct sisl_rht_entry *rht_start;	/* initialized at startup */
	int ref_cnt;		/* num ctx_infos pointing to me */
};

/* Single AFU context can be pointed to by multiple client connections.
 * The client can create multiple endpoints (mc_hndl_t) to the same
 * (context + AFU).
 */
struct ctx_info {
	volatile struct sisl_ctrl_map *p_ctrl_map;	/* initialized at startup */

	/* The rht_info pointer is initialized when the context is first
	   registered, can be changed on dup.
	 */
	struct rht_info *p_rht_info;

	/* all dup'ed contexts are in a doubly linked circular list */
	struct ctx_info *p_forw;
	struct ctx_info *p_next;

	int ref_cnt;		/* num conn_infos pointing to me */
};

/* forward decls */
struct capikv_ini_elm;

/* LUN discovery results are in lun_info */
struct lun_info {
	u64 lun_id;		/* from cmd line/cfg file */
	u32 flags;		/* housekeeping */

	struct {
		u8 wwid[16];	/* LUN WWID from page 0x83 (NAA-6) */
		u64 max_lba;	/* from read cap(16) */
		u32 blk_len;	/* from read cap(16) */
	} li;
	int lfd;
	struct cxl_ioctl_start_work work;
	spinlock_t _slock;
	spinlock_t *slock;

	enum open_mode_type mode;
#define LUN_INFO_VALID   0x01
};

/* Block Alocator can be shared between AFUs */
struct blka {
	struct ba_lun ba_lun;	/* single LUN for SureLock */
	u64 nchunk;		/* number of chunks */
	struct mutex mutex;
};

enum undo_level {
	UNDO_NONE = 0,
	UNDO_MLOCK,
	UNDO_TIMER,
	UNDO_AFU_OPEN,
	UNDO_AFU_START,
	UNDO_AFU_MMAP,
	UNDO_OPEN_SOCK,
	UNDO_BIND_SOCK,
	UNDO_LISTEN,
	UNDO_EPOLL_CREATE,
	UNDO_EPOLL_ADD,
	UNDO_AFU_ALL		/* must be last */
};

#define AFU_INIT_INDEX   0	/* first cmd is used in init/discovery,
	                         * free for other use thereafter
				 */
#define AFU_SYNC_INDEX   (NUM_CMDS - 1)	/* last cmd is rsvd for afu sync */

#define CMD_FREE   0x0
#define CMD_IN_USE 0x1
#define CMD_BUFSIZE 0x1000

struct afu_cmd {
	struct sisl_ioarcb_s rcb;	/* IOARCB (cache line aligned) */
	struct sisl_ioasa_s sa;		/* IOASA must follow IOARCB */
	spinlock_t _slock;
	spinlock_t *slock;
	struct timer_list timer;
	char *buf;                      /* per command buffer */
	int slot;
	u8 flag:1;
	u8 special:1;

} __attribute__ ((aligned(0x80)));

struct afu {
	/* Stuff requiring alignment go first. */

	u64 rrq_entry[NUM_RRQ_ENTRY];	/* 128B RRQ (page aligned) */
	/*
	 * Command & data for AFU commands.
	 */
	struct afu_cmd cmd[NUM_CMDS];

	/* Housekeeping data */
	struct ctx_info ctx_info[MAX_CONTEXT];
	struct rht_info rht_info[MAX_CONTEXT];
	struct mutex afu_mutex;	/* for anything that needs serialization
				   e. g. to access afu */
	struct mutex err_mutex;	/* for signalling error thread */
	wait_queue_head_t err_cv;
	int err_flag;
#define E_SYNC_INTR   0x1	/* synchronous error interrupt */
#define E_ASYNC_INTR  0x2	/* asynchronous error interrupt */

	/* AFU Shared Data */
	struct sisl_rht_entry rht[MAX_CONTEXT][MAX_RHT_PER_CONTEXT];
	/* LXTs are allocated dynamically in groups */

	/* AFU HW */
	int afu_fd;
	struct cxl_ioctl_start_work work;
	char event_buf[0x1000];	/* Linux cxl event buffer (interrupts) */
	volatile struct surelock_afu_map *p_afu_map;	/* entire MMIO map */
	volatile struct sisl_host_map *p_host_map;	/* master's sislite host map */
	volatile struct sisl_ctrl_map *p_ctrl_map;	/* master's control map */

	ctx_hndl_t ctx_hndl;	/* master's context handle */
	u64 *p_hrrq_start;
	u64 *p_hrrq_end;
	volatile u64 *p_hrrq_curr;
	unsigned int toggle;
	u64 room;
	u64 hb;

#define CFLASH_MAX_LUNS	512

	/* LUN discovery: one lun_info per path */
	struct lun_info lun_info[CFLASH_MAX_LUNS];

	/* shared block allocator with other AFUs */
	struct blka *p_blka[CFLASH_MAX_LUNS];

} __attribute__ ((aligned(0x1000)));

struct asyc_intr_info {
	u64 status;
	char *desc;
	u8 port;
	u8 action;
#define CLR_FC_ERROR   0x01
#define LINK_RESET     0x02
};

int afu_init(struct afu *p_afu, struct capikv_ini_elm *p_elm);
void undo_afu_init(struct afu *p_afu, enum undo_level level);
int afu_term(struct afu *p_afu);
void afu_err_intr_init(struct afu *p_afu);

void set_port_online(volatile u64 * p_fc_regs);
void set_port_offline(volatile u64 * p_fc_regs);
int wait_port_online(volatile u64 * p_fc_regs,
		     useconds_t delay_us, unsigned int nretry);
int wait_port_offline(volatile u64 * p_fc_regs,
		      useconds_t delay_us, unsigned int nretry);
int afu_set_wwpn(struct afu *p_afu, int port,
		 volatile u64 * p_fc_regs, u64 wwpn);
void afu_link_reset(struct afu *p_afu, int port, volatile u64 * p_fc_regs);

int grow_lxt(struct afu *p_afu,
	     int lun_index,
	     ctx_hndl_t ctx_hndl_u,
	     res_hndl_t res_hndl_u,
	     struct sisl_rht_entry *p_rht_entry,
	     u64 delta, u64 * p_act_new_size);

int shrink_lxt(struct afu *p_afu,
	       int lun_index,
	       ctx_hndl_t ctx_hndl_u,
	       res_hndl_t res_hndl_u,
	       struct sisl_rht_entry *p_rht_entry,
	       u64 delta, u64 * p_act_new_size);

int clone_lxt(struct afu *p_afu,
	      int lun_index,
	      ctx_hndl_t ctx_hndl_u,
	      res_hndl_t res_hndl_u,
	      struct sisl_rht_entry *p_rht_entry,
	      struct sisl_rht_entry *p_rht_entry_src);

struct asyc_intr_info *find_ainfo(u64 status);
void afu_rrq_intr(struct afu *p_afu);
void afu_sync_intr(struct afu *p_afu);
void afu_async_intr(struct afu *p_afu);
void notify_err(struct afu *p_afu, int err_flag);

void *afu_ipc_rx(void *arg);
void *afu_rrq_rx(void *arg);
void *afu_err_rx(void *arg);

void send_cmd(struct afu *p_afu, struct afu_cmd *p_cmd);
void wait_resp(struct afu *p_afu, struct afu_cmd *p_cmd);

int find_lun(struct cflash *p_cflash, u32 port_sel);
int read_cap16(struct afu *p_afu, struct lun_info *p_lun_info, u32 port_sel);
int page83_inquiry(struct afu *p_afu, struct lun_info *p_lun_info,
		   u32 port_sel);
int afu_sync(struct afu *p_afu, ctx_hndl_t ctx_hndl_u, res_hndl_t res_hndl_u,
	     u8 mode);

void print_wwid(u8 * p_wwid, char *ascii_buf);

void periodic_hb(void);
void periodic_fc(void);
void *sig_rx(void *arg);

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

void timer_start(struct timer_list *p_timer, unsigned long timeout_in_jiffies, struct afu *);
void timer_stop(struct timer_list *p_timer, bool sync);

#endif /* _MSERVE_H */
