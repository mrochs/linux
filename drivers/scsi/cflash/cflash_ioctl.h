#ifndef _CFLASHIOCTL_H
#define _CFLASHIOCTL_H

/* Header file to be included in the block library.
 * Contains definitions of structures for ioctls sent from
 * from the block library to the CAPI Flash Adapater Driver
 */

struct dk_capi_path_info { 
	uint16_t path_id;        /* MPIO path identifier  */ 
	dev_t    devno;          /* Device number of the parent adapter */ 
	uint64_t reserved[4];    /* Space for future stuff */
};

struct dk_capi_paths { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint8_t path_count;          /* Entries in passed in path_info array */ 
	uint8_t returned_path_count; /* Total paths for this disk            */ 
	struct dk_capi_path_info path_info[1];   /* Info about each path     */
};

struct dk_capi_attach { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* Path number to attach */ 
	uint16_t num_interrupts;     /* Requested number of interrupts */ 
	uint16_t rsvd[1]; 
	uint64_t flags;              /* Input flags for the attach */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t context_id;         /* Returned context ID */ 
	void *mmio_start;            /* Returned address of MMIO area */ 
	uint64_t mmio_size;          /* Returned size of MMIO area */ 
	uint64_t block_size;         /* Returned block size, in bytes */ 
	uint32_t adap_fd;            /* Returned adapter file descriptor */
};

struct dk_capi_detach { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* Path number to detach */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for detach operation */ 
	uint64_t return_flags;       /* Returned flags from detach */ 
	uint64_t context_id;         /* Context ID to detach */
};

struct dk_capi_udirect { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* MPIO path ID for attach */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for LUN creation */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t context_id;         /* Context ID for the attach */ 
	uint64_t rsrc_handle;        /* Returned resource handle */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t block_size;         /* Returned block size, in bytes */ 
	uint64_t last_lba;           /* Returned last LBA on the device */
};

struct dk_capi_uvirtual { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* MPIO path ID for attach */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for virtual LUN create */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t context_id;         /* Context ID for the attach */ 
	uint64_t rsrc_handle;        /* Returned resource handle */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t block_size;         /* Returned block size, in bytes */ 
	uint64_t last_lba;           /* Returned last LBA of LUN */ 
	uint64_t lun_size;           /* Requested size, blocks */
};

struct dk_capi_release { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* MPIO path ID */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for the release op */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t context_id;         /* Context ID for the attach */ 
	uint64_t rsrc_handle;        /* Resource handle to release */ 
	uint64_t challenge;          /* Validation cookie */
};

struct dk_capi_resize { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* MPIO path ID */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for resize */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t context_id;         /* Context ID of LUN to resize */ 
	uint64_t rsrc_handle;        /* Resource handle of LUN to resize */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t req_size;           /* New requested size, blocks */ 
	uint64_t last_lba;           /* Returned last LBA of LUN */
};

struct dk_capi_verify { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* ID of path to verify */ 
	uint16_t rsvd[2]; 
	uint64_t flags;              /* Flags for verification */ 
	uint64_t return_flags;       /* Returned verification flags */ 
	uint64_t rsrc_handle;        /* Resource handle of LUN */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t hint;               /* Reasons for verify */ 
	uint64_t last_lba;           /* Returned last LBA of device */
};

struct dk_capi_log { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* Path ID to log error against */ 
	uint16_t log_rsvd[2]; 
	uint64_t flags;              /* Flags for error log */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t rsrc_handle;        /* Resource handle to log error against */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t reason;             /* Reason code for error */ 
	char sense_data[256];        /* Sense data to include in error */
};

struct dk_capi_recover_afu { 
	uint16_t version;            /* SCSI_VERSION_0 */ 
	uint16_t path_id;            /* ID of path to recover */ 
	uint16_t ver_rsvd[2]; 
	uint64_t flags;              /* Flags for recovery */ 
	uint64_t return_flags;       /* Returned flags */ 
	uint64_t rsrc_handle;        /* Resource handle for LUN to recover */ 
	uint64_t challenge;          /* Validation cookie */ 
	uint64_t reason;             /* Reason for recovery request */
};


#define CXL_MAGIC 0xCA

#define DK_CAPI_QUERY_PATH        _IOW(CXL_MAGIC, 0x80, struct dk_capi_paths)
#define DK_CAPI_ATTACH            _IOW(CXL_MAGIC, 0x81, struct dk_capi_attach)
#define DK_CAPI_USER_DIRECT       _IOW(CXL_MAGIC, 0x82, struct dk_capi_udirect)
#define DK_CAPI_USER_VIRTUAL      _IOW(CXL_MAGIC, 0x83, struct dk_capi_uvirtual)
#define DK_CAPI_VLUN_RESIZE       _IOW(CXL_MAGIC, 0x84, struct dk_capi_resize)
#define DK_CAPI_RELEASE           _IOW(CXL_MAGIC, 0x85, struct dk_capi_release)
#define DK_CAPI_DETACH            _IOW(CXL_MAGIC, 0x86, struct dk_capi_detach)
#define DK_CAPI_VERIFY            _IOW(CXL_MAGIC, 0x87, struct dk_capi_verify)
#define DK_CAPI_LOG_EVENT         _IOW(CXL_MAGIC, 0x88, struct dk_capi_log)
#define DK_CAPI_RECOVER_AFU       _IOW(CXL_MAGIC, 0x89, struct dk_capi_recover_afu)
#define DK_CAPI_QUERY_EXCEPTIONS  _IOW(CXL_MAGIC, 0x8A, struct dk_capi_log)

#define DK_CAPI_BLOCK		  0x1000
#endif  /* ifndef _CFLASHIOCTL_H */
