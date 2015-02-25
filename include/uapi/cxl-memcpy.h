/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_MISC_CXL_MEMCPY_HH
#define _UAPI_MISC_CXL_MEMCPY_H

#include <linux/ioctl.h>
#include <uapi/misc/cxl.h>

/* ioctl numbers */
#define CXL_MEMCPY_MAGIC 0xC9
#define CXL_MEMCPY_IOCTL_GET_FD		_IOW(CXL_MEMCPY_MAGIC, 0x00, int)

#define CXL_MEMCPY_IOCTL_GET_FD_MASTER	0x0000000000000001UL
#define CXL_MEMCPY_IOCTL_GET_FD_ALL	0x0000000000000001UL

struct cxl_memcpy_ioctl_get_fd {
	struct cxl_ioctl_start_work work;
	__u64 master;
};

#endif
