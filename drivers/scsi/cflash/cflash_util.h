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

#ifndef _CFLASHUTIL_H
#define _CFLASHUTIL_H

#include "cflash_ioctl.h"

void marshall_virt_to_resize(struct dk_capi_uvirtual *pvirt,
			     struct dk_capi_resize *psize);

void marshall_rele_to_resize(struct dk_capi_release *prele,
			     struct dk_capi_resize *psize);
void marshall_det_to_rele(struct dk_capi_detach *pdet,
			  struct dk_capi_release *prel);
void marshall_clone_to_rele(struct dk_capi_clone *pclone,
			    struct dk_capi_release *prel);

#endif /* ifndef _CFLASHUTIL_H */
