/*
 * CAPI Flash Device Driver
 *
 * Written by: Manoj N. Kumar <kumarmn@us.ibm.com>, IBM Corporation
 *             Matthew R. Ochs <mrochs@us.ibm.com>, IBM Corporation
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

#define KWDATA_SZ  256		//max size of a VPD buffer
#define KWNAME_SZ 3
#define PROV_CONVERT_UINT8_ARRAY_UINT16(lo,hi) \
	(((hi)<<8) | (lo))

#define PCI_FORMAT_EYECATCHER   0x82
#define PCI_RO_DATA_EYECATCHER  0x90
#define PCI_RW_DATA_EYECATCHER  0x91
#define PCI_DATA_ENDTAG         0x78

typedef struct __attribute__ ((__packed__)) prov_pci_vpd_header {
	char pci_eyecatcher;	//must be 0x82 
	u8 name_sz[2];		//length of the name field. byte 0 is lo, 
	//byte 1 is hi.  
	char name[1];
} prov_pci_vpd_header_t;

typedef struct __attribute__ ((__packed__)) prov_pci_vpd_segment {
	char segment_eyecatcher;	//must be 0x90 or 0x91 
	u8 segment_sz[2];	//TOTAL length of the fields. byte 
	// 0 is lo, byt e 1 is hi.  

	u8 keywords[1];		//variable length VPD data!
} prov_pci_vpd_segment_t;

bool prov_find_vpd_kw(const char *i_kw,
		      const u8 * i_vpd_buffer,
		      size_t i_vpd_buffer_length,
		      u8 * o_kwdata, int *io_kwdata_length);


void marshall_virt_to_resize(struct dk_capi_uvirtual *pvirt, 
			     struct dk_capi_resize *psize);

void marshall_rele_to_resize(struct dk_capi_release *prele, 
			     struct dk_capi_resize *psize);
void marshall_det_to_rele(struct dk_capi_detach *pdet, 
			  struct dk_capi_release *prel);
void marshall_clone_to_rele(struct dk_capi_clone *pclone,
			    struct dk_capi_release *prel);

void hexdump(void *data, long len, const char *hdr);

#endif /* ifndef _CFLASHUTIL_H */
