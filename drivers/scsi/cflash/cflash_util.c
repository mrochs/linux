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

#include "cflash.h"
#include "cflash_util.h"
#include "cflash_ioctl.h"

void marshall_virt_to_resize(struct dk_capi_uvirtual *pvirt,
			     struct dk_capi_resize *psize)
{
	psize->version = pvirt->version;
	psize->rsvd[0] = pvirt->rsvd[0];
	psize->rsvd[1] = pvirt->rsvd[1];
	psize->rsvd[2] = pvirt->rsvd[2];
	psize->flags = pvirt->flags;
	psize->return_flags = pvirt->return_flags;
	psize->context_id = pvirt->context_id;
	psize->rsrc_handle = pvirt->rsrc_handle;
	psize->req_size = pvirt->lun_size;
	psize->last_lba = pvirt->last_lba;
}

void marshall_rele_to_resize(struct dk_capi_release *prele,
			     struct dk_capi_resize *psize)
{
	psize->version = prele->version;
	psize->rsvd[0] = prele->rsvd[0];
	psize->rsvd[1] = prele->rsvd[1];
	psize->rsvd[2] = prele->rsvd[2];
	psize->flags = prele->flags;
	psize->return_flags = prele->return_flags;
	psize->context_id = prele->context_id;
	psize->rsrc_handle = prele->rsrc_handle;
}

void marshall_det_to_rele(struct dk_capi_detach *pdet,
			  struct dk_capi_release *prel)
{
	prel->version = pdet->version;
	prel->rsvd[0] = pdet->rsvd[0];
	prel->rsvd[1] = pdet->rsvd[1];
	prel->rsvd[2] = pdet->rsvd[2];
	prel->flags = pdet->flags;
	prel->return_flags = pdet->return_flags;
	prel->context_id = pdet->context_id;
}

void marshall_clone_to_rele(struct dk_capi_clone *pclone,
			    struct dk_capi_release *prel)
{
	prel->version = pclone->version;
	prel->rsvd[0] = pclone->rsvd[0];
	prel->rsvd[1] = pclone->rsvd[1];
	prel->rsvd[2] = pclone->rsvd[2];
	prel->flags = pclone->flags;
	prel->context_id = pclone->context_id_dst;
}

void hexdump(void *data, long len, const char *hdr)
{

	int i, j, k;
	char str[18];
	char *p = (char *)data;

	i = j = k = 0;
	printk("%s: length=%ld\n", hdr ? hdr : "hexdump()", len);

	/* Print each 16 byte line of data */
	while (i < len) {
		if (!(i % 16))	/* Print offset at 16 byte bndry */
			printk("%03x  ", i);

		/* Get next data byte, save ascii, print hex */
		j = (int)p[i++];
		if (j >= 32 && j <= 126)
			str[k++] = (char)j;
		else
			str[k++] = '.';
		printk("%02x ", j);

		/* Add an extra space at 8 byte bndry */
		if (!(i % 8)) {
			printk(" ");
			str[k++] = ' ';
		}

		/* Print the ascii at 16 byte bndry */
		if (!(i % 16)) {
			str[k] = '\0';
			printk(" %s\n", str);
			k = 0;
		}
	}

	/* If we didn't end on an even 16 byte bndry, print ascii for partial
	 * line. */
	if ((j = i % 16)) {
		/* First, space over to ascii region */
		while (i % 16) {
			/* Extra space at 8 byte bndry--but not if we
			 * started there (was already inserted) */
			if (!(i % 8) && j != 8)
				printk(" ");
			printk("   ");
			i++;
		}
		/* Terminate the ascii and print it */
		str[k] = '\0';
		printk("  %s\n", str);
	}

	return;
}

