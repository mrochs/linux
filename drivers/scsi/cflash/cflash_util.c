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

bool prov_find_vpd_kw(const char *i_kw,
		      const u8 * i_vpd_buffer,
		      size_t i_vpd_buffer_length,
		      u8 * o_kwdata, int *io_kwdata_length)
{
	/* Locals  */
	bool l_rc = false;
	bool l_found_kw = false;
	prov_pci_vpd_header_t *l_vpd_header = NULL;
	int l_section_length = 0;
	u8 *l_buffer_ptr = NULL;

	/* 1 b/c we want a terminating null  */
	char l_curr_kw_name[KWNAME_SZ + 1] = { 0 };

	char l_curr_kw_data[KWDATA_SZ] = { 0 };
	char l_vpd_name[KWDATA_SZ] = { 0 };
	int l_vpd_name_sz = 0;
	prov_pci_vpd_segment_t *l_vpd_section = NULL;

	/* get the address of the end of the buffer. note this is the
	 * 1st byte PAST the end of the array
	 */

	const u8 *l_end_of_buffer = &i_vpd_buffer[i_vpd_buffer_length];
	u8 l_curr_kw_sz = 0;

	/* Code  */
	cflash_dbg("Entry");

	do {
		if ((i_kw == NULL) || (i_vpd_buffer == NULL) ||
		    (i_vpd_buffer_length == 0) ||
		    (o_kwdata == NULL) || (io_kwdata_length == NULL)) {
			cflash_err("Invalid or null Args. Unable to parse "
				   "VPD structures.");
			l_rc = false;
			break;
		}
		/* hope for the best  */
		l_vpd_header = (prov_pci_vpd_header_t *) i_vpd_buffer;

		/* validate if we have a real PCI VPD or not
		 * we expect read-only data to come first
		 */

		if (l_vpd_header->pci_eyecatcher != PCI_FORMAT_EYECATCHER) {
			cflash_err("This doesn't appear to be valid VPD. "
			     "PCI eyecatcher = 0x%02x, expected 0x%02x.",
			     l_vpd_header->pci_eyecatcher,
			     PCI_FORMAT_EYECATCHER);
			l_rc = false;
			break;
		}

		l_vpd_name_sz =
		    PROV_CONVERT_UINT8_ARRAY_UINT16(l_vpd_header->name_sz[0],
						    l_vpd_header->name_sz[1]);
		cflash_dbg("Got apparently-valid eyecatcher data. "
			   "Name size is %d.", l_vpd_name_sz);

		if (l_vpd_name_sz > KWDATA_SZ) {
			cflash_info("Warning: Trimming KW Name down to "
				    "%d bytes. Original was %d",
				    KWDATA_SZ, l_vpd_name_sz);
			l_vpd_name_sz = KWDATA_SZ;
		}

		memset(l_vpd_name, 0, sizeof(l_vpd_name));
		strncpy(l_vpd_name, l_vpd_header->name, l_vpd_name_sz);

		cflash_info("Parsing VPD for '%s'", l_vpd_name);

		/* get the address of the VPD section that follows the name
		 * by relying on the fact that the name section is an "array"
		 * in the struct, and that we can index into the array for
		 * the length of the KW. For example - a 0-length name
		 * would technically mean that the "name" byte of the struct
		 * represents the next segment of data. A 1-byte name would
		 * get the 2nd byte after, etc.
		 */

		l_vpd_section =
		    (prov_pci_vpd_segment_t *) &
		    l_vpd_header->name[l_vpd_name_sz];
		l_section_length =
		    PROV_CONVERT_UINT8_ARRAY_UINT16(l_vpd_section->segment_sz
						    [0],
						    l_vpd_section->segment_sz
						    [1]);

		cflash_dbg("Got %d bytes of RO section data.",
			   l_section_length);

		/* set up the pointer to the beginning of the keyword data */
		l_buffer_ptr = l_vpd_section->keywords;

		/* l_buffer_pt */
		while ((l_buffer_ptr < l_end_of_buffer) &&
		       (*l_buffer_ptr != PCI_DATA_ENDTAG)) {

			memset(l_curr_kw_name, 0, sizeof(l_curr_kw_name));
			memset(l_curr_kw_data, 0, sizeof(l_curr_kw_data));
			l_curr_kw_sz = 0;

			if (*l_buffer_ptr == PCI_RW_DATA_EYECATCHER) {
				u8 lo = *l_buffer_ptr++;
				u8 hi = *l_buffer_ptr++;
				l_section_length =
				    PROV_CONVERT_UINT8_ARRAY_UINT16(lo, hi);
				cflash_info("RW Data section found of "
					    "length %d bytes, starting a "
					    "new section.", l_section_length);
				continue;	/* new section found, so
						 * continue processing
						 */
			}
			/* get the name of the KW + its size */
			l_curr_kw_name[0] = *l_buffer_ptr++;
			l_curr_kw_name[1] = *l_buffer_ptr++;
			l_curr_kw_sz = *l_buffer_ptr++;
			cflash_dbg("Current KW: '%s' size = %d",
				   l_curr_kw_name, l_curr_kw_sz);

			/* copy the data out. note this may copy zero bytes
			 * if the KW is zero length (which seems to be
			 * allowed by the spec).
			 */
			memcpy(l_curr_kw_data, l_buffer_ptr, l_curr_kw_sz);

			/* check to see if we found the desired KW!   */
			if (0 == strcmp(i_kw, l_curr_kw_name)) {
				l_found_kw = true;
				break;
			}
			/* advance the pointer by the size of the KW and
			 * loop again...
			 */
			l_buffer_ptr += l_curr_kw_sz;

		}/* end inner while that is searching the buffer for KW data */

		if (l_found_kw) {
			cflash_info("Found VPD for keyword '%s' length %d",
				    l_curr_kw_name, l_curr_kw_sz);

			if (*io_kwdata_length < l_curr_kw_sz) {
				cflash_dbg("Output buffer %d is too small "
					   "for keyword '%s' data. We need "
					   "at least %d bytes.",
					   *io_kwdata_length, l_curr_kw_name,
					   l_curr_kw_sz);
				l_rc = false;
				break;
			} else {
				cflash_dbg("Copying data to output buffer...");
				*io_kwdata_length = l_curr_kw_sz;
				memcpy(o_kwdata, l_curr_kw_data, l_curr_kw_sz);
				l_rc = true;
			}
		}
	} while (0);

	/* all paths exit via the same return path */
	if (l_rc == false) {
		/* set the output size to 0 for consistency  */
		*io_kwdata_length = 0;
	}
	return l_rc;
}

void marshall_virt_to_resize(struct dk_capi_uvirtual *pvirt,
			     struct dk_capi_resize *psize)
{
	psize->version = pvirt->version;
	psize->path_id = pvirt->path_id;
	psize->rsvd[0] = pvirt->rsvd[0];
	psize->rsvd[1] = pvirt->rsvd[1];
	psize->flags = pvirt->flags;
	psize->return_flags = pvirt->return_flags;
	psize->context_id = pvirt->context_id;
	psize->rsrc_handle = pvirt->rsrc_handle;
	psize->challenge = pvirt->challenge;
	psize->req_size = pvirt->lun_size;
	psize->last_lba = pvirt->last_lba;
}

void marshall_rele_to_resize(struct dk_capi_release *prele,
			     struct dk_capi_resize *psize)
{
	psize->version = prele->version;
	psize->path_id = prele->path_id;
	psize->rsvd[0] = prele->rsvd[0];
	psize->rsvd[1] = prele->rsvd[1];
	psize->flags = prele->flags;
	psize->return_flags = prele->return_flags;
	psize->context_id = prele->context_id;
	psize->rsrc_handle = prele->rsrc_handle;
	psize->challenge = prele->challenge;
}

void marshall_det_to_rele(struct dk_capi_detach *pdet,
			  struct dk_capi_release *prel)
{
	prel->version = pdet->version;
	prel->path_id = pdet->path_id;
	prel->rsvd[0] = pdet->rsvd[0];
	prel->rsvd[1] = pdet->rsvd[1];
	prel->flags = pdet->flags;
	prel->return_flags = pdet->return_flags;
	prel->context_id = pdet->context_id;
}

void marshall_clone_to_rele(struct dk_capi_clone *pclone,
			    struct dk_capi_release *prel)
{
	prel->version = pclone->version;
	prel->path_id = pclone->path_id;
	prel->rsvd[0] = pclone->rsvd[0];
	prel->rsvd[1] = pclone->rsvd[1];
	prel->flags = pclone->flags;
	prel->context_id = pclone->context_id_dst;
	prel->challenge = pclone->challenge_dst;
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

