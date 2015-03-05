/*
* Copyright 2015 IBM Corp.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version
* 2 of the License, or (at your option) any later version.
*/
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/syscalls.h>

#include "sislite.h"
#include "cflash.h"
#include "cflash_mc.h"
#include "cflash_ba.h"
#include "cflash_ioctl.h"

#define KWNAME_SZ 3
#define PROV_CONVERT_UINT8_ARRAY_UINT16(lo,hi) \
	(((hi)<<8) | (lo))

#define PCI_FORMAT_EYECATCHER   0x82
#define PCI_RO_DATA_EYECATCHER  0x90
#define PCI_RW_DATA_EYECATCHER  0x91
#define PCI_DATA_ENDTAG         0x78


typedef struct  __attribute__((__packed__))prov_pci_vpd_header
{ 
	char    pci_eyecatcher; //must be 0x82 
	uint8_t name_sz[2];     //length of the name field. byte 0 is lo, 
	                        //byte 1 is hi.  
	char    name[1];
}prov_pci_vpd_header_t;

typedef struct  __attribute__((__packed__))prov_pci_vpd_segment
{ 
	char    segment_eyecatcher;  //must be 0x90 or 0x91 
	uint8_t segment_sz[2];       //TOTAL length of the fields. byte 
				     // 0 is lo, byt e 1 is hi.  
				     
	uint8_t    keywords[1];    //variable length VPD data!
}prov_pci_vpd_segment_t;


bool provFindVPDKw(const char* i_kw, 
		   const uint8_t* i_vpd_buffer, 
		   size_t i_vpd_buffer_length, 
		   uint8_t* o_kwdata, 
		   int* io_kwdata_length)
{ 
	//Locals 
	bool l_rc = false; 
	bool l_found_kw = false; 
	prov_pci_vpd_header_t* l_vpd_header = NULL; 
	int l_section_length = 0; 
	uint8_t* l_buffer_ptr = NULL; 

	//+1 b/c we want a terminating null 
	char l_curr_kw_name[KWNAME_SZ + 1] = {0}; 
	
	char l_curr_kw_data[KWDATA_SZ] = {0}; 
	char l_vpd_name[KWDATA_SZ] = {0}; 
	int  l_vpd_name_sz = 0; 
	prov_pci_vpd_segment_t* l_vpd_section = NULL; 

	//get the address of the end of the buffer. note this is the 
	//1st byte PAST the end of the array 
	const uint8_t* l_end_of_buffer = &i_vpd_buffer[i_vpd_buffer_length]; 
	uint8_t l_curr_kw_sz = 0; 

	//Code 
	cflash_dbg("Entry\n"); 

	do { 
		if((i_kw == NULL) || (i_vpd_buffer == NULL) || 
		   (i_vpd_buffer_length == 0) || 
		   (o_kwdata == NULL) || (io_kwdata_length == NULL)) { 
			cflash_err("Invalid or null Args. Unable to parse "
				   "VPD structures.\n"); 
			l_rc = false; 
			break; 
		} 

		//hope for the best 
		l_vpd_header = (prov_pci_vpd_header_t*) i_vpd_buffer; 

		//validate if we have a real PCI VPD or not 
		//we expect read-only data to come first 
		
		if(l_vpd_header->pci_eyecatcher != PCI_FORMAT_EYECATCHER) 
		{ 
			cflash_err
				("This doesn't appear to be valid VPD. " 
			       "PCI eyecatcher = 0x%02x, expected 0x%02x.\n", 
			       l_vpd_header->pci_eyecatcher, 
			       PCI_FORMAT_EYECATCHER); 
			l_rc = false; 
			break; 
		} 
		
		l_vpd_name_sz = 
			PROV_CONVERT_UINT8_ARRAY_UINT16(l_vpd_header->
							name_sz[0], 
							l_vpd_header->
							name_sz[1]); 
		cflash_dbg("Got apparently-valid eyecatcher data. "
			   "Name size is %d.\n", l_vpd_name_sz); 
		
		if(l_vpd_name_sz > KWDATA_SZ) { 
			cflash_info("Warning: Trimming KW Name down to "
				    "%d bytes. Original was %d\n", 
				    KWDATA_SZ, l_vpd_name_sz); 
			l_vpd_name_sz = KWDATA_SZ; 
		} 
		
		memset(l_vpd_name, 0, sizeof(l_vpd_name)); 
		strncpy(l_vpd_name, l_vpd_header->name, l_vpd_name_sz); 
		
		cflash_info("Parsing VPD for '%s'\n", l_vpd_name); 
		
		//get the address of the VPD section that follows the name 
		//by relying on the fact that the name section is an "array" 
		//in the struct, and that we can index into the array for 
		//the length of the KW. For example - a 0-length name 
		//would technically mean that the "name" byte of the struct 
		//represents the next segment of data. A 1-byte name would 
		//get the 2nd byte after, etc.  
		
		l_vpd_section = (prov_pci_vpd_segment_t*)&l_vpd_header->
			name[l_vpd_name_sz]; 
		l_section_length = 
			PROV_CONVERT_UINT8_ARRAY_UINT16(l_vpd_section->
							segment_sz[0], 
							l_vpd_section->
							segment_sz[1]); 

		cflash_dbg("Got %d bytes of RO section data.\n", 
			   l_section_length);

	       	//set up the pointer to the beginning of the keyword data 
		l_buffer_ptr = l_vpd_section->keywords; 
		
		//l_buffer_pt 
		while((l_buffer_ptr < l_end_of_buffer) && 
		      (*l_buffer_ptr != PCI_DATA_ENDTAG)) { 

			memset(l_curr_kw_name, 0, sizeof(l_curr_kw_name)); 
			memset(l_curr_kw_data, 0, sizeof(l_curr_kw_data)); 
			l_curr_kw_sz = 0; 
			
			if(*l_buffer_ptr == PCI_RW_DATA_EYECATCHER) { 
				uint8_t lo = *l_buffer_ptr++; 
				uint8_t hi = *l_buffer_ptr++; 
				l_section_length = 
					PROV_CONVERT_UINT8_ARRAY_UINT16(lo, hi); 
				cflash_info("RW Data section found of "
					    "length %d bytes, starting a "
					    "new section.\n", 
					    l_section_length); 
				continue; //new section found, so continue 
				          //processing 
			} 
			
			//get the name of the KW + its size 
			l_curr_kw_name[0] = *l_buffer_ptr++; 
			l_curr_kw_name[1] = *l_buffer_ptr++; 
			l_curr_kw_sz = *l_buffer_ptr++; 
			cflash_dbg("Current KW: '%s' size = %d\n",
				   l_curr_kw_name, l_curr_kw_sz); 
			
			//copy the data out. note this may copy zero bytes 
			//if the KW is zero length (which seems to be 
			//allowed by the spec).  
			memcpy(l_curr_kw_data, l_buffer_ptr, l_curr_kw_sz); 
			
			//check to see if we found the desired KW!  
			if(0 == strcmp(i_kw, l_curr_kw_name)) { 
				l_found_kw = true;
				break;
		       	} 
			
			//advance the pointer by the size of the KW and 
			//loop again...  
			l_buffer_ptr+=l_curr_kw_sz; 
		
		} //end inner while that is searching the buffer for KW data 
		
		if(l_found_kw) { 
			cflash_info("Found VPD for keyword '%s' "
				    "length %d\n", l_curr_kw_name, 
				    l_curr_kw_sz); 
			
			if(*io_kwdata_length < l_curr_kw_sz) { 
				cflash_dbg("Output buffer %d is too small "
					  "for keyword '%s' data. We need "
					  "at least %d bytes.\n", 
					  *io_kwdata_length, l_curr_kw_name, 
					  l_curr_kw_sz); 
				l_rc = false; 
				break; 
			} 
			else { 
				cflash_dbg("Copying data to output "
					   "buffer...\n"); 
				*io_kwdata_length = l_curr_kw_sz; 
				memcpy(o_kwdata, l_curr_kw_data, l_curr_kw_sz); 
				l_rc = true; 
			} 
		} 
	} while (0); 
	
	//all paths exit via the same return path 
	if(l_rc == false) { 
		//set the output size to 0 for consistency 
		*io_kwdata_length = 0; 
	} 
	return l_rc;
}

