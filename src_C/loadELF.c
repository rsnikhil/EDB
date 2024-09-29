// Copyright (c) 2013-2023 Bluespec, Inc. All Rights Reserved
// Author: Rishiyur S. Nikhil

// Function to read an ELF file and load it into memory on the FPGA

// ================================================================
// Standard C includes

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <gelf.h>
#include <time.h>

// ----------------
// This project

#include "Status.h"
#include "loadELF.h"

// ================================================================
// External functions for reads and writes into target memory

extern
int exec_read_buf (const uint64_t  start_addr,
		   const int       n_bytes,
		   uint8_t        *p_rdata);

extern
int exec_write_buf (const uint64_t  start_addr,
		    const int       n_bytes,
		    const uint8_t  *p_wdata);

// ================================================================
// Features of the ELF binary

typedef struct {
    int       bitwidth;
    uint64_t  min_paddr;
    uint64_t  max_paddr;
    uint64_t  num_bytes_total;

    uint64_t  pc_start;       // Addr of label  '_start'
    uint64_t  pc_exit;        // Addr of label  'exit'
    uint64_t  tohost_addr;    // Addr of label  'tohost'
} Elf_Features;

static const char start_symbol  [] = "_start";
static const char exit_symbol   [] = "exit";
static const char tohost_symbol [] = "tohost";

// ================================================================

// From /usr/include/gelf.h
//    typedef Elf64_Phdr GElf_Phdr;

// From /usr/include/elf.h
//    typedef struct
//    {
//      Elf64_Word    p_type;                 /* Segment type */
//      Elf64_Word    p_flags;                /* Segment flags */
//      Elf64_Off     p_offset;               /* Segment file offset */
//      Elf64_Addr    p_vaddr;                /* Segment virtual address */
//      Elf64_Addr    p_paddr;                /* Segment physical address */
//      Elf64_Xword   p_filesz;               /* Segment size in file */
//      Elf64_Xword   p_memsz;                /* Segment size in memory */
//      Elf64_Xword   p_align;                /* Segment alignment */
//    } Elf64_Phdr;

static
void print_GElf_Phdr_column_names ()
{
    fprintf (stdout, "      ");
    fprintf (stdout, "%16s", "vaddr");
    fprintf (stdout, " %16s", "vaddrlim");
    fprintf (stdout, "    ");
    fprintf (stdout, " %9s", "type");
    fprintf (stdout, " %5s", "flags");
    fprintf (stdout, " %16s", "offset");
    fprintf (stdout, " %8s", "paddr");
    fprintf (stdout, " %8s", "filesz");
    fprintf (stdout, " %8s", "memsz");
    fprintf (stdout, " %8s", "align\n");
}

static
void print_GElf_Phdr (const int index, const GElf_Phdr *p_phdr)
{
    fprintf (stdout, "      ");
    fprintf (stdout, "%016lx",  p_phdr->p_vaddr);
    fprintf (stdout, " %016lx",  p_phdr->p_vaddr + p_phdr->p_memsz);

    fprintf (stdout, " [%02d]", index);
    fprintf (stdout, " %8x",    p_phdr->p_type);
    fprintf (stdout, " %5x",    p_phdr->p_flags);
    fprintf (stdout, " %16lx",  p_phdr->p_offset);
    fprintf (stdout, " %8lx",   p_phdr->p_paddr);
    fprintf (stdout, " %8lx",   p_phdr->p_filesz);
    fprintf (stdout, " %8lx",   p_phdr->p_memsz);
    fprintf (stdout, " %8lx\n", p_phdr->p_align);
}

static
uint64_t fn_vaddr_to_paddr (Elf *e, uint64_t vaddr, uint64_t size)
{
    GElf_Phdr phdr;    // = Elf64_Phdr
    int index = 0;
    const bool verbose = false;

    if (verbose) {
	fprintf (stdout, "    fn_vaddr_to_paddr (vaddr %0" PRIx64 ", size %0" PRIx64 ")\n",
		 vaddr, size);
	fprintf (stdout, "      Searching phdrs\n");
	print_GElf_Phdr_column_names ();
    }

    uint64_t paddr = 0;
    while (gelf_getphdr (e, index, & phdr) != NULL) {
	if (verbose)
	    print_GElf_Phdr (index, & phdr);

	if ((phdr.p_vaddr <= vaddr)
	    && ((vaddr + size) <= (phdr.p_vaddr + phdr.p_memsz))) {

	    uint64_t paddr2 = (vaddr - phdr.p_vaddr) + phdr.p_paddr;

	    if ((paddr != 0) && (paddr != paddr2)) {
		fprintf (stdout, "WARNING: %s: more than one GElf_Phdr match:\n",
			 __FUNCTION__);
		fprintf (stdout, "    vaddr   %08" PRIx64 "\n", vaddr);
		fprintf (stdout, "    paddr 1 %08" PRIx64 "\n", paddr);
		fprintf (stdout, "    paddr 2 %08" PRIx64 " (using this one)\n", paddr2);
	    }
	    paddr = paddr2;
	}
	index++;
    }
    return paddr;
}

// ================================================================
// Readback check
// Note: currently reading back at most first 8 bytes at addr

static
int ELF_readback_check (const int       verbosity,
			const char     *sec_name,
			const uint8_t  *buf,
			const uint64_t  size,
			const uint64_t  addr)
{
    int j;

    if (size < 1) return STATUS_OK;

    // Truncate size to 8 bytes or less
    int size1       = ((size > 8) ? 8 : size);

    if (verbosity != 0)
	fprintf (stdout, "    %s: check %0d bytes at addr %0" PRIx64 "",
		 sec_name, size1, addr);

    // Initialize readback_bytes to something different from buf data
    uint8_t readback_bytes [8];
    memcpy (readback_bytes, buf, size1);
    readback_bytes [0] = ~ (readback_bytes [0]);

    int status = exec_read_buf (addr, size1, readback_bytes);
    if (status != STATUS_OK) {
	fprintf (stdout,
		 "\nERROR: %s: exec_read_buf failed: status %0d\n",
		 __FUNCTION__, status);
	return STATUS_ERR;
    }

    bool err = false;
    for (j = 0; j < size1; j++) {
	if (buf [j] != readback_bytes [j])
	    err = true;
    }
    if (! err) {
	if (verbosity != 0)
	    fprintf (stdout, ": OK\n");
	return STATUS_OK;
    }
    else {
	fprintf (stdout, ": MISMATCH (addr %0" PRIx64 "\n", addr);

	fprintf (stdout, "      expected:");
	for (j = 0; j < size1; j++) fprintf (stdout, " %02x", buf [j]);
	fprintf (stdout, "\n");
	fprintf (stdout, "      readback:");
	for (j = 0; j < size1; j++) fprintf (stdout, " %02x", readback_bytes [j]);
	fprintf (stdout, "\n");
	return STATUS_ERR;
    }
}

// ================================================================
// Scan the ELF file

static
char indent [] = "        ";    // for printfs

// This is only relevant if we include code below that zeroes out .bss
// static
// uint8_t zerobuf [4096] = { 0 };    // 4096 == 0x1000

static
int scan_elf (const int         verbosity,
	      Elf              *e,
	      const GElf_Ehdr  *ehdr,
	      const int         pass,

	      Elf_Features     *p_features)
{
    int status;

    // Grab the string section index
    size_t shstrndx;
    shstrndx = ehdr->e_shstrndx;

    // Iterate through each of the sections looking for code that should be loaded
    Elf_Scn  *scn   = 0;
    GElf_Shdr shdr;

    while ((scn = elf_nextscn (e,scn)) != NULL) {
        // get the header information for this section
        gelf_getshdr (scn, & shdr);

	char *sec_name = elf_strptr (e, shstrndx, shdr.sh_name);
	if ((pass == 1) && (verbosity != 0))
	    fprintf (stdout, "  %s:\n", sec_name);

	Elf_Data *data = 0;
	// 'ALLOC' type sections are candidates to be loaded
	if (shdr.sh_flags & SHF_ALLOC) {
	    data = elf_getdata (scn, data);

	    // data->sh_addr may be virtual; find the phys addr from the segment table
	    uint64_t section_paddr = fn_vaddr_to_paddr (e, shdr.sh_addr, data->d_size);
	    if ((pass == 1) && (verbosity != 0)) {
#if !defined(__APPLE__)
		// Linux
		fprintf (stdout, "%svaddr %10" PRIx64 " to vaddr %10" PRIx64 ";",
			 indent,
			 shdr.sh_addr,
			 shdr.sh_addr + data->d_size);
#else
		// MacOS
		fprintf (stdout, "%svaddr %10lx to vaddr %10lx;",
			 indent,
			 shdr.sh_addr,
			 shdr.sh_addr + data->d_size);
#endif
		fprintf (stdout, " size 0x%lx (=%0ld)\n", data->d_size, data->d_size);
		fprintf (stdout, "        paddr %10" PRIx64 "\n",
			 section_paddr);
	    }

	    // Record some features
	    if (pass == 1) {
		if (section_paddr < p_features->min_paddr)
		    p_features->min_paddr = section_paddr;
		if (p_features->max_paddr < (section_paddr + data->d_size - 1))
		    p_features->max_paddr = section_paddr + data->d_size - 1;
		p_features->num_bytes_total += data->d_size;
	    }

	    if (data->d_size == 0) {
		if ((pass == 1) && (verbosity != 0)) {
		    fprintf (stdout, "%s", indent);
		    fprintf (stdout, "Ignoring size 0 section\n");
		}
	    }
	    else {
		uint64_t addr   = section_paddr;
		uint64_t size   = data->d_size;
		uint8_t *buf    = data->d_buf;

		if (pass == 1) {
		    // Pass 1: load the section bits into memory

		    if (shdr.sh_type != SHT_NOBITS) {
			if (verbosity != 0) {
			    fprintf (stdout, "%s", indent);
			    fprintf (stdout,
				     "Loading addr %0" PRIx64 ", size %0" PRIx64 "\n",
				     addr, size);
			}
			status = exec_write_buf (addr, size, buf);
			if (status != STATUS_OK) {
			    fprintf (stdout,
				     "ERROR: %s: exec_write_buf failed: status %0d\n",
				     __FUNCTION__, status);
			    return STATUS_ERR;
			}
		    }
		    else if ((strcmp (sec_name, ".bss") == 0)
			     || (strcmp (sec_name, ".sbss") == 0)) {
			if (verbosity != 0) {
			    fprintf (stdout, "%s", indent);
			    fprintf (stdout, ".bss/.sbss: addr %0" PRIx64, addr);
			    fprintf (stdout, " size %0" PRIx64 "\n", size);
			    fprintf (stdout, "%s... not loadable\n", indent);
			}

			/* This code zeroes out .bss memory, 4K page at a time.
			uint64_t addr1  = addr;
			uint64_t size1  = 0;
			while ((addr1 + size1) <= (addr + size)) {
			    size1 = (addr + size) - addr1;
			    if (size1 > 4096)
				size1 = 4096;
			    if (verbosity != 0) {
				fprintf (stdout, "%sLoading", indent);
				fprintf (stdout, " addr1 %0" PRIx64, addr1);
				fprintf (stdout, ", size1 %0" PRIx64, size1);
				fprintf (stdout, " with zeroes\n");
			    }
			    status = exec_write_buf (addr1, size1, zerobuf);
			    if (status != STATUS_OK) {
				fprintf (stdout,
					 "ERROR: %s: exec_write_buf failed: status %0d\n",
					 __FUNCTION__, status);
				return STATUS_ERR;
			    }
			    addr1 += 4096;
			}
			*/
		    }
		    else {
			if (verbosity != 0) {
			    fprintf (stdout, "%sIgnoring ELF section", indent);
			    fprintf (stdout, " (shdr.sh_type == SHT_NOBITS)\n");
			}
		    }
		}
		else {
		    // Pass 2: read-back check: sample up to 8 bytes at buf[0]
		    // TODO: should we sample some more points?

		    if (shdr.sh_type != SHT_NOBITS) {
			status = ELF_readback_check (verbosity, sec_name, buf, size, addr);
			if (status != STATUS_OK)
			    return STATUS_ERR;
		    }
		    else if ((strcmp (sec_name, ".bss") == 0)
			     || (strcmp (sec_name, ".sbss") == 0)) {
			status = STATUS_OK;

			/* This code checks if bss is zero; is relevant only
			   if we zero'd bss during loading.
			uint64_t size1 = ((size > 4096) ? 4096 : size);
			status = ELF_readback_check (verbosity,
						     sec_name, zerobuf, size1, addr);
			if (status != STATUS_OK)
			    return STATUS_ERR;
			*/
		    }
		    else {
			if (verbosity != 0) {
			    fprintf (stdout, "    No bits to load\n");
			}
		    }
		}
	    }
	}

	// In pass 1, if we find the symbol table, search for symbols of interest
	else if ((shdr.sh_type == SHT_SYMTAB)
		 && (pass == 1)
		 && (verbosity != 0)) {
	    fprintf (stdout, "    Searching for symbols  '%s'  '%s'  '%s'\n",
		     start_symbol, exit_symbol, tohost_symbol);

 	    // Get the section data
	    data = elf_getdata (scn, data);

	    // Get the number of symbols in this section
	    int symbols = shdr.sh_size / shdr.sh_entsize;

	    // search for the uart_default symbols we need to potentially modify.
	    GElf_Sym sym;
	    int i;
	    for (i = 0; i < symbols; ++i) {
	        // get the symbol data
	        gelf_getsym (data, i, &sym);

		// get the name of the symbol
		char *name = elf_strptr (e, shdr.sh_link, sym.st_name);

		// Look for, and remember PC of the start symbol
		if (strcmp (name, start_symbol) == 0) {
		    p_features->pc_start = fn_vaddr_to_paddr (e, sym.st_value, 4);
		}
		// Look for, and remember PC of the exit symbol
		else if (strcmp (name, exit_symbol) == 0) {
		    p_features->pc_exit = fn_vaddr_to_paddr (e, sym.st_value, 4);
		}
		// Look for, and remember addr of 'tohost' symbol
		else if (strcmp (name, tohost_symbol) == 0) {
		    // tohost usually is in MMIO space, won't have a virtual address
		    // p_features->tohost_addr = fn_vaddr_to_paddr (e, sym.st_value, 4);
		    p_features->tohost_addr = sym.st_value;
		}
	    }

	    fprintf (stdout, "    _start");
	    if (p_features->pc_start == -1)
		fprintf (stdout, "    Not found\n");
	    else
		fprintf (stdout, "    %0" PRIx64 "\n", p_features->pc_start);

	    fprintf (stdout, "    exit  ");
	    if (p_features->pc_exit == -1)
		fprintf (stdout, "    Not found\n");
	    else
		fprintf (stdout, "    %0" PRIx64 "\n", p_features->pc_exit);

	    fprintf (stdout, "    tohost");
	    if (p_features->tohost_addr == -1)
		fprintf (stdout, "    Not found\n");
	    else
		fprintf (stdout, "    %0" PRIx64 "\n", p_features->tohost_addr);
	}

	else {
	    if ((pass == 1) && (verbosity != 0)) {
		fprintf (stdout, "%sIgnoring ELF section:",
			 indent);
		fprintf (stdout, " shdr.sh_flags [SHF_ALLOC] is false\n");
	    }
	}
    }
    return STATUS_OK;
}

// ================================================================
// Load an ELF file from named file.
// Returns STATUS_OK on success,
// else STATUS_ERR (multiple possible reasons).

int loadELF (const int   verbosity,
	     const bool  do_readback_check,
	     const char *elf_filename)
{
    Elf_Features  elf_features;
    Elf          *e;
    int           status;

    // Verify the elf library version
    if (elf_version (EV_CURRENT) == EV_NONE) {
	fprintf (stdout,
		 "ERROR: %s: Failed to initialize the libelf library.\n",
		 __FUNCTION__);
	status = STATUS_ERR;
	goto done2;
    }

    // Open the file for reading
    int fd = open (elf_filename, O_RDONLY, 0);
    if (fd < 0) {
	fprintf (stdout,
		 "ERROR: could not open ELF file: %s\n",
		 elf_filename);
	status = STATUS_ERR;
	goto done2;
    }

    // Initialize the Elf object with the open file
    e = elf_begin (fd, ELF_C_READ, NULL);
    if (e == NULL) {
	fprintf (stdout, "ERROR: %s: elf_begin() initialization failed!\n",
		 __FUNCTION__);
	status = STATUS_ERR;
	goto done;
    }

    // Verify that the file is an ELF file
    if (elf_kind (e) != ELF_K_ELF) {
	if (verbosity != 0)
	    fprintf (stdout, "  '%s' is not an ELF file\n", elf_filename);
        elf_end (e);
	status = STATUS_ERR;
	goto done;
    }

    // Get the ELF header
    GElf_Ehdr ehdr;
    if (gelf_getehdr (e, & ehdr) == NULL) {
	fprintf (stdout, "ERROR: %s: get_getehdr() failed: %s\n",
		 __FUNCTION__, elf_errmsg (-1));
        elf_end (e);
	status = STATUS_ERR;
	goto done;
    }

    // Is this a 32b or 64 ELF?
    if (gelf_getclass (e) == ELFCLASS32) {
	if (verbosity != 0)
	    fprintf (stdout, "  This is a 32-bit ELF file\n");
	elf_features.bitwidth = 32;
    }
    else if (gelf_getclass (e) == ELFCLASS64) {
	if (verbosity != 0)
	    fprintf (stdout, "  This is a 64-bit ELF file\n");
	elf_features.bitwidth = 64;
    }
    else {
	fprintf (stdout, "ERROR: ELF file '%s' is not 32b or 64b\n",
		 elf_filename);
        elf_end (e);
	status = STATUS_ERR;
	goto done;
    }

    // ----------------
    // Verify ELF is for RISC-V (e_machine = 0xF3 = 243)
    // https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc
    // http://www.sco.com/developers/gabi/latest/ch4.eheader.html
#ifndef EM_RISCV
    // This is for elf lib on MacOS (Ventura 13.1, 2023-01-31) where EM_RISCV is not defined
#define EM_RISCV 0xF3
#endif
    if (ehdr.e_machine != EM_RISCV) {
	fprintf (stdout,
		 "ERROR: %s: %s is not a RISC-V ELF file?\n",
		 __FUNCTION__, elf_filename);
        elf_end (e);
	status = STATUS_ERR;
	goto done;
    }

    // ----------------
    // Verify we are dealing with a little endian ELF
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
	fprintf (stdout,
		 "ERROR: %s is big-endian, not supported\n",
		 elf_filename);
        elf_end (e);
	status = STATUS_ERR;
	goto done;
    }

    // ----------------------------------------------------------------
    // Ok, all checks done, ready to read the ELF and load it.

    fprintf (stdout, "Loading ELF file into RISC-V memory:\n");
    fprintf (stdout, "    %s\n", elf_filename);

    elf_features.bitwidth        = 0;
    elf_features.min_paddr       = 0xFFFFFFFFFFFFFFFFllu;
    elf_features.max_paddr       = 0x0000000000000000llu;
    elf_features.num_bytes_total = 0;
    elf_features.pc_start        = 0xFFFFFFFFFFFFFFFFllu;
    elf_features.pc_exit         = 0xFFFFFFFFFFFFFFFFllu;
    elf_features.tohost_addr     = 0xFFFFFFFFFFFFFFFFllu;

    // ----------------------------------------------------------------
    // Pass 1: Extract ELF payload and write to target mem

    struct timespec ts1, ts2;
    int pass;

    clock_gettime (CLOCK_REALTIME, & ts1);
    pass   = 1;
    status = scan_elf (verbosity, e, & ehdr, pass, & elf_features);
    clock_gettime (CLOCK_REALTIME, & ts2);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: %s: scan_elf failed: status %0d\n",
		 __FUNCTION__, status);
	status = STATUS_ERR;
	goto done;
    }
    fprintf (stdout, "  ELF load complete\n");

    // Report bandwidth
    uint64_t nsecs = (((ts2.tv_sec * 1000000000) + ts2.tv_nsec)
		      - ((ts1.tv_sec * 1000000000) + ts1.tv_nsec));
    if (nsecs != 0) {
	uint64_t bytes_per_sec = ((elf_features.num_bytes_total * 1000000000)
				  / nsecs);
	fprintf (stdout,
		 "  Transfer rate: %0" PRId64 " bytes/sec", bytes_per_sec);
	fprintf (stdout,
		 " (%0" PRId64 " bytes in %0" PRId64 " nsecs)\n",
		 elf_features.num_bytes_total, nsecs);
    }

    // Report features
    if (verbosity != 0) {
	uint64_t span = elf_features.max_paddr + 1 - elf_features.min_paddr;
	fprintf (stdout,
		 "    Size: 0x%0" PRIx64 " (%0" PRId64 ") bytes\n",
		 elf_features.num_bytes_total, elf_features.num_bytes_total);
	fprintf (stdout,
		 "    Min paddr: %10" PRIx64 "\n", elf_features.min_paddr);
	fprintf (stdout,
		 "    Max paddr: %10" PRIx64 "\n", elf_features.max_paddr);
	fprintf (stdout,
		 "    Span:      %10" PRIx64 " (=%0" PRId64 ") bytes\n",
		 span, span);
    }

    // ----------------------------------------------------------------
    // Pass 2: readback check

    if (do_readback_check) {
	fprintf (stdout, "  Readback check\n");
	pass = 2;
	status = scan_elf (verbosity, e, & ehdr, pass, & elf_features);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: %s: scan_elf failed: status %0d\n",
		     __FUNCTION__, status);
	}
	else
	    fprintf (stdout, "  Readback check complete\n");
    }

    // Close elf object
    elf_end (e);

    status = STATUS_OK;

 done:
    if (fd >= 0) close (fd);
 done2:
    return status;
}

// ================================================================
