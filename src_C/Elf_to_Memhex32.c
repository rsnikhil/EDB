// Copyright (c) 2013-2024 Bluespec, Inc. All Rights Reserved
// Author: Rishiyur S. Nikhil
// Some fragments taken from earlier version of Catamaran

// Program to convert an ELF file into a memhex32 file.
// Run with --help or with no command-line args for help.

// ================================================================
// Includes from C library

// General
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>    // for tolower()
#include <errno.h>
#include <time.h>
#include <assert.h>

// ================================================================
// Includes for this project

#include "Status.h"
#include "loadELF.h"

// ================================================================

void print_usage (FILE *fo, const int argc, char *argv[])
{
    fprintf (fo, "Usage:\n");
    fprintf (fo, "  %s  <filename.elf (input)>  <filename.memhex32 (output)>\n", argv [0]);
    fprintf (fo, "  Converts ELF file into Memhex32 file\n");
}

// ****************************************************************
// Store-buffer
// loadELF() emits stream of (addr, byte) into this store-buffer.
// It buffers up to four bytes, 4-byte aligned
// It writes out the buffer when addr is for a different word than buf_addr.

static int64_t   last_addr_written = -8;
static int64_t   buf_addr = -8;
static uint32_t  buf_data;
static uint8_t  *p = NULL;

static
void emit (FILE *fp_out, int64_t addr, uint8_t byte)
{
    p = (uint8_t *) (& buf_data);

    if (addr < buf_addr) {
	fprintf (stdout, "WARNING: addr %08" PRIx64 " is < last addr %08" PRIx64 "\n",
		 addr, buf_addr);
	// exit (1);
    }

    int64_t addr_aligned = ((addr >> 2) << 2);
    uint8_t lsbs         = (addr & 0x3);

    if (buf_addr < 0) buf_addr = addr_aligned;    // On first invocation

    if (buf_addr != addr_aligned) {
	// Write out the buffer
	// Write out addr line if needed
	if ((last_addr_written + 4) != buf_addr) {
	    fprintf (fp_out, "@%0" PRIx64 "    // ---- %0" PRIx64 "\n",
		     buf_addr >> 2, buf_addr);
	}
	// Write out data
	// fprintf (fp_out, "%08x\n", buf_data);
	fprintf (fp_out, "%08x     // %08" PRIx64 "\n", buf_data, buf_addr);
	last_addr_written = buf_addr;

	buf_addr = addr_aligned;
	buf_data = 0;
    }

    if (! (buf_addr == addr_aligned)) {
	fprintf (stdout, "ERROR: %s: buf_addr:%08" PRIx64 "  addr_aligned %08" PRIx64 "\n",
		 __FUNCTION__, buf_addr, addr_aligned);
	assert (buf_addr == addr_aligned);
    }

    // Merge-in the new byte
    // fprintf (stdout, "DEBUG: p[%0d] = %02x\n", lsbs, byte);
    p [lsbs] = byte;
}

static
void flush_emit_buffer (FILE *fp_out)
{
    if (buf_addr >= 0) {
	// Write out the buffer
	// Write out addr line if needed
	if (buf_addr != last_addr_written) {
	    fprintf (fp_out, "@%0" PRIx64 "    // ---- %0" PRIx64 "\n",
		     buf_addr >> 2, buf_addr);
	}
	// Write out data
	fprintf (fp_out, "%08x  // %08" PRIx64 "\n", buf_data, buf_addr);
	last_addr_written = buf_addr;
    }
}

// ****************************************************************
// External functions called by loadELF to read/write memory

FILE *fo_memhex32 = NULL;

int exec_write_buf (const uint64_t  start_addr,
		    const int       n_bytes,
		    const uint8_t  *p_wdata)
{
    fprintf (stdout, "        STUB write_buf %0d bytes to addr %0" PRIx64 "\n",
	     n_bytes, start_addr);
    for (int j = 0; j < n_bytes; j++)
	emit (fo_memhex32, start_addr + j, p_wdata [j]);
    return STATUS_OK;
}

int exec_read_buf (const uint64_t  start_addr,
		   const int       n_bytes,
		   uint8_t        *p_rdata)
{
    fprintf (stdout, "        STUB read_buf %0d bytes from addr %0" PRIx64 "\n",
	     n_bytes, start_addr);
    return STATUS_OK;
}

// ****************************************************************

int main (int argc, char *argv[])
{
    if ((argc <= 1)
	|| (argc != 3)
	|| (strcmp (argv [0], "-h") == 0)
	|| (strcmp (argv [1], "--help") == 0)) {
	print_usage (stdout, argc, argv);
	return 0;
    }

    fo_memhex32 = fopen (argv [2], "w");
    if (fo_memhex32 == NULL) {
	fprintf (stdout, "ERROR: unable to open output file for memhex32: %s\n", argv [2]);
    }

    const int  verbosity         = 0;
    const bool do_readback_check = false;
    int status = loadELF (verbosity, do_readback_check, argv [1]);

    flush_emit_buffer (fo_memhex32);
    fclose (fo_memhex32);

    return ((status == STATUS_OK) ? 0 : 1);
}

// ================================================================
