// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// Test_loadELF
// Standalone test for loadELF

// ****************************************************************
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

static
void print_usage (FILE *fo, int argc, char *argv [])
{
    fprintf (fo, "Usage:\n");
    fprintf (fo, "  %s    <elf-file-name>    Displays details about the ELF file\n",
	     argv [0]);
}

// ================================================================
// Stubs of functions invoked by loadELF.c

int exec_write_buf (const uint64_t  start_addr,
		    const int       n_bytes,
		    const uint8_t  *p_wdata)
{
    fprintf (stdout, "        STUB write_buf %0d bytes to addr %0" PRIx64 "\n",
	     n_bytes, start_addr);
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

// ================================================================

int main (int argc, char *argv [])
{
    for (int j = 1; j < argc; j++) {
	if ((strcmp (argv [j], "-h") == 0)
	    || (strcmp (argv [j], "--help") == 0)) {
	    print_usage (stdout, argc, argv);
	    return 0;
	}
    }

    if ((argc != 2)
	fprintf (stdout, "ERROR: expecting one command-line arg\n");
	print_usage (stdout, argc, argv);
	return 1;
    }

    const int  verbosity         = 1;
    const bool do_readback_check = false;
    int status = loadELF (verbosity, do_readback_check, argv [1]);

    return ((status == STATUS_OK) ? 0 : 1);
}
