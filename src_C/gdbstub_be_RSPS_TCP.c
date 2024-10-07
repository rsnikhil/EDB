// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved
//
// 'gdbstub_be_RSPS' is a library of functions invoked by EDB's main,
// or by the front end (fe) of gdbstub:
// 
//                   +-------- EDB ---------+
//                   |                      |     RSPS/   +-----+
//                   |main| gdbstub_be_RSPS |<c---TCP---s>|RISCV|
//                   +----+-----------------+             +-----+
//
//  +----+           +------ gdbstub -------+
//  |GDB/|    RSP/   |                      |     RSPS    +-----+
//  |LLDB|<c--TCP--s>| fe | gdbstub_be_RSPS |<c---TCP---s>|RISCV|
//  +----+           +----+-----------------+             +-----+
//
// Notes:
//   EDB          is our "Economical/Elementary Debugger"
//   RISCV        is a RISC-V implementation (simulation or hardware)
//   RSP          "Remote Serial Protocol (ASCII)", GDB/LLDB standard,
//                 here transported over a TCP link.
//                 Encodes debugger transactions as ASCII text strings.
//   RSPS         "Remote Serial Protocol (Structural)",
//                 here transported over a TCP link.
//                 Encodes debugger transactions as (bytes of a) C struct.
//   <c--TCP--s>  is a TCP connection between client 'c' and server 's'.
//
// Contrast with 'gdbstub_be_DMI' (elsewhere):
//   All 'gdbstub_be_*.c' files implement the API declared in 'gdbstub_be.h'.
//   gdbstub_be_RSPS.c
//       communicates with RISC-V using RSPS
//   gdbstub_be_DMI.c
//       communicates with RISC-V using DMI (standad Debug Module
//       Interface for standard RISC-V Debug Module).

// ----------------
// Acknowledgements
//
// Portions of TCP code here adapted from example ECHOSERV
//   ECHOSERV
//   (c) Paul Griffiths, 1999
//   http://www.paulgriffiths.net/program/c/echoserv.php
//
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

// For comms polling
#include <poll.h>

// For TCP
#include <sys/socket.h>       //  socket definitions
#include <sys/types.h>        //  socket types
#include <arpa/inet.h>        //  inet (3) funtions
#include <fcntl.h>            // To set non-blocking mode

// ================================================================
// Includes for this project

#include "Status.h"
#include "TCP_Client_Lib.h"
#include "Dbg_Pkts.h"
#include "ISA_Defs.h"
#include "gdbstub_be.h"
#include "loadELF.h"

// ****************************************************************
// Global vars

// ================================================================
// This file's verbosity

static
int verbosity = 0;

// ================================================================
// Word bitwidth (32 for RV32, 64 for RV64)
// This defaults to 64 (for RV64), but can be set to 32.
// If gdbstub_be_elf_load() is invoked, it'll be picked up from the ELF file.

uint8_t gdbstub_be_xlen = 64;

// ================================================================
// Default hostname and TCP port for remote RISCV server

static char     server_hostname [] = "127.0.0.1";    // (localhost)
static uint16_t server_listen_port = 30000;

// ****************************************************************
// EDB communication with RISC-V system

// File for logging communications with CPU
FILE *flog = NULL;

// ================================================================
// Packet send/recv to RISC-V server

typedef enum { DONT_POLL, DO_POLL } Poll;

static
int send_to_RISCV (const char *context, Dbg_to_CPU_Pkt *p_pkt_out)
{
    if (flog != NULL)
	print_to_CPU_pkt (flog, "Sending ", p_pkt_out, "\n");

    int status = tcp_client_send (sizeof (Dbg_to_CPU_Pkt),
				  (uint8_t *) p_pkt_out);
    if (status == STATUS_ERR) {
	fprintf (stdout, "ERROR: in %s.%s.tcp_client_send()\n", context, __FUNCTION__);
	return STATUS_ERR;
    }
    return STATUS_OK;
}

static
int recv_from_RISCV (const char *context, const Poll poll, Dbg_from_CPU_Pkt *p_pkt_in)
{
    bool do_poll = (poll == DO_POLL);
    int  status  = tcp_client_recv (do_poll,
				    sizeof (Dbg_from_CPU_Pkt),
				    (uint8_t *) p_pkt_in);
    if (status == STATUS_ERR)
	fprintf (stdout, "ERROR: %s.%s.tcp_client_recv()\n", context, __FUNCTION__);

    else if (status == STATUS_OK) {
	if (flog != NULL)
	    print_from_CPU_pkt (flog, "Received", p_pkt_in, "\n");
    }
    else {
	assert (status == STATUS_UNAVAIL);
	// 'unavailable' is only legal if we are polling
	assert (do_poll);
    }
    return status;
}

// ****************************************************************
// Help functions

// ================================================================
// Pretty-print 32-bit value of RISC-V CSR DCSR

void fprintf_dcsr_cause (FILE *fd, const char *pre, const uint32_t dcsr, const char *post)
{
    fprintf (fd, "%s", pre);
    uint32_t cause = DCSR_CAUSE (dcsr);
    switch (cause) {
    case dcsr_cause_EBREAK:       fprintf (stdout, "EBREAK");       break;
    case dcsr_cause_TRIGGER:      fprintf (stdout, "TRIGGER");      break;
    case dcsr_cause_HALTREQ:      fprintf (stdout, "HALTREQ");      break;
    case dcsr_cause_STEP:         fprintf (stdout, "STEP");         break;
    case dcsr_cause_RESETHALTREQ: fprintf (stdout, "RESETHALTREQ"); break;
    case dcsr_cause_GROUP:        fprintf (stdout, "GROUP");        break;
    case dcsr_cause_OTHER:        fprintf (stdout, "OTHER");        break;
    default:                      fprintf (stdout, "cause:%0d", cause);
    }
    fprintf (fd, "%s", post);
}

static
void fprintf_dcsr (FILE *fd, const uint32_t dcsr)
{
    // Line 1
    fprintf (fd, "  DCSR {");
    fprintf (fd, "debugver:%0d",   ((dcsr >> 28) & 0xF));
    fprintf (fd, " extcause:%0d",  ((dcsr >> 24) & 0x7));
    fprintf (fd, " cetrig:%0d",    ((dcsr >> 19) & 0x1));
    fprintf (fd, "\n");

    // Line 2
    fprintf (fd, "        ");
    fprintf (fd, "ebreak(vs:%0d",  ((dcsr >> 17) & 0x1));
    fprintf (fd, " vu:%0d",        ((dcsr >> 16) & 0x1));
    fprintf (fd, " m:%0d",         ((dcsr >> 15) & 0x1));
    fprintf (fd, " s:%0d",         ((dcsr >> 13) & 0x1));
    fprintf (fd, " u:%0d)",        ((dcsr >> 12) & 0x1));
    fprintf (fd, " stepie:%0d",    ((dcsr >> 11) & 0x1));
    fprintf (fd, " stopcount:%0d", ((dcsr >> 10) & 0x1));
    fprintf (fd, " stoptime:%0d",  ((dcsr >>  9) & 0x1));
    fprintf (fd, "\n");

    // Line 3
    fprintf_dcsr_cause (fd, "        cause:", dcsr, "\n");

    fprintf (fd, " v:%0d",         ((dcsr >>  5) & 0x1));
    fprintf (fd, " mprven:%0d",    ((dcsr >>  4) & 0x1));
    fprintf (fd, " nmip:%0d",      ((dcsr >>  3) & 0x1));
    fprintf (fd, " step:%0d",      ((dcsr >>  2) & 0x1));
    fprintf (fd, " prv:%0d",       ((dcsr >>  0) & 0x3));
    fprintf (fd, "}\n");
}

// ================================================================
// Read and print RISC-V CSR DPC

static
void read_and_fprintf_dpc ()
{
    // Read DPC
    uint64_t dpc;
    int status = gdbstub_be_CSR_read (gdbstub_be_xlen, addr_csr_dpc, & dpc);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: attempting to read DPC\n");
	return;
    }
    fprintf (stdout, "  DPC %08" PRIx64 "\n", dpc);
}

// ****************************************************************
// Internal functions to read/write from GPR, FPR, CSR

// ================================================================
// Internal function to read GPR/FPR/CSR/Mem

static
int read_internal (const Dbg_RW_Target target,
		   const uint64_t      addr,
		   const Dbg_RW_Size   rw_size,    // 1/2/4/8
		   uint64_t           *p_rdata)
{
    int status;

    // Send request
    Dbg_to_CPU_Pkt  pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type  = Dbg_to_CPU_RW;
    pkt_out.rw_op     = Dbg_RW_READ;
    pkt_out.rw_size   = rw_size;
    pkt_out.rw_target = target;
    pkt_out.rw_addr   = addr;
    pkt_out.rw_wdata  = 0xAAAAAAAA;    // bogus value

    status = send_to_RISCV (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;
	    
    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;

    *p_rdata = pkt_in.payload;
    return ((pkt_in.pkt_type == Dbg_from_CPU_RW_OK) ? STATUS_OK : STATUS_ERR);
}

// ================================================================
// Internal function to write GPR/FPR/CSR/Mem

static
int write_internal (const Dbg_RW_Target target,
		    const uint64_t      addr,
		    const Dbg_RW_Size   rw_size,    // 1/2/4/8
		    const uint64_t      wdata)
{
    int status;

    // Send request
    Dbg_to_CPU_Pkt  pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type  = Dbg_to_CPU_RW;
    pkt_out.rw_op     = Dbg_RW_WRITE;
    pkt_out.rw_size   = rw_size;
    pkt_out.rw_target = target;
    pkt_out.rw_addr   = addr;
    pkt_out.rw_wdata  = wdata;

    status = send_to_RISCV (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;

    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;
    return ((pkt_in.pkt_type == Dbg_from_CPU_RW_OK) ? STATUS_OK : STATUS_ERR);
}

// ****************************************************************
// gdbstub_be functions, implementing the API in 'gdbstub_be.h',
// here communicating with RSPS packets.

// ================================================================
// Help
// Return a help string for GDB to print out,
// listing which 'monitor' commands are available

static const char help_msg[] =
    "monitor help                       Print this help message\n"
    "monitor verbosity n                Set verbosity of HW simulation to n\n"
    "monitor xlen n                     Set XLEN to n (32 or 64 only)\n"
    "monitor reset_dm                   Perform Debug Module DM_RESET\n"
    "monitor reset_ndm                  Perform Debug Module NDM_RESET\n"
    "monitor reset_hart                 Perform Debug Module HART_RESET\n"
    "elf_load filename                  Load ELF file into RISC-V memory\n"
    ;

const char *gdbstub_be_help (void)
{
    return help_msg;
}

// ================================================================
// Initialize gdbstub_be

uint32_t  gdbstub_be_init (FILE *logfile, bool autoclose)
{
    flog = logfile;

    // Open TCP connection to remote RISC-V server
    int status = tcp_client_open (server_hostname, server_listen_port);
    if (status == STATUS_ERR) {
	fprintf (stdout, "ERROR: tcp_client_open\n");
	return status;
    }

    return STATUS_OK;
}

// ================================================================
// Final actions for gdbstub_be

uint32_t  gdbstub_be_final (const uint8_t xlen)
{
    int             status;
    Dbg_to_CPU_Pkt  pkt_out;

    // Send QUIT
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_QUIT;
    send_to_RISCV (__FUNCTION__, & pkt_out);

    // Wait 1 sec so 'QUIT' message has time to reach stub
    sleep (1);

    status = tcp_client_close (0);
    if (status == STATUS_ERR)
	fprintf (stdout, "ERROR: tcp_client_close\n");
    return status;
}

// ================================================================
// Reset the Debug Module

uint32_t  gdbstub_be_dm_reset (const uint8_t xlen)
{
    fprintf (stdout, "UNIMPLEMENTED: %s ()\n", __FUNCTION__);
    return STATUS_ERR;
}

// ================================================================
// Reset the NDM (non-debug module, i.e., everything but the debug module)
// The argument indicates whether the hart is running/halted after reset

uint32_t  gdbstub_be_ndm_reset (const uint8_t xlen, bool haltreq)
{
    fprintf (stdout, "UNIMPLEMENTED: %s ()\n", __FUNCTION__);
    return STATUS_ERR;
}

// ================================================================
// Reset the HART 
// The argument indicates whether the hart is running/halted after reset

uint32_t  gdbstub_be_hart_reset (const uint8_t xlen, bool haltreq)
{
    fprintf (stdout, "UNIMPLEMENTED: %s ()\n", __FUNCTION__);
    return STATUS_ERR;
}

// ================================================================
// Set verbosity to n in RISC-V system

uint32_t gdbstub_be_verbosity (uint32_t n)
{
    fprintf (stdout, "UNIMPLEMENTED: %s ()\n", __FUNCTION__);
    return STATUS_ERR;
}

// ================================================================
// Load ELF file into RISC-V memory

uint32_t gdbstub_be_elf_load (const char *elf_filename)
{
    const int  verbosity         = 0;
    const bool do_readback_check = true;
    int status = loadELF (verbosity, do_readback_check, elf_filename);
    return status;
}

// ================================================================
// Continue the HW execution at given PC

uint32_t gdbstub_be_continue (const uint8_t xlen)
{
    int              status;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    // Resume request
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_RISCV (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK)
	return status;

    // ----------------
    // Await RUNNING confirmatino
    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;

    if (pkt_in.pkt_type != Dbg_from_CPU_RUNNING) {
	fprintf (stdout, "ERROR: continue command: did not get RUNNING confirmation\n");
	return STATUS_ERR;
    }
    return STATUS_OK;
}

// ================================================================
// Step the HW execution at given PC

uint32_t  gdbstub_be_step (const uint8_t xlen)
{
    int              status;
    uint64_t         data;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    if (verbosity != 0)
	fprintf (stdout, "  Setting CSR DCSR [step] bit\n");

    // Read CSR DCSR
    status = read_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, & data);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: attempting to read CSR DCSR\n");
	return status;
    }

    // Set the 'step' bit
    data = data | mask_dcsr_step;

    // Write CSR DCSR
    status = write_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, data);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: attempting to read write DCSR\n");
	return status;
    }

    // ----------------
    if (verbosity != 0)
	fprintf (stdout, "  Resume execution (for stepi)\n");

    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_RISCV (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;

    // ----------------
    if (verbosity != 0)
	fprintf (stdout, "  Awaiting RUNNING confirmation (for stepi)\n");

    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;
    if (pkt_in.pkt_type != Dbg_from_CPU_RUNNING) {
	fprintf (stdout, "ERROR: stepi command: did not get RUNNING confirmation\n");
	return STATUS_ERR;
    }

    // ----------------
    if (verbosity != 0)
	fprintf (stdout, "  Awaiting HALTED from remote CPU (after stepi)\n");

    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;
    if (pkt_in.pkt_type != Dbg_from_CPU_HALTED) {
	fprintf (stdout, "ERROR: stepi command: did not get HALTED confirmation\n");
	return STATUS_ERR;
    }

    if (verbosity != 0) {
	fprintf (stdout, "  CPU halted (after stepi)\n");
	fprintf_dcsr (stdout, pkt_in.payload);
	read_and_fprintf_dpc ();
    }

    return STATUS_OK;
}

// ================================================================
// Stop CPU execution

uint32_t  gdbstub_be_stop (const uint8_t xlen)
{
    int              status;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // Send HALTREQ
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_HALTREQ;
    status = send_to_RISCV (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;

    // Wait for HALTED or ERR response
    status = recv_from_RISCV (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;

    if (pkt_in.pkt_type == Dbg_from_CPU_HALTED) {
	if (verbosity != 0) {
	    fprintf (stdout, "  CPU halted\n");
	    fprintf_dcsr (stdout, pkt_in.payload);
	    read_and_fprintf_dpc ();
	}
    }
    else if (pkt_in.pkt_type == Dbg_from_CPU_ERR) {
	fprintf (stdout, "  HALTREQ response is 'error'; CPU may be halted already?\n");
	status = STATUS_ERR;
    }
    else {
	fprintf (stdout, "ERROR: Unexpected response for HALTREQ\n");
	fprintf (stdout, "       Expecting HALTED confirmation\n");
	status = STATUS_ERR;
    }
    return status;
}

// ================================================================
// Poll the CPU connection for a HALTED message, if any

uint32_t  gdbstub_be_poll_for_halted (const uint8_t xlen)
{
    Dbg_from_CPU_Pkt  pkt_in;
    int status = recv_from_RISCV (__FUNCTION__, DO_POLL, & pkt_in);

    if (status != STATUS_OK)
	return status;

    else if (pkt_in.pkt_type == Dbg_from_CPU_HALTED) {
	if (verbosity != 0) {
	    fprintf (stdout, "  CPU halted\n");
	    fprintf_dcsr (stdout, pkt_in.payload);
	    read_and_fprintf_dpc ();
	}
	return STATUS_OK;
    }
    else {
	fprintf (stdout, "ERROR: continue command: did not get HALTED confirmation\n");
	return STATUS_ERR;
    }
}

// ================================================================
// Get stop-reason from HW
// (HW normally stops due to GDB ^C, after a 'step', or at a breakpoint)
// Implented as reading DCSR.CAUSE

int32_t  gdbstub_be_get_stop_reason (const uint8_t  xlen,
				     uint8_t       *p_stop_reason,
				     bool           commands_preempt)
{
    uint64_t dcsr;
    int status = gdbstub_be_CSR_read (xlen, addr_csr_dcsr, & dcsr);
    if (status != STATUS_OK)
	return status;
    uint32_t cause = DCSR_CAUSE (dcsr);
    *p_stop_reason = cause;
    return STATUS_OK;
}

// ================================================================
// This is not a debugger function at all, just an aid for humans
// perusing the logfile.  A GDB command can result in several DMI
// commands. This function writes a separation marker into the log
// file, so that it is easy to group sets of DMIs command and
// responses corresponding to a single GDB command.

uint32_t  gdbstub_be_start_command (const uint8_t xlen)
{
    if (flog != NULL)
	fprintf (flog, "---------------- start command\n");
    return STATUS_OK;
}

// ================================================================
// Read a value from the PC
// Implemented as reading CSR DPC

uint32_t  gdbstub_be_PC_read (const uint8_t xlen, uint64_t *p_PC)
{
    return gdbstub_be_CSR_read (xlen, addr_csr_dpc, p_PC);
}

// ================================================================
// Read a value from a GPR register in SoC

uint32_t  gdbstub_be_GPR_read (const uint8_t xlen, uint8_t regnum, uint64_t *p_regval)
{
    *p_regval = 0;

    Dbg_RW_Target target  = Dbg_RW_GPR;
    Dbg_RW_Size   rw_size = ((xlen == 32) ? Dbg_MEM_4B : Dbg_MEM_8B);
    int status = read_internal (target, regnum, rw_size, p_regval);
    return status;
}

// ================================================================
// Read a value from a FPR register in SoC

uint32_t  gdbstub_be_FPR_read (const uint8_t xlen, uint8_t regnum, uint64_t *p_regval)
{
    *p_regval = 0;

    fprintf (stdout, "UNIMPLEMENTED: %s (..,%0d,..)\n", __FUNCTION__, regnum);
    return STATUS_ERR;
}

// ================================================================
// Read a value from a CSR in SoC

uint32_t  gdbstub_be_CSR_read (const uint8_t xlen, uint16_t regnum, uint64_t *p_regval)
{
    *p_regval = 0;

    Dbg_RW_Target target  = Dbg_RW_CSR;
    Dbg_RW_Size   rw_size = ((xlen == 32) ? Dbg_MEM_4B : Dbg_MEM_8B);
    int status = read_internal (target, regnum, rw_size, p_regval);
    return status;
}

// ================================================================
// Read a value from PRIV
// Implemennted as a read from DCSR.PRIV

uint32_t  gdbstub_be_PRIV_read (const uint8_t xlen, uint64_t *p_PRIV)
{
    uint64_t dcsr;
    int status = gdbstub_be_CSR_read (xlen, addr_csr_dcsr, & dcsr);
    if (status != STATUS_OK)
	return status;

    uint64_t mask = 3;
    *p_PRIV = (dcsr & mask);
    return STATUS_OK;
}

// ================================================================
// Read 1, 2 or 4 bytes from SoC memory at address 'addr' into 'data'

uint32_t  gdbstub_be_mem_read_subword (const uint8_t   xlen,
				       const uint64_t  addr,
				       uint32_t       *data,
				       const size_t    len)
{
    return gdbstub_be_mem_read (xlen, addr, (char *) data, len);
}

// ================================================================
// Read 'len' bytes from SoC memory starting at address 'addr' into 'data'.
// No alignment restriction on 'addr'; no restriction on 'len'.

uint32_t  gdbstub_be_mem_read (const uint8_t   xlen,
			       const uint64_t  addr,
			       char           *data,
			       const size_t    len)
{
    if (len <= 0) {
	fprintf (stdout, "%s: len <= 0; no-op\n", __FUNCTION__);
	return STATUS_OK;
    }

    uint64_t addr1  = addr;
    uint64_t addr2  = addr + len;
    uint64_t offset = 0;
    int      status;
    uint64_t rdata = 0;

    // Read leading misaligned 1-byte, if any
    if ((addr1 & 0x1) == 1) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	memcpy (data + offset, & rdata, 1);
	addr1  += 1;
	offset += 1;
    }
    assert ((addr1 & 0x1) == 0);
    if (addr1 >= addr2)
	return STATUS_OK;

    // Read and show leading misaligned 2-bytes, if any
    if ((addr1 & 0x3) == 2) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	memcpy (data + offset, & rdata, 2);
	addr1  += 2;
	offset += 2;
    }
    assert ((addr1 & 0x3) == 0);
    if (addr1 >= addr2)
	return STATUS_OK;

    // Read and show aligned 4-bytes, if any
    while ((addr2 - addr1) >= 4) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_4B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 4 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	memcpy (data + offset, & rdata, 4);
	addr1  += 4;
	offset += 4;
    }

    // Read and show trailing misaligned 2-bytes, if any
    if ((addr2 - addr1) >= 2) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	memcpy (data + offset, & rdata, 2);
	addr1  += 2;
	offset += 2;
    }
    if (addr1 >= addr2)
	return STATUS_OK;

    // Read and show trailing misaligned 1-byte, if any
    if ((addr2 - addr1) == 1) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 1 mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	memcpy (data + offset, & rdata, 1);
	addr1  += 1;
 	offset += 1;
    }
    return STATUS_OK;
}

// ================================================================
// Write a value into the RISC-V PC
// Implemented as a write to DPC

uint32_t  gdbstub_be_PC_write (const uint8_t xlen, uint64_t regval)
{
    return gdbstub_be_CSR_write (xlen, addr_csr_dpc, regval);
}

// ================================================================
// Write a value into a RISC-V GPR register


uint32_t  gdbstub_be_GPR_write (const uint8_t xlen, uint8_t regnum, uint64_t regval)
{
    Dbg_RW_Target target  = Dbg_RW_GPR;
    Dbg_RW_Size   rw_size = ((xlen == 32) ? Dbg_MEM_4B : Dbg_MEM_8B);
    int status = write_internal (target, regnum, rw_size, regval);
    return status;
}

// ================================================================
// Write a value into a RISC-V FPR register

uint32_t  gdbstub_be_FPR_write (const uint8_t xlen, uint8_t regnum, uint64_t regval)
{
    fprintf (stdout, "UNIMPLEMENTED: %s (..,%0d,%0" PRIx64 ")\n",
	     __FUNCTION__, regnum, regval);
    return STATUS_ERR;
}

// ================================================================
// Write a value into a RISC-V CSR register

uint32_t  gdbstub_be_CSR_write (const uint8_t xlen, uint16_t regnum, uint64_t regval)
{
    Dbg_RW_Target target  = Dbg_RW_CSR;
    Dbg_RW_Size   rw_size = ((xlen == 32) ? Dbg_MEM_4B : Dbg_MEM_8B);
    int status = write_internal (target, regnum, rw_size, regval);
    return status;
}

// ================================================================
// Write a value into the RISC-V PRIV register
// Implmented as a write to DCSR.PRV

uint32_t  gdbstub_be_PRIV_write (const uint8_t xlen, uint64_t regval)
{
    uint64_t dcsr;
    int status = gdbstub_be_CSR_read (xlen, addr_csr_dcsr, & dcsr);
    if (status != STATUS_OK)
	return status;

    uint64_t mask = 3;
    dcsr = ((dcsr & (~ mask)) | (regval & mask));
    return gdbstub_be_CSR_write (xlen, addr_csr_dcsr, dcsr);
}

// ================================================================
// Write 'len' bytes of 'data' into RISC-V system memory, starting at address 'addr'
// where 'len' is 1, 2 or 4 only, and addr is aligned.

uint32_t  gdbstub_be_mem_write_subword (const uint8_t   xlen,
					const uint64_t  addr,
					const uint32_t  data,
					const size_t    len)
{
    return gdbstub_be_mem_write (xlen, addr, (char *) (& data), len);
}

// ================================================================
// Write 'len' bytes of 'data' into RISC-V system memory, starting at address 'addr'

uint32_t  gdbstub_be_mem_write (const uint8_t   xlen,
				const uint64_t  addr,
				const char     *data,
				const size_t    len)
{
    uint64_t addr1  = addr;
    uint64_t addr2  = addr + len;
    uint64_t offset = 0;
    int      status;
    uint64_t wdata = 0;

    // Write leading misaligned 1-byte, if any
    if ((addr1 & 0x1) == 1) {
	memcpy (& wdata, data + offset, 1);
	status = write_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, wdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	addr1  += 1;
	offset += 1;
    }
    assert ((addr1 & 0x1) == 0);

    // Read and show leading misaligned 2-bytes, if any
    if ((addr1 & 0x3) == 2) {
	memcpy (& wdata, data + offset, 2);
	status = write_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, wdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	addr1  += 2;
	offset += 2;
    }
    assert ((addr1 & 0x3) == 0);

    // Read and show aligned 4-bytes, if any
    while ((addr2 - addr1) >= 4) {
	memcpy (& wdata, data + offset, 4);
	status = write_internal (Dbg_RW_MEM, addr1, Dbg_MEM_4B, wdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 4 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	addr1  += 4;
	offset += 4;
    }

    // Read and show trailing misaligned 2-bytes, if any
    if ((addr2 - addr1) >= 2) {
	memcpy (& wdata, data + offset, 2);
	status = write_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, wdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	addr1  += 2;
	offset += 2;
    }

    // Read and show trailing misaligned 1-byte, if any
    if ((addr2 - addr1) == 1) {
	memcpy (& wdata, data + offset, 1);
	status = write_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, wdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 1 mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return status;
	}
	addr1  += 1;
 	offset += 1;
    }
    return STATUS_OK;
}

// ****************************************************************
// ****************************************************************
// ****************************************************************
// Raw reads and writes of the DMI interface (for debugging)

// ================================================================
// Raw DMI read

extern
uint32_t  gdbstub_be_dmi_read (uint16_t dmi_addr, uint32_t *p_data)
{
    fprintf (stdout, "UNIMPLEMENTED: %s (%0x,...)\n",
	     __FUNCTION__, dmi_addr);
    return STATUS_ERR;
}

// ================================================================
// Raw DMI write

uint32_t  gdbstub_be_dmi_write (uint16_t dmi_addr, uint32_t dmi_data)
{
    fprintf (stdout, "UNIMPLEMENTED: %s (%0x, %0x)\n",
	     __FUNCTION__, dmi_addr, dmi_data);
    return STATUS_ERR;
}

bool  gdbstub_be_poll_preempt (bool include_commands)
{
    fprintf (stdout, "UNIMPLEMENTED: %s (%0d)\n",
	     __FUNCTION__, include_commands);
    return STATUS_ERR;
}

// ****************************************************************
// Future improvements:

// In gdbstub_be_mem_read/write:
//   * do 64-bit reads if remote RISCV server supports it
//   * pipeline write requests and responses, instead of one-at-a-time

// ****************************************************************