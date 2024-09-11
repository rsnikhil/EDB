// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved

// ****************************************************************
// This is for standalone testing of 'edbstub.c', which is a server for
// 'edb': Economical/Elementary Debugger

// It listens on the server socket for a connection from edb,
// then pretends to be a CPU, accepting Dbg_to_CPU messages
// and responding with Dbg_from_CPU messages.

// ================================================================
// Includes from C library

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

// ================================================================
// Includes for this project

#include "Dbg_Pkts.h"

// ----------------
// From gdbstub.c

extern
int edbstub_verbosity;

extern
void edbstub_init (uint16_t listen_port);

extern
void edbstub_shutdown ();

extern
void edbstub_recv_to_CPU_pkt (Dbg_to_CPU_Pkt *p_pkt);

extern
void edbstub_send_dbg_from_CPU_pkt (const Dbg_from_CPU_Pkt *p_pkt_out);

// ****************************************************************
// "Pretend" architectural state of the CPU

static bool is_running = true;

static uint64_t gprs [32];

static uint64_t csrs [0x1000];

#define MEM_BASE_ADDR 0x80000000
#define MEM_SIZE_B    0x10000000

static uint8_t  mem [MEM_SIZE_B];

// ****************************************************************

static
void send_err_rsp (Dbg_to_CPU_Pkt *p_pkt_in)
{
    Dbg_from_CPU_Pkt pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_from_CPU_Pkt));
    pkt_out.pkt_type = Dbg_from_CPU_ERR;
    edbstub_send_dbg_from_CPU_pkt (& pkt_out);
}

// ================================================================

static
void handle_RESUMEREQ (Dbg_to_CPU_Pkt *p_pkt_in)
{
    assert (p_pkt_in->pkt_type == Dbg_to_CPU_RESUMEREQ);

    fprintf (stdout, "RESUMEREQ\n");

    if (is_running) {
	fprintf (stdout, "ERROR: RESUMEREQ: CPU is already running (not in Debug Mode)\n");
	send_err_rsp (p_pkt_in);
	return;
    }

    Dbg_from_CPU_Pkt pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_from_CPU_Pkt));

    // Respond 'RUNNING' to confirm running
    pkt_out.pkt_type = Dbg_from_CPU_RUNNING;
    edbstub_send_dbg_from_CPU_pkt (& pkt_out);

    uint32_t dcsr = csrs [addr_csr_dcsr];
    uint32_t dcsr_cause;
    
    if ((dcsr & mask_dcsr_step) == 0) {
	// "run the CPU" for some time, but listen for HALTREQ requests (^C/abort)
	// If no HALTREQ, pretend to halt on an EBREAK
	dcsr_cause = dcsr_cause_EBREAK;
	for (int j = 0; j < 10; j++) {
	    fprintf (stdout, "Running ...\n");
	    sleep (1);
	    // Poll for incoming packet
	    edbstub_recv_to_CPU_pkt (p_pkt_in);
	    if (p_pkt_in->pkt_type == Dbg_to_CPU_NOOP)
		// No packet
		continue;
	    else if (p_pkt_in->pkt_type == Dbg_to_CPU_HALTREQ) {
		dcsr_cause = dcsr_cause_HALTREQ;
		break;
	    }
	    else {
		fprintf (stdout, "WARNING: unexpected packet when running.\n");
		fprintf (stdout, "  When running, only HALTREQ packets expected.\n");
		exit (1);
	    }
	}
    }
    else {
	// STEPI; pretend we've execute one instruction
	dcsr_cause = dcsr_cause_STEP;
    }

    // Update DCSR for halt cause
    dcsr = ((dcsr & (~ mask_dcsr_cause)) | (dcsr_cause << 6));
    csrs [addr_csr_dcsr] = dcsr;

    pkt_out.pkt_type = Dbg_from_CPU_HALTED;
    pkt_out.payload  = dcsr;
    edbstub_send_dbg_from_CPU_pkt (& pkt_out);
}

// ================================================================

static
void handle_HALTREQ (Dbg_to_CPU_Pkt *p_pkt_in)
{
    assert (p_pkt_in->pkt_type == Dbg_to_CPU_HALTREQ);

    fprintf (stdout, "HALTREQ\n");

    if (! is_running) {
	fprintf (stdout, "ERROR: CPU is already halted (in Debug Mode)\n");
	send_err_rsp (p_pkt_in);
	return;
    }
    is_running = false;

    // Update DCSR for halt cause
    uint32_t dcsr = csrs [addr_csr_dcsr];
    dcsr = ((dcsr & (~ mask_dcsr_cause)) | (dcsr_cause_HALTREQ << 6));
    csrs [addr_csr_dcsr] = dcsr;

    // Send HALTED respons
    Dbg_from_CPU_Pkt pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_from_CPU_Pkt));
    pkt_out.pkt_type = Dbg_from_CPU_HALTED;
    pkt_out.payload  = dcsr;
    edbstub_send_dbg_from_CPU_pkt (& pkt_out);
}

// ================================================================

static
void handle_RW (Dbg_to_CPU_Pkt *p_pkt_in)
{
    assert (p_pkt_in->pkt_type == Dbg_to_CPU_RW);

    if (is_running) {
	fprintf (stdout, "ERROR: RW command while CPU is running (not in Debug Mode)\n");
	send_err_rsp (p_pkt_in);
	return;
    }

    // Response packet and default response
    Dbg_from_CPU_Pkt pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_from_CPU_Pkt));
    pkt_out.pkt_type = Dbg_from_CPU_ERR;
    pkt_out.payload  = 0xDABACAFE;    // bogus value

    // Do the R/W
    if (p_pkt_in->rw_target == Dbg_RW_GPR) {
	if (p_pkt_in->rw_addr >= 32) {
	    pkt_out.pkt_type = Dbg_from_CPU_ERR;
	    fprintf (stdout, "ERROR: GPR %0" PRId64 " read; illegal GPR number\n",
		     p_pkt_in->rw_addr);
	}
	else if (p_pkt_in->rw_op == Dbg_RW_READ) {
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    if (p_pkt_in->rw_addr == 0)
		pkt_out.payload = 0;
	    else
		pkt_out.payload = gprs [p_pkt_in->rw_addr];
	    fprintf (stdout, "GPR %0" PRId64 " read => 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, pkt_out.payload);
	}
	else {
	    // Dbg_RW_WRITE
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    if (p_pkt_in->rw_addr != 0)
		gprs [p_pkt_in->rw_addr] = p_pkt_in->rw_wdata;
	    fprintf (stdout, "GPR %0" PRId64 " write 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, p_pkt_in->rw_wdata);
	}
    }
    else if (p_pkt_in->rw_target == Dbg_RW_CSR) { 
	if (p_pkt_in->rw_addr >= 0x1000) {
	    pkt_out.pkt_type = Dbg_from_CPU_ERR;
	    fprintf (stdout, "ERROR: CSR %0" PRId64 " read; illegal CSR addr\n",
		     p_pkt_in->rw_addr);
	}
	else if (p_pkt_in->rw_op == Dbg_RW_READ) {
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    pkt_out.payload = csrs [p_pkt_in->rw_addr];
	    fprintf (stdout, "CSR 0x%0" PRIx64 " read => 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, pkt_out.payload);
	}
	else {
	    // Dbg_RW_WRITE
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    csrs [p_pkt_in->rw_addr] = p_pkt_in->rw_wdata;
	    fprintf (stdout, "CSR %0" PRIx64 " write 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, p_pkt_in->rw_wdata);
	}
    }
    else if (p_pkt_in->rw_target == Dbg_RW_FPR) { 
	// default err response
    }
    else {
	assert (p_pkt_in->rw_target == Dbg_RW_MEM);

	int n_bytes = 0;
	switch (p_pkt_in->rw_size) {
	case Dbg_MEM_1B: n_bytes = 1; break;
	case Dbg_MEM_2B: n_bytes = 2; break;
	case Dbg_MEM_4B: n_bytes = 4; break;
	case Dbg_MEM_8B: n_bytes = 8; break;
	}
	if ((p_pkt_in->rw_addr < MEM_BASE_ADDR)
	    || ((MEM_BASE_ADDR + MEM_SIZE_B) <= p_pkt_in->rw_addr)) {
	    pkt_out.pkt_type = Dbg_from_CPU_ERR;
	    fprintf (stdout, "ERROR: Mem %0" PRId64 " read; illegal addr\n",
		     p_pkt_in->rw_addr);
	}
	else if (p_pkt_in->rw_op == Dbg_RW_READ) {
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    pkt_out.payload = 0;
	    memcpy (& pkt_out.payload,
		    & (mem [p_pkt_in->rw_addr - MEM_BASE_ADDR]),
		    n_bytes);
	    fprintf (stdout, "Mem 0x%0" PRIx64 " read => 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, pkt_out.payload);
	}
	else {
	    // Dbg_RW_WRITE
	    pkt_out.pkt_type = Dbg_from_CPU_RW_OK;
	    memcpy (& (mem [p_pkt_in->rw_addr - MEM_BASE_ADDR]),
		    & (p_pkt_in->rw_wdata),
		    n_bytes);
	    fprintf (stdout, "Mem 0x%0" PRIx64 " write 0x%0" PRIx64 "\n",
		     p_pkt_in->rw_addr, p_pkt_in->rw_wdata);
	}
    }
    edbstub_send_dbg_from_CPU_pkt (& pkt_out);
}

// ****************************************************************

int main (int argc, char *argv [])
{
    uint16_t listen_port = 30000;
    edbstub_init (listen_port);

    for (int j = 0; j < 32; j++)
	gprs [j] = 0;

    edbstub_verbosity = 0;

    if (is_running)
	fprintf (stdout, "CPU is already running\n");
    else
	fprintf (stdout, "CPU is already halted\n");

    // This loop represents a server for a fake CPU for standalone testing of edbstub.
    // Receive packets from the debugger.
    // Send simulated response packets to the debugger.
    Dbg_to_CPU_Pkt  pkt_in;
    while (true) {
	edbstub_recv_to_CPU_pkt (& pkt_in);
	if (pkt_in.pkt_type == Dbg_to_CPU_NOOP) {
	    // No packet to process
	    usleep (1000);
	    continue;
	}

	// Send response
	switch (pkt_in.pkt_type) {
	case Dbg_to_CPU_RESUMEREQ: handle_RESUMEREQ (& pkt_in); break;
	case Dbg_to_CPU_HALTREQ:   handle_HALTREQ (& pkt_in);   break;
	case Dbg_to_CPU_RW:        handle_RW (& pkt_in);        break;
	case Dbg_to_CPU_QUIT:      goto done;
	default:                   send_err_rsp (& pkt_in);     break;
	}
    }

 done:
    edbstub_shutdown ();
    return 0;
}

// ****************************************************************
