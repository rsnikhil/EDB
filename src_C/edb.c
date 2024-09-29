// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// EDB: "Economical/Elementary Debugger"
// EDB is a simple debugger which can be used like GDB to control a remote RISC-V CPU.

// It uses TCP to connect to a remote 'edbstub' server (analogue of
//     'gdbstub' server) which controls the DUT (a RISC-V CPU).

// EDB is far simpler (and far less capable) than GDB, and the remote
// edbstub is far simpler (and far less capable) than gdbstub.  It is
// meant for quick bringup (easier than gdb/gdbstub) and for teaching
// the principles of how remote debugging works.

// It has a small repertoire of commands:
//     Type 'help' at the interactive prompt for list
//     or see 'exec_help()' below.
// It is machine-code-level only (no source-level debugging).
// It has no scripting.

// ----------------
// Acknowledgements
//
// Portions of TCP code adapted from example ECHOSERV
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

// For command-line reading and command-line history

#include <readline/readline.h>
#include <readline/history.h>

// ================================================================
// Includes for this project

#include "Status.h"
#include "TCP_Client_Lib.h"
#include "Dbg_Pkts.h"
#include "ISA_Defs.h"
#include "loadELF.h"

// ****************************************************************
// Default hostname and TCP port for remote edbstub server

static char     server_hostname [] = "127.0.0.1";    // (localhost)
static uint16_t server_listen_port = 30000;

// ****************************************************************
// Parse EDB interactive command, arguments

bool is_s1_prefix_of_s2 (const char *s1, const char *s2)
{
    int j = 0;
    while (true) {
	if (s1 [j] == 0) return true;
	if (s2 [j] == 0) return false;
	// Case-insensitive compare
	if (tolower (s1 [j]) != tolower (s2 [j])) return false;
	j++;
    }
}

typedef enum {CMD_HELP,
	      CMD_HELP_GPR_NAMES,
	      CMD_HELP_CSR_NAMES,
	      CMD_HISTORY,
	      CMD_HALT,
	      CMD_LOADELF,
	      CMD_BRK, CMD_RMBRK, CMD_LSBRKS,
	      CMD_CONTINUE, CMD_STEPI,
	      CMD_RGPR, CMD_RCSR, CMD_RMEM,
	      CMD_WGPR, CMD_WCSR, CMD_WMEM,
	      CMD_DUMPMEM,
	      CMD_QUIT,
	      CMD_ERR} Cmd_Code;

typedef struct {
    Cmd_Code  cmd_code;
    char     *cmd_name;
    char     *cmd_doc;
} Cmd;
    
Cmd cmds []
= { { CMD_HELP,           "help                  ", "Print this help" },
    { CMD_HELP_GPR_NAMES, "GPR_Names             ", "Show GPR symbolic names" },
    { CMD_HELP_CSR_NAMES, "CSR_Names             ", "Show CSR symbolic names" },
    { CMD_HISTORY,        "history               ", "Show command-line history" },
    { CMD_HALT,           "halt                  ", "Halt exec of running CPU" },
    { CMD_LOADELF,        "loadelf <elf file>    ", "Load ELF file" },
    { CMD_BRK,            "break <addr>          ", "Set a breakpoint" },
    { CMD_RMBRK,          "rmbreak <addr>        ", "Remove a breakpoint" },
    { CMD_LSBRKS,         "lsbreaks              ", "List breakpoints" },
    { CMD_CONTINUE,       "continue              ", "Resume exec of halted CPU" },
    { CMD_STEPI,          "stepi                 ", "Exec 1 instruction of halted CPU" },      
    { CMD_RGPR,           "rgpr <gprnum>         ", "Read GPR" },
    { CMD_WGPR,           "wgpr <gprnum>  <wdata>", "Write GPR" },
    { CMD_RCSR,           "rcsr <csraddr>        ", "Read CSR" },
    { CMD_WCSR,           "wcsr <csraddr> <wdata>", "Write CSR " },
    { CMD_RMEM,           "rmem <memaddr>        ", "Read Mem (one word)" },
    { CMD_WMEM,           "wmem <memaddr> <wdata>", "Write Mem (one word)" },
    { CMD_DUMPMEM,        "dumpmem  <a1>  <a2>   ", "Read memory addr a1 through a2"},
    { CMD_QUIT,           "quit                  ", "Quit EDB" },
    { CMD_ERR,            "",                       "<bogus sentinel>" } };

#define CHARBUF_SIZE 1024

// Read a command from cmdline.
// Return a pointer to a Cmd struct if successful (NULL if no match)
// In 'p_index', return index in cmdline of next char beyond the command

static
Cmd *parse_command (const char *cmdline, int *p_index)
{
    int  n;
    char cmd_s    [CHARBUF_SIZE];

    // Scan first word in command line
    n = sscanf (cmdline, "%s%n", cmd_s, p_index);
    if (n != 1)
	return NULL;

    // Search for command in command list
    int j_match = -1;
    for (int j = 0; cmds [j].cmd_code != CMD_ERR; j++)
	if (is_s1_prefix_of_s2 (cmd_s, cmds [j].cmd_name)) {
	    if (j_match >= 0) {
		fprintf (stdout, "  Ambigouous match '%s' and '%s'\n",
			 cmds [j_match].cmd_name,
			 cmds [j].cmd_name);
		return NULL;
	    }
	    j_match = j;
	}
    if (j_match == -1)
	return NULL;

    return & (cmds [j_match]);
}	

static
int parse_1_int_arg (const char *cmdline, uint64_t *p_arg1)
{
    int n = sscanf (cmdline, "%" SCNi64, p_arg1);
    if (n == 1)
	return STATUS_OK;

    fprintf (stdout, "ERROR: could not parse int arg\n");
    return STATUS_ERR;
}

static
int parse_1_string_arg (const char *cmdline, char *p_arg)
{
    int n = sscanf (cmdline, "%s", p_arg);
    return ((n == 1) ? STATUS_OK : STATUS_ERR);
}

// ----------------------------------------------------------------
// Parse GPR number

static
int parse_GPR_num (const char *cmdline, const int index, uint64_t *p_gpr_num, int *p_index)
{
    int delta;
    // Get first word on line, and index of char beyond it
    char word [CHARBUF_SIZE];
    int n = sscanf (cmdline + index, "%s%n", & word [0], & delta);
    if (n != 1) return STATUS_ERR;
    *p_index = index + delta;

    // Check for GPR ABI name
    for (int j = 0; GPR_ABI_Names [j].name != NULL; j++)
	if (strcmp (word, GPR_ABI_Names [j].name) == 0) {
	    *p_gpr_num = GPR_ABI_Names [j].val;
	    goto done;
	}

    // Scan for 'xN' name
    n = sscanf (word, "x%" PRId64, p_gpr_num);
    if (n == 1)
	goto done;

    // Scan an ordinary integer in decimal or hex format, and index of char beyond it
    n = sscanf (cmdline + index, "%" PRIi64 "%n", p_gpr_num, & delta);
    if (n != 1) return STATUS_ERR;
    *p_index = index + delta;

 done:
    return ((*p_gpr_num <= 31) ? STATUS_OK : STATUS_ERR);
}

// ----------------------------------------------------------------
// Parse CSR addr

static
int parse_CSR_addr (const char *cmdline, const int index, uint64_t *p_csr_addr, int *p_index)
{
    int delta;
    // Get first word on line, and index of char beyond it
    char word [CHARBUF_SIZE];
    int n = sscanf (cmdline + index, "%s%n", & word [0], & delta);
    if (n != 1) return STATUS_ERR;
    *p_index = index + delta;

    // Check for CSR name
    for (int j = 0; CSR_Names [j].name != NULL; j++)
	if (strcmp (word, CSR_Names [j].name) == 0) {
	    *p_csr_addr = CSR_Names [j].val;
	    goto done;
	}

    // Scan an ordinary integer in decimal or hex format, and index of char beyond it
    n = sscanf (cmdline + index, "%" PRIi64 "%n", p_csr_addr, & delta);
    if (n != 1) return STATUS_ERR;
    *p_index = index + delta;

 done:
    return ((*p_csr_addr <= 0xFFF) ? STATUS_OK : STATUS_ERR);
}

// ****************************************************************
// EDB communication with edbstub

// File for logging communications
FILE *flog = NULL;

// ================================================================
// Packet send/recv

typedef enum { DONT_POLL, DO_POLL } Poll;

static
int send_to_edbstub (const char *context, Dbg_to_CPU_Pkt *p_pkt_out)
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
int recv_from_edbstub (const char *context, const Poll poll, Dbg_from_CPU_Pkt *p_pkt_in)
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
// Internal functions used by exec_XXX functions

// ================================================================

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
    fprintf (fd, "        cause:");
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

    fprintf (fd, " v:%0d",         ((dcsr >>  5) & 0x1));
    fprintf (fd, " mprven:%0d",    ((dcsr >>  4) & 0x1));
    fprintf (fd, " nmip:%0d",      ((dcsr >>  3) & 0x1));
    fprintf (fd, " step:%0d",      ((dcsr >>  2) & 0x1));
    fprintf (fd, " prv:%0d",       ((dcsr >>  0) & 0x3));
    fprintf (fd, "}\n");
}

// ================================================================

static
int read_internal (const Dbg_RW_Target target,
		   const uint64_t      addr,
		   const Dbg_RW_Size   rw_size,
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

    status = send_to_edbstub (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;
	    
    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;

    *p_rdata = pkt_in.payload;
    return ((pkt_in.pkt_type == Dbg_from_CPU_RW_OK) ? STATUS_OK : STATUS_ERR);
}

// ================================================================
// Internal function to write GPR/CSR/Mem

static
int write_internal (const Dbg_RW_Target target,
		    const uint64_t      addr,
		    const Dbg_RW_Size   rw_size,
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

    status = send_to_edbstub (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return status;

    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return status;
    return ((pkt_in.pkt_type == Dbg_from_CPU_RW_OK) ? STATUS_OK : STATUS_ERR);
}

static
int read_dpc_internal (uint64_t *p_dpc)
{
    int status = read_internal (Dbg_RW_CSR, addr_csr_dpc, Dbg_MEM_4B, p_dpc);
    return status;
}

static
void fprintf_dpc ()
{
    // Read DPC
    uint64_t dpc;
    int status = read_dpc_internal (& dpc);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: attempting to read DPC\n");
	return;
    }
    fprintf (stdout, "  DPC %08" PRIx64 "\n", dpc);
}

// ****************************************************************
// Command execution

// ================================================================

static
void exec_help ()
{
    fprintf (stdout, "  Commands:\n");
    for (int j = 0; cmds [j].cmd_code != CMD_ERR; j++)
	fprintf (stdout, "    %s  %s\n", cmds [j].cmd_name, cmds [j].cmd_doc);
    fprintf (stdout, "  Commands are not case-sensitive.\n");
    fprintf (stdout, "  Commands can be abbreviated to any unique prefix.\n");
    fprintf (stdout, "  Integers can be written in decimal or in hex (0xNNNN).\n");
    fprintf (stdout, "  For r/w GPR, GPR addr can be symbolic 'xN' name, ABI name or int\n");
    fprintf (stdout, "  For r/w CPR, CSR addr can be symbolic name or int\n");
}

static
void exec_help_GPR_Names ()
{
    fprintf (stdout, "GPR symbolic names:\n");
    fprintf (stdout, "    Symbolic         Hex  Decimal\n");
    for (int j = 0; GPR_ABI_Names [j].name != NULL; j += 1) {
	fprintf (stdout, "    %4s  x%0d", GPR_ABI_Names [j].name, GPR_ABI_Names [j].val);
	if (GPR_ABI_Names [j].val < 10) fprintf (stdout, " ");
	fprintf (stdout, "        0x%0x", GPR_ABI_Names [j].val);
	if (GPR_ABI_Names [j].val < 0x10) fprintf (stdout, " ");
	fprintf (stdout, " %0d\n", GPR_ABI_Names [j].val);
    }
}

static
void exec_help_CSR_Names ()
{
    fprintf (stdout, "CSR symbolic names:\n");
    fprintf (stdout, "               Name    Addr\n");
    for (int j = 0; CSR_Names [j].name != NULL; j++)
	fprintf (stdout, "    %15s    0x%03x\n", CSR_Names [j].name, CSR_Names [j].val);
}

// ================================================================
// Uses GNU 'history' library

static
void exec_history ()
{
    HISTORY_STATE *history_state = history_get_history_state ();
    fprintf (stdout, "  Command-line history:\n");
    for (int j = 0; j < history_state->length; j++) {
	HIST_ENTRY *hist_entry = history_get (j);
	if (hist_entry != NULL)
	    fprintf (stdout, "    %d: %s\n", j, hist_entry->line);
    }
    putchar ('\n');
}

// ================================================================
// Halt the remote CPU (if running)

static
void exec_halt ()
{
    int              status;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // Send HALTREQ
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_HALTREQ;
    status = send_to_edbstub (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return;

    // Wait for HALTED or ERR response
    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return;
    if (pkt_in.pkt_type == Dbg_from_CPU_HALTED) {
	fprintf (stdout, "  CPU halted\n");
	fprintf_dcsr (stdout, pkt_in.payload);
	fprintf_dpc ();
    }
    else if (pkt_in.pkt_type == Dbg_from_CPU_ERR)
	fprintf (stdout, "  HALTREQ response is 'error'; CPU may be halted already?\n");
    else {
	fprintf (stdout, "ERROR: Unexpected response for HALTREQ\n");
	fprintf (stdout, "       Expecting HALTED confirmation\n");
    }

    // ----------------
    fprintf (stdout, "  Setting dcsr [ebreak*] bits\n");

    uint64_t data;

    // Read DCSR
    status = read_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, & data);
    if (status != STATUS_OK) return;

    // Set the various ebreak* bits
    data = (data | mask_dcsr_ebreakvs | mask_dcsr_ebreakvu
	    | mask_dcsr_ebreakm | mask_dcsr_ebreaks | mask_dcsr_ebreaku);

    // Write DCSR
    status = write_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, data);
    if (status != STATUS_OK) return;

}

// ================================================================
// Load an ELF file into the remote CPU's memory

static
void exec_loadelf (const char *cmdline)
{
    char filename [CHARBUF_SIZE];
    int status = parse_1_string_arg (cmdline, filename);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: unable to parse filename on command-line\n");
	return;
    }

    const int  verbosity         = 0;
    const bool do_readback_check = true;
    status = loadELF (verbosity, do_readback_check, filename);
    if (status == STATUS_OK)
	fprintf (stdout, "  OK\n");
    else
	fprintf (stdout, "ERROR: Unable to load ELF file\n");
}

// ================================================================
// Set a breakpoint

typedef struct {
    uint64_t  addr;     // Use -1 to denote 'invalid'
    uint32_t  instr;    // original instruction at this location
} Brkpt_Entry;

#define EBREAK_INSTR 0x00100073

#define MAX_NUM_BRKPTS 128
static
Brkpt_Entry  breakpoint_arr [MAX_NUM_BRKPTS];

static
int set_breakpoint_internal (const uint64_t brk_addr)
{
    uint64_t data;
    int      status;

    // Check 4-byte alignment
    if ((brk_addr & 0x3) != 0) {
	fprintf (stdout, "ERROR: breakpoint addr is not 4-byte aligned (0x%" PRIx64 ")\n",
		 brk_addr);
	fprintf (stdout, "       Ignoring ...\n");
	return STATUS_ERR;
    }
    // Scan breakpoint array for empty slot/duplicate
    int j1 = -1;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	if ((j1 == -1) && (breakpoint_arr [j].addr == -1))
	    j1 = j;
	else if (breakpoint_arr [j].addr == brk_addr) {
	    fprintf (stdout, "Already have a breakpoint at (0x%" PRIx64 ")\n", brk_addr);
	    fprintf (stdout, "    Ignoring ...\n");
	    return STATUS_OK;
	}
    }
    if (j1 == -1) {
	fprintf (stdout, "ERROR: already have maximum number of breakpoints (%0d)\n",
		 MAX_NUM_BRKPTS);
	fprintf (stdout, "       Ignoring ...\n");
	return STATUS_ERR;
    }
    // Read instruction at this memory location (for restore when later removing breakpoint)
    status = read_internal (Dbg_RW_MEM, brk_addr, Dbg_MEM_4B, & data);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: failed reading original instruction at addr\n");
	fprintf (stdout, "       Ignoring ...\n");
	return status;
    }
    // Write EBREAK instruction at this memory location
    status = write_internal (Dbg_RW_MEM, brk_addr, Dbg_MEM_4B, EBREAK_INSTR);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: failed writing EBREAK instruction at addr\n");
	fprintf (stdout, "       Ignoring ...\n");
	return status;
    }
    breakpoint_arr [j1].addr  = brk_addr;
    breakpoint_arr [j1].instr = data;
    return STATUS_OK;
}

static
void exec_set_breakpoint (const char *cmdline)
{
    uint64_t  brk_addr;
    int status = parse_1_int_arg (cmdline, & brk_addr);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: unable to read 1 int arg (breakpoint addr)\n");
	return;
    }
    set_breakpoint_internal (brk_addr);
}

// ================================================================
// Remove a breakpoint

// rm_breakpoint_internal() returns true if it actually removed a
// breakpoint, else false

static
bool rm_breakpoint_internal (const uint64_t brk_addr)
{
    // Scan breakpoint array for this breakpoint addr
    int j1 = -1;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	if (breakpoint_arr [j].addr == brk_addr) {
	    j1 = j;
	    break;
	}
    }
    if (j1 == -1) {
	fprintf (stdout, "  Remove breakpoint: no breakpoint at 0x%0" PRIx64 "\n", brk_addr);
	fprintf (stdout, "       Ignoring ...\n");
	return false;
    }
    // Write original instruction back to this memory location
    int status = write_internal (Dbg_RW_MEM, brk_addr, Dbg_MEM_4B, breakpoint_arr [j1].instr);
    if (status != STATUS_OK) {
	fprintf (stdout, "  ERROR: failed writing original instruction back to addr\n");
	fprintf (stdout, "       Ignoring ...\n");
	return false;
    }
    // Free up entry in breakpoint array
    breakpoint_arr [j1].addr  = -1;
    breakpoint_arr [j1].instr = 0;
    return true;
}

static
void exec_rm_breakpoint (const char *cmdline)
{
    uint64_t  brk_addr;
    int status = parse_1_int_arg (cmdline, & brk_addr);
    if (status != STATUS_OK) {
	fprintf (stdout, "  ERROR: unable to read 1 int arg (breakpoint addr)\n");
	return;
    }
    rm_breakpoint_internal (brk_addr);
}

// ================================================================
// List breakpoints

static
void exec_ls_breakpoints ()
{
    // Scan breakpoint array and list valid breakpoints
    int n = 0;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	if (breakpoint_arr [j].addr != -1) {
	    fprintf (stdout, "    %0d: addr 0x%0" PRIx64 "    original instr 0x%08x\n",
		     j,
		     breakpoint_arr [j].addr,
		     breakpoint_arr [j].instr);
	    n++;
	}
    }
    if (n == 0)
	fprintf (stdout, "No breakpoints currently set\n");
}

// ================================================================
// Read GPR/CSR/Mem

static
void exec_read (const char         *cmdline,
		int                 index,
		const Dbg_RW_Target target,
		const Dbg_RW_Size   rw_size)
{
    int      status, index2;
    uint64_t addr;
    if (target == Dbg_RW_GPR) {
	status = parse_GPR_num (cmdline, index, & addr, & index2);
	if (status == STATUS_OK)
	    fprintf (stdout, "Reading GPR x%0" PRId64 "\n", addr);
    }
    else if (target == Dbg_RW_CSR) {
	status = parse_CSR_addr (cmdline, index, & addr, & index2);
	if (status == STATUS_OK)
	    fprintf (stdout, "Reading CSR 0x%0" PRIx64 "\n", addr);
    }
    else {
	assert (target == Dbg_RW_MEM);
	status = parse_1_int_arg (cmdline + index, & addr);
	if (status == STATUS_OK)
	    fprintf (stdout, "Reading Mem [0x%0" PRIx64 "]\n", addr);
    }
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: unable to read GPR num/CSR addr/Mem addr\n");
	return;
    }

    uint64_t rdata;
    status = read_internal (target, addr, rw_size, & rdata);
    if (status == STATUS_OK)
	fprintf (stdout, "  Read-value: 0x%0" PRIx64 "\n", rdata);
    else
	fprintf (stdout, "ERROR: did not get RW_OK response\n");
}

// ================================================================
// Read n_bytes from remote CPU's memory, by iterating read_internal().

int exec_read_buf (const uint64_t  start_addr,
		   const int       n_bytes,
		         uint8_t  *p_rdata)
{
    int      status;
    uint64_t addr   = start_addr;
    int      offset = 0;
    uint64_t data;

    if (offset >= n_bytes) return STATUS_OK;

    // Do leading 1-byte alignment, if any
    if ((addr & 0x1) == 1) {
	status = read_internal (Dbg_RW_MEM, addr, Dbg_MEM_1B, & data);
	if (status != STATUS_OK) return status;
	memcpy (p_rdata + offset, & data, 1);
	offset += 1;
	addr   += 1;
    }
    if (offset >= n_bytes) return STATUS_OK;

    // Is now 2-byte aligned
    assert (((addr + offset) & 0x1) == 0);
    // Do leading 2-byte alignment, if any
    if ((addr & 0x3) == 2) {
	status = read_internal (Dbg_RW_MEM, addr, Dbg_MEM_2B, & data);
	if (status != STATUS_OK) return status;
	memcpy (p_rdata + offset, & data, 2);
	offset += 2;
	addr   += 2;
    }
    if (offset >= n_bytes) return STATUS_OK;

    // Is now 4-byte aligned
    assert (((addr + offset) & 0x3) == 0);
    // Do remaining 4-byte reads
    while ((offset + 4) <= n_bytes) {
	status = read_internal (Dbg_RW_MEM, addr, Dbg_MEM_4B, & data);
	if (status != STATUS_OK) return status;
	memcpy (p_rdata + offset, & data, 4);
	offset += 4;
	addr   += 4;
    }

    // Do trailing 2-byte alignment, if any
    if ((n_bytes - offset) >= 2) {
	status = read_internal (Dbg_RW_MEM, addr, Dbg_MEM_2B, & data);
	if (status != STATUS_OK) return status;
	memcpy (p_rdata + offset, & data, 2);
	offset += 2;
	addr   += 2;
    }

    // Do trailing 1-byte alignment, if any
    if ((n_bytes - offset) == 1) {
	status = read_internal (Dbg_RW_MEM, addr, Dbg_MEM_1B, & data);
	if (status != STATUS_OK) return status;
	memcpy (p_rdata + offset, & data, 1);
    }
    return STATUS_OK;
}

// ================================================================
// Write GPR/CSR/Mem

static
void exec_write (const char         *cmdline,
		int                  index,
		 const Dbg_RW_Target target,
		 const Dbg_RW_Size   rw_size)
{
    // Parse address
    int      status, index2;
    uint64_t addr;
    if (target == Dbg_RW_GPR) {
	status = parse_GPR_num (cmdline, index, & addr, & index2);
	if (status == STATUS_OK)
	    fprintf (stdout, "Writing GPR x%0" PRId64 "\n", addr);
    }
    else if (target == Dbg_RW_CSR) {
	status = parse_CSR_addr (cmdline, index, & addr, & index2);
	if (status == STATUS_OK)
	    fprintf (stdout, "Writing CSR 0x%0" PRIx64 "\n", addr);
    }
    else {
	assert (target == Dbg_RW_MEM);
	int n = sscanf (cmdline + index, "%" SCNi64 "%n", & addr, & index2);
	status = ((n == 1) ? STATUS_OK : STATUS_ERR);
	index2 += index;
	if (status == STATUS_OK)
	    fprintf (stdout, "Writing Mem [0x%0" PRIx64 "]\n", addr);
    }
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: unable to read GPR num/CSR addr/Mem addr\n");
	return;
    }

    // Parse w-data
    uint64_t wdata;
    int n = sscanf (cmdline + index2, "%" SCNi64, & wdata);
    if (n != 1) {
	fprintf (stdout, "ERROR: unable to parse w-data (to be written to GPR/CSR/mem)\n");
	return;
    }
    fprintf (stdout, "    wdata = %0" PRIx64 "\n", wdata);

    status = write_internal (target, addr, rw_size, wdata);
    if (status == STATUS_OK)
	fprintf (stdout, "  OK\n");
    else
	fprintf (stdout, "ERROR: 'write' did not get RW_OK response\n");
}

// ================================================================
// Write n_bytes to remote CPU's mem by iterating write_internal()

int exec_write_buf (const uint64_t  start_addr,
		    const int       n_bytes,
		    const uint8_t  *p_wdata)
{
    int      status;
    uint64_t addr   = start_addr;
    uint64_t data;
    int      offset = 0;

    if (offset >= n_bytes) return STATUS_OK;

    // Do leading 1-byte alignment, if any
    if ((addr & 0x1) == 1) {
	memcpy (& data, p_wdata + offset, 1);
	status = write_internal (Dbg_RW_MEM, addr, Dbg_MEM_1B, data);
	if (status != STATUS_OK) return status;
	offset += 1;
	addr   += 1;
    }
    if (offset >= n_bytes) return STATUS_OK;

    // Is now 2-byte aligned
    assert (((addr + offset) & 0x1) == 0);
    // Do leading 2-byte alignment, if any
    if ((addr & 0x3) == 2) {
	memcpy (& data, p_wdata + offset, 2);
	status = write_internal (Dbg_RW_MEM, addr, Dbg_MEM_2B, data);
	if (status != STATUS_OK) return status;
	offset += 2;
	addr   += 2;
    }
    if (offset >= n_bytes) return STATUS_OK;

    // Is now 4-byte aligned
    assert (((addr + offset) & 0x3) == 0);
    // Do remaining 4-byte reads
    while ((offset + 4) <= n_bytes) {
	memcpy (& data, p_wdata + offset, 4);
	status = write_internal (Dbg_RW_MEM, addr, Dbg_MEM_4B, data);
	if (status != STATUS_OK) return status;
	offset += 4;
	addr   += 4;
    }

    // Do trailing 2-byte alignment, if any
    if ((n_bytes - offset) >= 2) {
	memcpy (& data, p_wdata + offset, 2);
	status = write_internal (Dbg_RW_MEM, addr, Dbg_MEM_2B, data);
	if (status != STATUS_OK) return status;
	offset += 2;
	addr   += 2;
    }

    // Do trailing 1-byte alignment, if any
    if ((n_bytes - offset) == 1) {
	memcpy (& data, p_wdata + offset, 1);
	status = write_internal (Dbg_RW_MEM, addr, Dbg_MEM_1B, data);
	if (status != STATUS_OK) return status;
    }
    return STATUS_OK;
}

// ================================================================
// Dump mem addr a1 through a2
// Print 16 bytes per line, MSB ... LSB, with LSB aligned to 4'b0000
// Print '--' for bytes below addr1 and above addr2

static bool      valid [16];
static uint8_t   buf [16];
static uint64_t  buf_addr;

static
void flush_buf ()
{
    fprintf (stdout, "    ");
    for (int j = 15; j >= 0; j--) {
	if ((j == 11) || (j == 7) || (j == 3))
	    fprintf (stdout, "  ");
	if (valid [j])
	    fprintf (stdout, " %02x", buf [j]);
	else
	    fprintf (stdout, " --");
	valid [j] = false;
    }
    fprintf (stdout, " @ %08" PRIx64 "\n", ((buf_addr >> 4) << 4));
}

static
void append_bytes (const uint64_t addr, const int n_bytes, uint64_t data)
{
    // First time
    if (buf_addr == -1) buf_addr = addr;

    // Check addresses are sequential
    assert (addr == buf_addr);
    assert ((n_bytes == 1) || (n_bytes == 2) || (n_bytes == 4) || (n_bytes == 8));

    // fprintf (stdout, "append_bytes: %0" PRIx64 "  %0d bytes  %0" PRIx64 "\n",
    //	     addr, n_bytes, data);

    // Buffer the new bytes
    for (int j = 0; j < n_bytes; j++) {
	int k = (addr & 0xF) + j;
	buf [k]   = (data & 0xFF);
	valid [k] = true;
	data      = (data >> 8);
    }
    if (((addr + n_bytes - 1) & 0xF) == 0xF)
	flush_buf ();

    buf_addr += n_bytes;
}

static
void exec_dumpmem (const char *cmdline, int index)
{
    uint64_t  addr1, addr2;
    int n = sscanf (cmdline + index, "%" SCNi64 "%" SCNi64, & addr1, & addr2);
    if (n != 2) {
	fprintf (stdout, "ERROR: unable to parse starting and/or ending addr\n");
	return;
    }
    fprintf (stdout, "Dumping mem from addr1 %0" PRIx64 " to addr2 %0" PRIx64 "\n",
	     addr1, addr2);
    if (addr1 >= addr2) {
	fprintf (stdout, "Nothing to print: addr1 (%0" PRIx64 ") > addr2 (%0" PRIx64 ")\n",
		 addr1, addr2);
	return;
    }

    buf_addr = -1;
    int      status;
    uint64_t rdata = 0;

    // Read and show leading misaligned 1-byte, if any
    if ((addr1 & 0x1) == 1) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return;
	}
	// fprintf (stdout, "    Read 1 byte  %0" PRIx64 " => %0" PRIx64 "\n", addr1, rdata);
	append_bytes (addr1, 1, rdata);
	addr1 += 1;
    }
    assert ((addr1 & 0x1) == 0);

    // Read and show leading misaligned 2-bytes, if any
    if ((addr1 & 0x3) == 2) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return;
	}
	// fprintf (stdout, "    Read 2 bytes %0" PRIx64 " => %0" PRIx64 "\n", addr1, rdata);
	append_bytes (addr1, 2, rdata);
	addr1 += 2;
    }
    assert ((addr1 & 0x3) == 0);

    // Read and show aligned 4-bytes, if any
    while ((addr2 - addr1) >= 4) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_4B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 4 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return;
	}
	// fprintf (stdout, "    Read 4 bytes %0" PRIx64 " => %0" PRIx64 "\n", addr1, rdata);
	append_bytes (addr1, 4, rdata);
	addr1 += 4;
    }

    // Read and show trailing misaligned 2-bytes, if any
    if ((addr2 - addr1) >= 2) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_2B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 2 mem bytes at addr %0" PRIx64 "\n",
		     addr1);
	    return;
	}
	// fprintf (stdout, "    Read 2 bytes %0" PRIx64 " => %0" PRIx64 "\n", addr1, rdata);
	append_bytes (addr1, 2, rdata);
	addr1 += 2;
    }

    // Read and show trailing misaligned 1-byte, if any
    if ((addr2 - addr1) == 1) {
	status = read_internal (Dbg_RW_MEM, addr1, Dbg_MEM_1B, & rdata);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: unable to read 1 mem byte at addr %0" PRIx64 "\n",
		     addr1);
	    return;
	}
	// fprintf (stdout, "    Read 1 byte  %0" PRIx64 " => %0" PRIx64 "\n", addr1, rdata);
	append_bytes (addr1, 1, rdata);
	addr1 += 1;
    }

    if ((addr2 & 0xF) != 0)
	flush_buf ();
}

// ================================================================
// Resume running the remote CPU for exactly 1 instruction ('stepi' command)
// and wait for remote CPU to halt (after 1 instruction).

// Arg 'only_if_breakpoint' true => step only if we are at a
// breakpoint, else skip.

static
void exec_stepi (const bool only_if_breakpoint)
{
    int              status;
    uint64_t         dpc, data;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    // Read CSR DPC and remove breakpoint there, if any
    fprintf (stdout, "  Reading CSR DPC\n");
    status = read_dpc_internal (& dpc);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: attempting to read CSR DPC\n");
	return;
    }
    fprintf (stdout, "  Removing breakpoint, if any, at CSR DPC 0x%0" PRIx64 "\n", dpc);
    fprintf (stdout, "      (restoring original instr)\n");
    bool is_breakpoint = rm_breakpoint_internal (dpc);

    if (only_if_breakpoint && (! is_breakpoint)) return;

    // ----------------
    fprintf (stdout, "  Setting CSR DCSR [step] bit\n");

    // Read CSR DCSR
    status = read_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, & data);
    if (status != STATUS_OK) return;

    // Set the 'step' bit
    data = data | mask_dcsr_step;

    // Write DCSR
    status = write_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, data);
    if (status != STATUS_OK) return;

    // ----------------
    fprintf (stdout, "  Resuming execution\n");    // Will single-step

    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_edbstub (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return;

    // ----------------
    fprintf (stdout, "  Awaiting RUNNING confirmation\n");

    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return;
    if (pkt_in.pkt_type != Dbg_from_CPU_RUNNING) {
	fprintf (stdout, "ERROR: stepi command: did not get RUNNING confirmation\n");
	return;
    }

    // ----------------
    fprintf (stdout, "  Awaiting HALTED from remote CPU\n");    // after 1 instr

    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return;
    if (pkt_in.pkt_type != Dbg_from_CPU_HALTED) {
	fprintf (stdout, "ERROR: stepi command: did not get HALTED confirmation\n");
	return;
    }

    fprintf (stdout, "  CPU halted\n");
    fprintf_dcsr (stdout, pkt_in.payload);
    fprintf_dpc ();

    // ----------------
    // Restore breakpoint if there was one before stepping
    if (is_breakpoint) {
	fprintf (stdout, "  Restoring breakpoint at 0x%0" PRIx64 "\n", dpc);
	status = set_breakpoint_internal (dpc);
	if (status != STATUS_OK)
	    fprintf (stdout, "ERROR: couldn't set breakpoint at 0x%0" PRIx64 "\n", dpc);
    }
}

// ================================================================
// Resume running the remote CPU ('continue' command)
// and wait for:
//     either: remote CPU halts (breakpoint)
//     or:     user types 'halt' to force a halt

// ----------------
// trygetchar()
// Returns next input character (ASCII code) from fd.
// Returns -2 if read-err, -1 if no input is available, else the char

static
int trygetchar (const int fd)
{
    uint8_t  ch;
    ssize_t  n;
    struct pollfd  x_pollfd;

    // ----------------
    // Poll for input
    x_pollfd.fd      = fd;
    x_pollfd.events  = POLLRDNORM;
    x_pollfd.revents = 0;
    poll (& x_pollfd, 1, 0);

    // printf ("INFO: %s: Polling for input\n", __FUNCTION__);
    if ((x_pollfd.revents & POLLRDNORM) == 0) {
	return -1;
    }

    // ----------------
    // Input is available; get it
    n = read (fd, & ch, 1);
    if (n < 0) {
	perror ("read()");
	fprintf (stderr, "    In %s\n", __FUNCTION__);
	return -2;
    }
    else if (n == 1) {
	return ch;
    }
    else {
	assert (n == 0);
	return -2;
    }
}

// ----------------------------------------------------------------

static
void exec_continue ()
{
    int              status;
    uint64_t         data;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    // If the current halt-point is a breakpoint, first do a single-step
    // (will restore original instr, step, re-install the breakpoint).

    fprintf (stdout, "  If current instr is breakpoint, step it\n");
    bool only_if_breakpoint = true;
    exec_stepi (only_if_breakpoint);

    // ----------------
    fprintf (stdout, "  Ready to continue: clearing DCSR [step] bit\n");

    // Read CSR DCSR
    status = read_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, & data);
    if (status != STATUS_OK) return;

    // Clear the 'step' bit
    data = data & (~ mask_dcsr_step);

    // Write DCSR
    status = write_internal (Dbg_RW_CSR, addr_csr_dcsr, Dbg_MEM_4B, data);
    if (status != STATUS_OK) return;

    // ----------------
    fprintf (stdout, "  Resuming execution\n");    // Will run (not single-step)

    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_edbstub (__FUNCTION__, & pkt_out);
    if (status != STATUS_OK) return;

    // ----------------
    fprintf (stdout, "  Awaiting RUNNING confirmation\n");

    status = recv_from_edbstub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != STATUS_OK) return;
    if (pkt_in.pkt_type != Dbg_from_CPU_RUNNING) {
	fprintf (stdout, "ERROR: continue command: did not get RUNNING confirmation\n");
	return;
    }
    fprintf (stdout, "  ... running ...; type 'h'/'halt' to force halt of remote CPU\n");

    // ----------------
    fprintf (stdout, "  Awaiting HALTED from remote CPU or 'h'/'halt' on keyboard\n");

    int ch = 0;
    while (true) {
	// Only check for first 'h'
	if (ch != 'h') {
	    // Check for 'h' input on stdin terminal
	    ch = trygetchar (fileno (stdin));
	    if (ch == -2) {
		fprintf (stdout, "ERROR polling terminal for 'h'\n");
		return;
	    }
	    else if (ch == -1) {    // no chars avail
		// skip
	    }
	    else {
		if (ch == 'h') {
		    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
		    pkt_out.pkt_type = Dbg_to_CPU_HALTREQ;
		    status = send_to_edbstub (__FUNCTION__, & pkt_out);
		    if (status != STATUS_OK) return;
		}
		else {
		    fprintf (stdout, "ERROR: unexpected keyboard input; only 'h' expected\n");
		    fprintf (stdout, "    while remote CPU is running\n");
		    fprintf (stdout, "    Ignoring ...\n");
		}
		// Consume and discard rest of line
		int ch1 = 0;
		while (ch1 != '\n') ch1 = fgetc (stdin);
	    }
	}
	// Only poll if we haven't sent a HALTREQ
	Poll do_poll = ((ch == 'h') ? DONT_POLL : DO_POLL);
	status = recv_from_edbstub (__FUNCTION__, do_poll, & pkt_in);
	if (status == STATUS_UNAVAIL) {
	    usleep (1000);
	    continue;
	}
	else if (status != STATUS_OK)
	    return;
	else if (pkt_in.pkt_type == Dbg_from_CPU_HALTED) {
	    fprintf (stdout, "  CPU halted\n");
	    fprintf_dcsr (stdout, pkt_in.payload);
	    fprintf_dpc ();
	    break;
	}
	else {
	    fprintf (stdout, "ERROR: continue command: did not get HALTED confirmation\n");
	    return;
	}
    }
}

// ================================================================
// Quit this EDB program back to the shell

static
void exec_quit ()
{
    Dbg_to_CPU_Pkt   pkt_out;

    // Send QUIT
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_QUIT;
    send_to_edbstub (__FUNCTION__, & pkt_out);
}

// ****************************************************************

void interactive_command_loop ()
{
    int   index;    // Cursor on cmdline for parsing
    char *cmdline;
    int   serialnum = 1;

    // Initialize command-line history, and limit its size
    using_history();
    stifle_history (100);

    // Force a halt, in case remote CPU is running
    // (and also set dcsr.ebreak* bits)
    fprintf (stdout, "Sending initial HALT request in case CPU is already running\n");
    exec_halt ();

    while (true) {
	// Issue prompt and read command-line
	fprintf (stdout, "[%0d] ----------------\n", serialnum);
	cmdline = readline ("EDB: ");
	if (cmdline == NULL) {
	    fprintf (stdout, "EOF; exit\n");
	    break;
	}
	if (strcmp (cmdline, "") == 0) {
	    // Empty command-line
	    free (cmdline);
	    continue;
	}
	add_history (cmdline);
	serialnum++;

	for (int j = 0; cmdline [j] != 0; j++)
	    cmdline [j] = tolower (cmdline [j]);

	Cmd *p_cmd = parse_command (cmdline, & index);
	if (p_cmd == NULL) {
	    fprintf (stdout, "Unable to parse a command; type 'help' for list of commands\n");
	    continue;
	}

	switch (p_cmd->cmd_code) {
	case CMD_QUIT:           exec_quit ();           return;
	case CMD_HELP:           exec_help ();           break;
	case CMD_HELP_GPR_NAMES: exec_help_GPR_Names (); break;
	case CMD_HELP_CSR_NAMES: exec_help_CSR_Names (); break;
	case CMD_HISTORY: exec_history ();               break;

	case CMD_LOADELF:  exec_loadelf (cmdline + index);             break;
	case CMD_BRK:      exec_set_breakpoint (cmdline + index);      break;
	case CMD_RMBRK:    exec_rm_breakpoint (cmdline + index);       break;
	case CMD_LSBRKS:   exec_ls_breakpoints ();                     break;
	case CMD_STEPI:    exec_stepi (/*only_if_breakpoint=*/false ); break;
	case CMD_CONTINUE: exec_continue ();                           break;
	case CMD_HALT:     exec_halt ();                               break;

	case CMD_RGPR: exec_read  (cmdline, index, Dbg_RW_GPR, Dbg_MEM_4B); break;
	case CMD_RCSR: exec_read  (cmdline, index, Dbg_RW_CSR, Dbg_MEM_4B); break;
	case CMD_RMEM: exec_read  (cmdline, index, Dbg_RW_MEM, Dbg_MEM_4B); break;

	case CMD_WGPR: exec_write (cmdline, index, Dbg_RW_GPR, Dbg_MEM_4B); break;
	case CMD_WCSR: exec_write (cmdline, index, Dbg_RW_CSR, Dbg_MEM_4B); break;
	case CMD_WMEM: exec_write (cmdline, index, Dbg_RW_MEM, Dbg_MEM_4B); break;

	case CMD_DUMPMEM: exec_dumpmem (cmdline, index); break;

	case CMD_ERR:
        default:      fprintf (stdout, "Unrecognized command (type 'help' for help)\n");
	}
    }
}

// ****************************************************************

char edb_log_filename[] = "edb_log.txt";

void print_help (FILE *fd, int argc, char *argv [])
{
    fprintf (fd, "Usage: %s  <optional flags>\n", argv [0]);
    fprintf (fd, "  Flags:\n");
    fprintf (fd, "  --help, -h    Print this help text and quit\n");
    fprintf (fd, "  --log,  -l    Record communications with edbstub in file '%s'\n",
	     edb_log_filename);
    fprintf (fd, "  The program will enter an interactive command-loop\n");
    fprintf (fd, "  where you can type 'help' for a list of interctive commands\n");
}

int main (int argc, char *argv [])
{
    fprintf (stdout, "EDB v.1.00 ((c) 2024 R.S.Nikhil, Bluespec Inc.)\n");
    fprintf (stdout, "    Rerun with --help for help.\n");

    for (int j = 0; j < argc; j++) {
	if ((strcmp (argv [j], "--help") == 0) || (strcmp (argv [j], "-h") == 0)) {
	    print_help (stdout, argc, argv);
	    return 0;
	}
    }

    for (int j = 0; j < argc; j++) {
	if (strcmp (argv [j], "-log") == 0) {
	    flog = fopen (edb_log_filename, "w");
	    if (flog == NULL) {
		fprintf (stdout, "ERROR: unable to open file '%s'\n", edb_log_filename);
		fprintf (stdout, "       Proceeding without logging\n");
	    }
	    fprintf (stdout, "Logging communication with edbstub in %s\n",
		     edb_log_filename);
	    break;
	}
    }

    // Open TCP connection to remote edbstub server
    int status;
    status = tcp_client_open (server_hostname, server_listen_port);
    if (status == STATUS_ERR) {
	fprintf (stdout, "ERROR: tcp_client_open\n");
	return 1;
    }
    
    for (int j = 0; j < MAX_NUM_BRKPTS; j++)
	breakpoint_arr [j].addr = -1;

    // ================================================================
    
    interactive_command_loop ();

    // ================================================================
    // Postlude
    fprintf (stdout, "Quitting ... (waiting for TCP shutdown)\n");

    // Wait 1 sec so 'QUIT' message reaches stub
    sleep (1);

    status = tcp_client_close (0);
    if (status == STATUS_ERR) {
	fprintf (stdout, "ERROR: tcp_client_close\n");
	return 1;
    }
    return 0;
}

// ****************************************************************
// TODO (FUTURE IMPROVEMENTS)

// Add 'loadmemhex32' command, like 'loadELF'
// In read_buf/write_buf, do 64-bit reads if remote server supports it.
// In read_buf/write_buf, pipeline write requests and responses, instead of one-at-a-time.

// ****************************************************************
