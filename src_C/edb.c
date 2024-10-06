// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// EDB: "Economical/Elementary Debugger"
// EDB is a simple debugger which can be used like GDB to control a remote RISC-V CPU.

// EDB uses TCP to connect to a remote server controlling a RISC-V CPU
//     (simulation or hardware).  It uses RSPS (RSP/Structural) for
//     communication with the server.

// EDB is far simpler (and far less capable) than GDB/LLDB.
// * An RSPS server for a CPU is MUCH simpler to implement than a RISC-V Debug Module
// * EDB is small, standalone, easily-portable C program, whereas
//     GDB/LLDB require more serious installation effort.

// * All the code is small, simple, and open-source, and therefore
//     more suitable for teaching principles of how remote debugging
//     is implemented.

// EDB has a small repertoire of commands:
//     Type 'help' at the interactive prompt for a list.

// You will still need GDB/LLDB for:
// * Source-code (C, C++, ...) debugging. EDB only has a RISC-V ISA-level view.
// * Scripting (gdb scripting, Python scripting, ...)

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
#include "Dbg_Pkts.h"
#include "ISA_Defs.h"
#include "gdbstub_be.h"

// ****************************************************************
// Verbosity for this module

static
int verbosity = 0;

// ****************************************************************
// Poll the CPU connection for a HALTED message, if any
// TODO: should this be added to gdbstub_be.h or gdbstub_be_RSPS.h?
extern
uint32_t  gdbstub_be_poll_for_halted (const uint8_t xlen);

// Pretty-pring dcsr cause field
// TODO: should this be added to gdbstub_be_RSPS.h?
extern
void fprintf_dcsr_cause (FILE *fd, const char *pre, const uint32_t dcsr, const char *post);

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
    if (n != 1) {
	fprintf (stdout, "ERROR: unknown GPR specified.\n");
	fprintf (stdout, "  An acceptable GPR spec is:\n");
	fprintf (stdout, "    0   ... 31\n");
	fprintf (stdout, "    0x0 ... 0x1F\n");
	fprintf (stdout, "    x0  ... x31\n");
	fprintf (stdout, "    symbolic-GPR-name   (type 'GPR_Names' for list of GPR names\n");
	return STATUS_ERR;
    }
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
    fprintf (stdout, "A GPR can be specified with symbolic name or hex or decimal number:\n");
    fprintf (stdout, "    Symbolic     Hex  Decimal\n");
    for (int j = 0; GPR_ABI_Names [j].name != NULL; j += 1) {
	fprintf (stdout, "    %4s  x%0d", GPR_ABI_Names [j].name, GPR_ABI_Names [j].val);
	if (GPR_ABI_Names [j].val < 10) fprintf (stdout, " ");
	fprintf (stdout, "    0x%0x", GPR_ABI_Names [j].val);
	if (GPR_ABI_Names [j].val < 0x10) fprintf (stdout, " ");
	fprintf (stdout, " %0d\n", GPR_ABI_Names [j].val);
    }
}

static
void exec_help_CSR_Names ()
{
    fprintf (stdout, "A CSR can be specified with a 12-bit CSR address (hex or decimal)\n");
    fprintf (stdout, "or with one of these symbolic names:\n");
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
    int status = gdbstub_be_stop (gdbstub_be_xlen);
    if (status != STATUS_OK)
	fprintf (stdout, "ERROR: attemping to halt the CPU\n");
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

    gdbstub_be_elf_load (filename);
}

// ================================================================
// Breakpoints

// Breakpoints are stored in EDB in an array of (PC,original-instr)
// breakpoint-entries. The array is not sorted; free entries have
// 'invalid' PCs.

typedef struct {
    uint64_t  addr;     // PC of breakpoing (use -1 to denote 'invalid')
    uint32_t  instr;    // original instruction at this location
} Brkpt_Entry;

#define MAX_NUM_BRKPTS 128
static
Brkpt_Entry  breakpoint_arr [MAX_NUM_BRKPTS];

// Command-line set/remove/list breakpoint is just a local operation
// on this array. ('set' attempts to read memory just to check that
// the addr is readable).

// When EDB executes 'continue', it replaces instructions in memory at
// breakpoints with the 'EBREAK' instruction, and holds the original
// instruction in the breakpoint-entry.

// When EDB regains control after the CPU halts (for whatever reason),
// the original instructions are restored.

// ----------------------------------------------------------------
// Set a breakpoint

static
void exec_set_breakpoint (const char *cmdline)
{
    int      status;

    // Get breakpoint addr from command line
    uint64_t  brk_addr;
    status = parse_1_int_arg (cmdline, & brk_addr);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: unable to read 1 int arg (breakpoint addr)\n");
	return;
    }

    // Check 4-byte alignment
    if ((brk_addr & 0x3) != 0) {
	fprintf (stdout, "ERROR: breakpoint addr is not 4-byte aligned\n");
	fprintf (stdout, "       Ignoring addr 0x%08" PRIx64 " ...\n", brk_addr);
	return;
    }
    // Scan breakpoint array for empty slot/duplicate
    int j1 = -1;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	if ((j1 == -1) && (breakpoint_arr [j].addr == -1))
	    j1 = j;
	else if (breakpoint_arr [j].addr == brk_addr) {
	    fprintf (stdout, "NOTE: This is already a breakpoint\n");
	    fprintf (stdout, "       Ignoring addr 0x%08" PRIx64 " ...\n", brk_addr);
	    return;
	}
    }
    if (j1 == -1) {
	fprintf (stdout, "ERROR: already have maximum number of breakpoints (%0d)\n",
		 MAX_NUM_BRKPTS);
	fprintf (stdout, "       Ignoring ...\n");
	return;
    }
    // Check if this memory location is readable
    // (Note: actual saving of original instr will be done in 'continue')
    uint64_t rdata;
    status = gdbstub_be_mem_read (gdbstub_be_xlen, brk_addr, (char *) (& rdata), 4);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: failed trying to read breakpoint location\n");
	fprintf (stdout, "       Ignoring addr 0x%08" PRIx64 " ...\n", brk_addr);
	return;
    }
    breakpoint_arr [j1].addr  = brk_addr;
    breakpoint_arr [j1].instr = rdata;
    return;
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
    int status = gdbstub_be_mem_write (gdbstub_be_xlen,
				       brk_addr,
				       (char *) & (breakpoint_arr [j1].instr),
				       4);
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
    fprintf (stdout, "  Current breakoints:\n");
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	if (breakpoint_arr [j].addr != -1) {
	    fprintf (stdout, "    %0d: addr 0x%0" PRIx64 "\n", j, breakpoint_arr [j].addr);
	    n++;
	}
    }
    if (n == 0)
	fprintf (stdout, "No breakpoints currently set\n");
}

// ================================================================
// Read GPR/CSR/Mem

void exec_read (const char         *cmdline,
		int                 index,
		const Dbg_RW_Target target,
		const Dbg_RW_Size   rw_size)
{
    int      status, index2;
    uint64_t addr;
    uint64_t rdata;

    if (target == Dbg_RW_GPR) {
	status = parse_GPR_num (cmdline, index, & addr, & index2);
	if (status != STATUS_OK)
	    return;

	fprintf (stdout, "Reading GPR x%0" PRId64 "\n", addr);
	status = gdbstub_be_GPR_read (gdbstub_be_xlen, addr, & rdata);
    }
    else if (target == Dbg_RW_CSR) {
	status = parse_CSR_addr (cmdline, index, & addr, & index2);
	if (status != STATUS_OK)
	    return;

	fprintf (stdout, "Reading CSR 0x%0" PRIx64 "\n", addr);
	status = gdbstub_be_CSR_read (gdbstub_be_xlen, addr, & rdata);
    }
    else {
	assert (target == Dbg_RW_MEM);
	status = parse_1_int_arg (cmdline + index, & addr);
	if (status != STATUS_OK)
	    return;

	fprintf (stdout, "Reading Mem [0x%0" PRIx64 "]\n", addr);
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr, (char *) (& rdata),
				      ((gdbstub_be_xlen==32) ? 4 : 8));
    }

    if (status == STATUS_OK)
	fprintf (stdout, "  Read-value: 0x%0" PRIx64 "\n", rdata);
    else
	fprintf (stdout, "ERROR: did not get RW_OK response\n");
}

// ================================================================
// Read n_bytes from remote CPU's memory, by iterating read_internal().
// This is used by loadELF for a readback check after loading an ELF into memory.

int exec_read_buf (const uint64_t  start_addr,
		   const int       n_bytes,
		         uint8_t  *p_rdata)
{
    return gdbstub_be_mem_read (gdbstub_be_xlen, start_addr, (char *) p_rdata, n_bytes);
}

// ================================================================
// Write GPR/CSR/Mem

static
void exec_write (const char         *cmdline,
		 int                 index,
		 const Dbg_RW_Target target,
		 const Dbg_RW_Size   rw_size)
{
    // Parse address
    int      status, index2;
    uint64_t addr;
    if (target == Dbg_RW_GPR) {
	status = parse_GPR_num (cmdline, index, & addr, & index2);
	if (status != STATUS_OK)
	    return;
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

    // Parse wdata
    uint64_t wdata;
    int n = sscanf (cmdline + index2, "%" SCNi64, & wdata);
    if (n != 1) {
	fprintf (stdout, "ERROR: unable to parse w-data (to be written to GPR/CSR/mem)\n");
	return;
    }
    fprintf (stdout, "    wdata = %0" PRIx64 "\n", wdata);

    if (target == Dbg_RW_GPR)
	status = gdbstub_be_GPR_write (gdbstub_be_xlen, addr, wdata);
    else if (target == Dbg_RW_CSR)
	status = gdbstub_be_CSR_write (gdbstub_be_xlen, addr, wdata);
    else {
	assert (target == Dbg_RW_MEM);
	status = gdbstub_be_mem_write (gdbstub_be_xlen, addr, (char *) (& wdata),
				       ((gdbstub_be_xlen == 32) ? 4 : 8));
    }

    if (status == STATUS_OK)
	fprintf (stdout, "  OK\n");
    else
	fprintf (stdout, "ERROR: 'write' did not get RW_OK response\n");
}

// ================================================================
// Write n_bytes to remote CPU's mem by iterating write_internal()
// This is used by loadELF to load an ELf into memory.

int exec_write_buf (const uint64_t  start_addr,
		    const int       n_bytes,
		    const uint8_t  *p_wdata)
{
    return gdbstub_be_mem_write (gdbstub_be_xlen, start_addr, (char *) p_wdata, n_bytes);
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
	fprintf (stdout, "  Empty addr range; no-op\n");
	return;
    }

    buf_addr = -1;
    int      status;
    uint64_t rdata = 0;

    // Read and show leading misaligned 1-byte, if any
    if ((addr1 & 0x1) == 1) {
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr1, (char *) (& rdata), 1);
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
    if ((addr1 < addr2) && ((addr1 & 0x3) == 2)) {
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr1, (char *) (& rdata), 2);
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
    while ((addr1 < addr2) && ((addr2 - addr1) >= 4)) {
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr1, (char *) (& rdata), 4);
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
    if ((addr1 < addr2) && ((addr2 - addr1) >= 2)) {
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr1, (char *) (& rdata), 2);
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
    if ((addr1 < addr2) && ((addr2 - addr1) == 1)) {
	status = gdbstub_be_mem_read (gdbstub_be_xlen, addr1, (char *) (& rdata), 1);
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
// exec_stepi()
// Resume running the remote CPU for exactly 1 instruction ('stepi' command)
// and wait for remote CPU to halt (after 1 instruction).

static
void exec_stepi ()
{
    int status = gdbstub_be_step (gdbstub_be_xlen);
    if (status != STATUS_OK)
	fprintf (stdout, "ERROR: while trying to stepi\n");
}

// ================================================================
// Resume running the remote CPU ('continue' command)
// and wait for:
//     either: remote CPU halts (breakpoint)
//     or:     user types anything to force a halt

// ----------------
// trygetchar()
// Polls for next input character (ASCII code) from fd (keyboard).
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
// Strategy for 'continue':

// * Single step the first instruction
// * Set all breakpoints (saving original instrs)
//        Note: instr mem could have changed before this.
// * continue execution (until self-halt or halt request)
// * Restore original instrs at all breakpoints
//        Note: instr mem may be viewed after this.

#define EBREAK_INSTR 0x00100073

static
void exec_continue ()
{
    int      status, n_brks;
    uint64_t rdata, wdata, brk_addr;
    uint32_t orig_instr, dcsr_ebreak_bits_mask, dcsr_ebreak_step_bits_original;

    // ----------------------------------------------------------------
    // Single-step first instruction, before arming breakpoints
    if (verbosity != 0)
	fprintf (stdout, "  Single-stepping first instruction before arming breakpoints\n");

    status = gdbstub_be_step (gdbstub_be_xlen);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: during first-instruction single-step on 'continue'\n");
	return;
    }

    // ----------------------------------------------------------------
    // Insert all breakpoints
    if (verbosity != 0)
	fprintf (stdout, "  Insert all breakpoints\n");
    // ----------------
    // Read original instrs at all breakpoints
    if (verbosity != 0)
	fprintf (stdout, "    Read and save original instrs at breakpoints\n");
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	// Skip if this is not a valid breakpoint
	if ((breakpoint_arr [j].addr & 0x1) == 1) continue;

	// Read instruction at this memory location, for later restore
	brk_addr = breakpoint_arr [j].addr;
	status = gdbstub_be_mem_read (gdbstub_be_xlen, brk_addr, (char *) (& rdata), 4);
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: In 'continue', while inserting breakpoints\n");
	    fprintf (stdout, "    Failed read original instruction @ %08" PRIx64 "\n",
		     brk_addr);
	    fprintf (stdout, "    Please first remove that breakpoint\n");
	    return;
	}
	if (verbosity != 0)
	    fprintf (stdout, "    Original instr @ %08" PRIx64 " is 0x%08" PRIx64 "\n",
		     brk_addr, rdata);
	breakpoint_arr [j].instr = rdata;
    }
    // ----------------
    // Write EBREAK instruction at all breakpoints
    if (verbosity != 0)
	fprintf (stdout, "    Write EBREAK instr at all breakpoints\n");
    n_brks = 0;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	// Skip if this is not a valid breakpoint
	if ((breakpoint_arr [j].addr & 0x1) == 1) continue;

	// Write EBREAK instruction at this memory location
	wdata    = EBREAK_INSTR;
	brk_addr = breakpoint_arr [j].addr;
	if (verbosity != 0)
	    fprintf (stdout, "    Set @ %08" PRIx64 " to EBREAK instr (0x%08x)\n",
		     brk_addr, EBREAK_INSTR);
	status = gdbstub_be_mem_write (gdbstub_be_xlen, brk_addr, (char *) (& wdata), 4);
	n_brks++;
	if (status != STATUS_OK) {
	    fprintf (stdout, "ERROR: In 'continue', while inserting breakpoints\n");
	    fprintf (stdout, "    Failed write @ %08" PRIx64 " EBREAK instruction\n",
		     brk_addr);
	    fprintf (stdout, "    There will be no breakpoint at that addr\n");
	}
    }
    if (verbosity != 0)
	fprintf (stdout, "    %0d breakpoints inserted\n", n_brks);

    // ----------------------------------------------------------------
    // Set DCSR.{EBREAK*} bits, clear DCSR.STEP (and remember original settings)
    if (verbosity != 0)
	fprintf (stdout, "  Set dcsr [ebreak*] bits, clear DCRS [step] bit\n");
    // Read DCSR
    status = gdbstub_be_CSR_read (gdbstub_be_xlen, addr_csr_dcsr, & rdata);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: In 'continue', while arming breakpoints\n");
	fprintf (stdout, "    Failed reading CSR DCSR (to set ebreak* bits)\n");
	return;
    }
    // Remember EBREAK* and STEP bits (to restore after 'continue')
    dcsr_ebreak_bits_mask = (mask_dcsr_ebreakvs | mask_dcsr_ebreakvu
			     | mask_dcsr_ebreakm | mask_dcsr_ebreaks
			     | mask_dcsr_ebreaku);
    dcsr_ebreak_step_bits_original = (rdata & (dcsr_ebreak_bits_mask | mask_dcsr_step));
    // Set the various ebreak* bits
    wdata = (rdata | dcsr_ebreak_bits_mask);
    // Clear the step bit
    wdata = (wdata & (~ mask_dcsr_step));
    // Write back DCSR
    if (verbosity != 0)
	fprintf (stdout, "  Updating DCSR: %08" PRIx64 " => %08" PRIx64 "\n", rdata, wdata);
    status = gdbstub_be_CSR_write (gdbstub_be_xlen, addr_csr_dcsr, wdata);
    if (status != STATUS_OK){
	fprintf (stdout, "ERROR: In 'continue', while updating CSR ebreak*/step bits\n");
	fprintf (stdout, "    Failed writing back CSR DCSR\n");
	return;
    }

    // ----------------
    // Resume execution
    status = gdbstub_be_continue (gdbstub_be_xlen);
    if (status != STATUS_OK)
	return;

    // ----------------
    fprintf (stdout, "  ... running ... (awaiting HALTED from remote CPU)\n");
    fprintf (stdout, "  To force halt, type anything on the keyboard\n");
    fprintf (stdout, "      (<newline> by itself is enough; input is discarded)\n");
    int ch = 0;
    while (true) {
	// Only check for first 'h'
	if (ch != 'h') {
	    // Check for 'h' input on stdin terminal
	    ch = trygetchar (fileno (stdin));
	    if (ch == -2) {
		fprintf (stdout, "ERROR: in polling for keyboard activity\n");
	    }
	    else if (ch == -1) {    // no chars avail
		// skip
	    }
	    else {
		fprintf (stdout, "  Forcing CPU halt due to keyboard activity ...\n");
		// Consume and discard rest of keyboard input line
		int ch1 = ch;
		while (ch1 != '\n') ch1 = fgetc (stdin);
		ch = 'h';    // Don't poll keyboard any more
		status = gdbstub_be_stop (gdbstub_be_xlen);
		if (status != STATUS_OK)
		    fprintf (stdout, "ERROR: attempting CPU 'halt'\n");
		break;
	    }
	}
	status = gdbstub_be_poll_for_halted (gdbstub_be_xlen);
	if (status == STATUS_UNAVAIL) {
	    usleep (1000);
	    continue;
	}
	else {
	    if (status != STATUS_OK)
		fprintf (stdout, "ERROR: polling CPU for HALTED state\n");
	    break;
	}
    }

    // ----------------
    // Restore all breakpoints with original instructions
    // Read CSR DPC if it is at a breakpoint, remove the breakpoint
    // Then: write EBREAK instruction at all breakpoints
    if (verbosity != 0)
	fprintf (stdout, "  Disarm all breakpoints (restore pre-EBREAK instrs)\n");
    n_brks = 0;
    for (int j = 0; j < MAX_NUM_BRKPTS; j++) {
	// Skip if this is not a valid breakpoint
	if ((breakpoint_arr [j].addr & 0x1) == 1) continue;

	// Restore original instruction at this memory location
	brk_addr   = breakpoint_arr [j].addr;
	orig_instr = breakpoint_arr [j].instr;
	if (verbosity != 0)
	    fprintf (stdout, "    Restore @ %08" PRIx64 " instr 0x%08x\n",
		     brk_addr, orig_instr);
	status = gdbstub_be_mem_write (gdbstub_be_xlen, brk_addr, (char *) (& orig_instr), 4);
	n_brks++;
	if (status != STATUS_OK) {
	    // Note: this failure can occur even if previous breakpoint-arming succeeded
	    //       if, for example, PMPs have changed during the program-run
	    fprintf (stdout, "ERROR: In 'continue', while restoring breakpoint instr\n");
	    fprintf (stdout, "    Failed write @ %08" PRIx64 " instr %08x\n",
		     brk_addr, orig_instr);
	}
    }

    // ----------------
    // Print halt cause, for information
    if (verbosity != 0)
	fprintf (stdout, "  Restore dcsr [ebreak*] bits\n");
    // Read DCSR
    status = gdbstub_be_CSR_read (gdbstub_be_xlen, addr_csr_dcsr, & rdata);
    if (status != STATUS_OK) {
	fprintf (stdout, "ERROR: In 'continue', while arming breakpoints\n");
	fprintf (stdout, "    Failed reading CSR DCSR (to restore ebreak* bits)\n");
	return;
    }
    fprintf_dcsr_cause (stdout, "  CPU halt reason: ", rdata, "\n");
    
    // ----------------
    // Restore DCSR's original ebreak* and step bits
    // Restore ebreak bits
    wdata = ((rdata & (~ (dcsr_ebreak_bits_mask | mask_dcsr_step)))
	     | dcsr_ebreak_step_bits_original);
    if (verbosity != 0)
	fprintf (stdout, "  Restoring DCSR: %08" PRIx64 " => %08" PRIx64 "\n", rdata, wdata);
    // Write back DCSR
    status = gdbstub_be_CSR_write (gdbstub_be_xlen, addr_csr_dcsr, wdata);
    if (status != STATUS_OK){
	fprintf (stdout, "ERROR: In 'continue', while arming breakpoints\n");
	fprintf (stdout, "    Failed writing back CSR DCSR (to restore ebreak* bits)\n");
	return;
    }

    // ----------------
    if (verbosity != 0)
	fprintf (stdout, "    %0d breakpoints disarmed\n", n_brks);
}

// ================================================================
// Quit this EDB program back to the shell

static
void exec_quit ()
{
    fprintf (stdout, "Quitting ...\n");
    gdbstub_be_final (gdbstub_be_xlen);
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

	case CMD_LOADELF:  exec_loadelf (cmdline + index);        break;
	case CMD_BRK:      exec_set_breakpoint (cmdline + index); break;
	case CMD_RMBRK:    exec_rm_breakpoint (cmdline + index);  break;
	case CMD_LSBRKS:   exec_ls_breakpoints ();                break;
	case CMD_STEPI:    exec_stepi ();                         break;
	case CMD_CONTINUE: exec_continue ();                      break;
	case CMD_HALT:     exec_halt ();                          break;

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
    fprintf (fd, "  --log,  -l    Record remote communication with CPU in file '%s'\n",
	     edb_log_filename);
    fprintf (fd, "  The program will enter an interactive command-loop\n");
    fprintf (fd, "  where you can type 'help' for a list of interactive commands\n");
}

int main (int argc, char *argv [])
{
    fprintf (stdout, "EDB v.1.10 (c) 2024 R.S.Nikhil, Bluespec Inc.\n");
    fprintf (stdout, "  Rerun with --help or -h for help on command-line args.\n");
    fprintf (stdout, "  In interactive command loop type 'help' for more help\n");

    for (int j = 0; j < argc; j++) {
	if ((strcmp (argv [j], "--help") == 0) || (strcmp (argv [j], "-h") == 0)) {
	    print_help (stdout, argc, argv);
	    return 0;
	}
    }

    FILE *flog = NULL;

    for (int j = 0; j < argc; j++) {
	if ((strcmp (argv [j], "--log") == 0) || (strcmp (argv [j], "-l") == 0)) {
	    flog = fopen (edb_log_filename, "w");
	    if (flog == NULL)
		fprintf (stdout, "ERROR: unable to open file '%s'\n", edb_log_filename);
	    fprintf (stdout, "Logging communication with RISC-V server in: %s\n",
		     edb_log_filename);
	    break;
	}
    }
    if (flog == NULL)
	fprintf (stdout, "Not logging communication with RISC-V server.\n");

    // Open TCP connection to remote edbstub server
    int status = gdbstub_be_init (flog, false);
    if (status == STATUS_ERR)
	return 1;
    
    for (int j = 0; j < MAX_NUM_BRKPTS; j++)
	breakpoint_arr [j].addr = -1;

    // ================================================================
    
    interactive_command_loop ();

    return 0;
}

// ****************************************************************
// TODO (FUTURE IMPROVEMENTS)

// Add 'loadmemhex32' command, like 'loadELF'

// ****************************************************************
