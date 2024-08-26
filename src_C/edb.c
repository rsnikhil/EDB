// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// EDB: "Economical/Elementary Debugger"

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

// ----------------
// Includes for this project

#include "TCP_Client_Lib.h"
#include "Pkts.h"

// ****************************************************************
// The socket file descriptor

static char     server_hostname [] = "127.0.0.1";
static uint16_t server_listen_port = 30000;

// ****************************************************************
// Parse EDB interactive command

bool is_s1_prefix_of_s2 (const char *s1, const char *s2)
{
    int j = 0;
    while (true) {
	if (s1 [j] == 0) return true;
	if (s2 [j] == 0) return false;
	if (s1 [j] != s2 [j]) return false;
	j++;
    }
}

typedef enum {CMD_HELP,
	      CMD_HALT,
	      CMD_CONTINUE, CMD_STEPI,
	      CMD_RR, CMD_WR,
	      CMD_RC, CMD_WC,
	      CMD_RM, CMD_WM,
	      CMD_QUIT, CMD_ERR} Cmd_Code;

typedef struct {
    Cmd_Code  cmd_code;
    char     *cmd_name;
    int       num_args;
    char     *cmd_doc;
} Cmd;
    
Cmd cmds []
= { { CMD_HELP,     "help",     0, "Print this help" },
    { CMD_HALT,     "halt",     0, "Halt exec of running CPU" },
    { CMD_CONTINUE, "continue", 0, "Resume exec of halted CPU" },
    { CMD_STEPI,    "stepi",    0, "Resume exec of halted CPU for exactly one instruction" },
    { CMD_RR,       "rrg",      1, "Read  GPR <regnum>" },
    { CMD_WR,       "wrg",      2, "Write GPR <gpraddr> <data>" },
    { CMD_RC,       "rc",       1, "Read  CSR <csraddr>" },
    { CMD_WC,       "wc",       2, "Write CSR <csraddr> <data>" },
    { CMD_RM,       "rm",       1, "Read  Mem <memaddr>" },
    { CMD_WM,       "wm",       2, "Write Mem <memaddr> <data>" },
    { CMD_QUIT,     "quit",     0, "Quit EDB" },
    { CMD_ERR,      "" } };

#define LINEBUF_SIZE 1024

static int serialnum = 1;

int get_command (uint64_t *p_arg1, uint64_t *p_arg2)
{
    int      cmd, n;
    char    *p;
    uint64_t arg1 = 0, arg2 = 0;

    char linebuf [LINEBUF_SIZE];
    char verb    [LINEBUF_SIZE];

    fprintf (stdout, "----------------\n");
    fprintf (stdout, "[%0d] EDB: ", serialnum);
    serialnum++;
    p = fgets (linebuf, LINEBUF_SIZE, stdin);
    if (p == NULL)
	return CMD_QUIT;

    n = sscanf (linebuf, "%s", verb);
    if (n == 0)
	return CMD_ERR;

    int j_match = -1;
    for (int j = 0; cmds [j].cmd_code != CMD_ERR; j++)
	if (is_s1_prefix_of_s2 (verb, cmds [j].cmd_name)) {
	    if (j_match >= 0) {
		fprintf (stdout, "Ambigouous match '%s' and '%s'\n",
			 cmds [j_match].cmd_name,
			 cmds [j].cmd_name);
		return CMD_ERR;
	    }
	    j_match = j;
	}

    cmd = ((j_match >= 0) ? j_match : CMD_ERR);

    if (cmds [j_match].num_args >= 1) {
	n = sscanf (linebuf, "%s %" SCNi64, verb, & arg1);
	if (n != 2) {
	    fprintf (stdout, "ERROR: could not parse arg0 (reg num/csr addr/mem addr)\n");
	    return CMD_ERR;
	}
	if (cmds [j_match].num_args == 2) {
	    n = sscanf (linebuf, "%s %" SCNi64 " %" SCNi64, verb, & arg1, & arg2);
	    if (n != 3) {
		fprintf (stdout, "ERROR: could not parse arg2 (reg/csr/mem write-data)\n");
		return CMD_ERR;
	    }
	}
    }
    *p_arg1 = arg1;
    *p_arg2 = arg2;
    return cmd;
}	

// ****************************************************************
// EDB interactive commands

// ================================================================
// Packet send/recv

typedef enum { DONT_POLL, DO_POLL } Poll;

static
int send_to_stub (const char *context, Dbg_to_CPU_Pkt *p_pkt_out)
{
    print_to_CPU_pkt (stdout, "Sending ", p_pkt_out, "\n");

    int status = tcp_client_send (sizeof (Dbg_to_CPU_Pkt),
				  (uint8_t *) p_pkt_out);
    if (status == status_err) {
	fprintf (stdout, "ERROR: in %s.%s.tcp_client_send()\n", context, __FUNCTION__);
	return status_err;
    }
    return status_ok;
}

static
int recv_from_stub (const char *context, const Poll poll, Dbg_from_CPU_Pkt *p_pkt_in)
{
    bool do_poll = (poll == DO_POLL);
    int  status  = tcp_client_recv (do_poll,
				    sizeof (Dbg_from_CPU_Pkt),
				    (uint8_t *) p_pkt_in);
    if (status == status_err)
	fprintf (stdout, "ERROR: %s.%s.tcp_client_recv()\n", context, __FUNCTION__);

    else if (status == status_ok)
	print_from_CPU_pkt (stdout, "Received", p_pkt_in, "\n");

    else {
	assert (status == status_unavail);
	// 'unavailable' is only legal if we are polling
	assert (do_poll);
    }
    return status;
}

// ================================================================
// Command execution

static
int exec_command_help ()
{
    fprintf (stdout, "Commands:\n");
    for (int j = 0; cmds [j].cmd_code != CMD_ERR; j++)
	fprintf (stdout, "  %-10s  %s\n", cmds [j].cmd_name, cmds [j].cmd_doc);
    return status_ok;
}

static
int exec_command_halt ()
{
    int              status;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // Send HALTREQ
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_HALTREQ;
    status = send_to_stub (__FUNCTION__, & pkt_out);
    if (status != status_ok) return status;

    // Wait for HALTED or ERR response
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;
    if (pkt_in.pkt_type == Dbg_from_CPU_HALTED)
	fprintf (stdout, "CPU halted\n");
    else if (pkt_in.pkt_type == Dbg_from_CPU_ERR) {
	fprintf (stdout, "ERROR response for HALTREQ\n");
	fprintf (stdout, "    CPU may have been halted already?\n");
    }
    else {
	fprintf (stdout, "ERROR: Unexpected response for HALTREQ\n");
	fprintf (stdout, "       Expecting HALTED confirmation\n");
	status = status_err;
    }
    return status;
}

static
int exec_command_read (const Dbg_RW_Target target, const uint64_t addr, uint64_t *p_rdata)
{
    int status;

    // Send request
    Dbg_to_CPU_Pkt  pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type  = Dbg_to_CPU_RW;
    pkt_out.rw_op     = Dbg_RW_READ;
    pkt_out.rw_size   = Dbg_MEM_4B;
    pkt_out.rw_target = target;
    pkt_out.rw_addr   = addr;
    pkt_out.rw_wdata  = 0xAAAAAAAA;    // bogus value

    status = send_to_stub (__FUNCTION__, & pkt_out);
    if (status != status_ok) return status;
	    
    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;

    *p_rdata = pkt_in.payload;
    if (pkt_in.pkt_type == Dbg_from_CPU_RW_OK)
	fprintf (stdout, " Read-value: 0x%0" PRIx64 "\n", pkt_in.payload);
    else
	fprintf (stdout, " Read ERROR: expecting RW_OK response\n");
    return status_ok;
}

static
int exec_command_write (const Dbg_RW_Target target, const uint64_t addr, const uint64_t wdata)
{
    int status;

    // Send request
    Dbg_to_CPU_Pkt  pkt_out;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type  = Dbg_to_CPU_RW;
    pkt_out.rw_op     = Dbg_RW_WRITE;
    pkt_out.rw_size   = Dbg_MEM_4B;
    pkt_out.rw_target = target;
    pkt_out.rw_addr   = addr;
    pkt_out.rw_wdata  = wdata;

    status = send_to_stub (__FUNCTION__, & pkt_out);
    if (status != status_ok) return status;

    // Receive response
    Dbg_from_CPU_Pkt  pkt_in;
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;
    if (pkt_in.pkt_type == Dbg_from_CPU_RW_OK)
	fprintf (stdout, "OK\n");
    else
	fprintf (stdout, "Write ERROR: expecting RW_OK response\n");
    return status_ok;
}

// ================================================================
// Exec continue

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

// ----------------

static
int exec_command_continue ()
{
    int              status;
    uint64_t         data;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    fprintf (stdout, "Clearing dcsr [step] bit\n");

    // Read DCSR
    status = exec_command_read (Dbg_RW_CSR, addr_csr_dcsr, & data);
    if (status != status_ok) return status;

    // Clear the 'step' bit
    data = data & (~ mask_dcsr_step);

    // Write DCSR
    status = exec_command_write (Dbg_RW_CSR, addr_csr_dcsr, data);
    if (status != status_ok) return status;

    // ----------------
    // Send RESUMEREQ
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_stub (__FUNCTION__, & pkt_out);
    if (status != status_ok) return status;

    // ----------------
    fprintf (stdout, "Await RUNNING confirmation\n");

    // Receive RUNNING confirmation
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;
    if (pkt_in.pkt_type == Dbg_from_CPU_RUNNING)
	fprintf (stdout, "... running ...; type 'h' to force halt of remote CPU\n");
    else {
	fprintf (stdout, "continue command ERROR: expecting RUNNING confirmation\n");
	return status_err;
    }

    // ----------------
    fprintf (stdout, "Await HALTED from stub or 'h' on terminal\n");

    int ch = 0;
    while (true) {
	// Only check for first 'h'
	if (ch != 'h') {
	    // Check for 'h' input on stdin terminal
	    ch = trygetchar (fileno (stdin));
	    if (ch == -2) {
		fprintf (stdout, "ERROR polling terminal for 'h'\n");
		return status_err;
	    }
	    else if (ch == -1) {    // no chars avail
		// skip
	    }
	    else {
		if (ch == 'h') {
		    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
		    pkt_out.pkt_type = Dbg_to_CPU_HALTREQ;
		    status = send_to_stub (__FUNCTION__, & pkt_out);
		    if (status != status_ok) return status;
		}
		else {
		    fprintf (stdout, "Unrecognized keyboard input; only 'h' expected\n");
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
	status = recv_from_stub (__FUNCTION__, do_poll, & pkt_in);
	if (status == status_unavail) {
	    usleep (1000);
	    continue;
	}
	else if (status != status_ok)
	    return status;
	else if (pkt_in.pkt_type == Dbg_from_CPU_HALTED) {
	    break;
	}
	else {
	    fprintf (stdout, "continue command ERROR: expecting HALTED confirmation\n");
	    return status_err;
	}
    }
    return status_ok;
}

// ================================================================

static
int exec_command_stepi ()
{
    int               status;
    uint64_t          data;
    Dbg_to_CPU_Pkt   pkt_out;
    Dbg_from_CPU_Pkt pkt_in;

    // ----------------
    fprintf (stdout, "Setting dcsr [step] bit\n");

    // Read DCSR
    status = exec_command_read (Dbg_RW_CSR, addr_csr_dcsr, & data);
    if (status != status_ok) return status;

    // Set the 'step' bit
    data = data | mask_dcsr_step;

    // Write DCSR
    status = exec_command_write (Dbg_RW_CSR, addr_csr_dcsr, data);
    if (status != status_ok) return status;

    // ----------------
    // Send RESUMEREQ
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_RESUMEREQ;
    status = send_to_stub (__FUNCTION__, & pkt_out);
    if (status != status_ok) return status;

    // ----------------
    fprintf (stdout, "Await RUNNING confirmation\n");

    // Receive RUNNING confirmation
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;
    if (pkt_in.pkt_type != Dbg_from_CPU_RUNNING) {
	fprintf (stdout, "stepi command ERROR: expecting RUNNING confirmation\n");
	return status_err;
    }

    // ----------------
    fprintf (stdout, "Await HALTED from stub\n");

    // Receive HALTED confirmation
    status = recv_from_stub (__FUNCTION__, DONT_POLL, & pkt_in);
    if (status != status_ok) return status;
    if (pkt_in.pkt_type != Dbg_from_CPU_HALTED) {
	fprintf (stdout, "stepi command ERROR: expecting HALTED confirmation\n");
	return status_err;
    }
    return status_ok;
}

// ================================================================

static
int exec_command_quit ()
{
    int               status;
    Dbg_to_CPU_Pkt   pkt_out;

    // Send QUIT
    memset (& pkt_out, 0, sizeof (Dbg_to_CPU_Pkt));
    pkt_out.pkt_type = Dbg_to_CPU_QUIT;
    status = send_to_stub (__FUNCTION__, & pkt_out);
    return status;
}

// ****************************************************************

void main_loop ()
{
    int      cmd;
    uint64_t arg1, arg2, data;

    while (true) {
	cmd = get_command (& arg1, & arg2);
	// fprintf (stdout, "cmd %0d arg1 %0" PRIx64 " arg2 %0" PRIx64 "\n", cmd, arg1, arg2);

	switch (cmd) {
	case CMD_QUIT:     exec_command_quit ();                          return;
	case CMD_HELP:     exec_command_help ();                          break;
	case CMD_HALT:     exec_command_halt ();                          break;
	case CMD_CONTINUE: exec_command_continue ();                      break;
	case CMD_STEPI:    exec_command_stepi ();                         break;
	case CMD_RR:       exec_command_read  (Dbg_RW_GPR, arg1, & data); break;
	case CMD_WR:       exec_command_write (Dbg_RW_GPR, arg1, arg2);   break;
	case CMD_RC:       exec_command_read  (Dbg_RW_CSR, arg1, & data); break;
	case CMD_WC:       exec_command_write (Dbg_RW_CSR, arg1, arg2);   break;
	case CMD_RM:       exec_command_read  (Dbg_RW_MEM, arg1, & data); break;
	case CMD_WM:       exec_command_write (Dbg_RW_MEM, arg1, arg2);   break;

	case CMD_ERR:
        default:           fprintf (stdout, "Unrecognized command (type 'help' for help)\n");
	}
    }
}

// ****************************************************************

int main (int argc, char *argv [])
{
    uint32_t status;

    status = tcp_client_open (server_hostname, server_listen_port);
    if (status == status_err) {
	fprintf (stdout, "ERROR: tcp_client_open\n");
	return 1;
    }

    main_loop ();

    // Wait 1 sec so 'QUIT' message reaches stub
    sleep (1);

    status = tcp_client_close (0);
    if (status == status_err) {
	fprintf (stdout, "ERROR: tcp_client_close\n");
	return 1;
    }
    return 0;
}
