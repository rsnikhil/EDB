// Copyright (c) 2020-2023 Bluespec, Inc. All Rights Reserved
// Author: Rishiyur Nikhil
//
// ================================================================
// C lib includes

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

// ----------------
// Local includes

#include "gdbstub_fe.h"

// ****************************************************************

int gdbstub_start_tcp (unsigned short port, Gdbstub_FE_Params *params)
{
    int sockfd, err;
    struct sockaddr_in sa;
    socklen_t salen;

    sockfd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
	fprintf (stderr, "ERROR: Failed to open socket: %s\n", strerror (errno));
	return sockfd;
    }

    int yes = 1;
    err = setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, & yes, sizeof (yes));
    if (err < 0) {
	fprintf (stderr, "ERROR: Failed to set SO_REUSEADDR: %s\n", strerror (errno));
	close (sockfd);
	return err;
    }

    salen = sizeof (sa);
    memset (&sa, 0, salen);
    sa.sin_family = AF_INET;
    sa.sin_port = htons (port);
    sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    err = bind (sockfd, (struct sockaddr *) (& sa), salen);
    if (err < 0) {
	fprintf (stderr, "ERROR: Failed to bind socket: %s\n", strerror (errno));
	close (sockfd);
	return err;
    }

    err = listen (sockfd, 1);
    if (err < 0) {
	fprintf (stderr, "ERROR: Failed to listen on socket: %s\n", strerror (errno));
	close (sockfd);
	return err;
    }

    err = getsockname (sockfd, (struct sockaddr *) (& sa), & salen);
    if (err < 0) {
	fprintf (stderr, "ERROR: Failed to get bound socket address: %s\n", strerror (errno));
	close (sockfd);
	return err;
    }
    else if (salen != sizeof (sa)) {
	fprintf (stderr, "ERROR: Bad address length; got %zu, expected %zu\n",
		 (size_t) salen, sizeof (sa));
	close (sockfd);
	return -1;
    }

    params->gdb_fd = sockfd;

    return ntohs (sa.sin_port);
}

// ================================================================
// Entry point when listening on a TCP socket. Tight loop around
// accept(2) and main_gdbstub, whilst checking stop_fd.

static
void *main_gdbstub_accept (void *arg)
{
    Gdbstub_FE_Params *params = (Gdbstub_FE_Params *) arg;
    FILE *logfile = params->logfile;
    int   sockfd  = params->gdb_fd;
    int   stop_fd = params->stop_fd;
    bool  autoclose_logfile_stop_fd = params->autoclose_logfile_stop_fd;

#ifdef __APPLE__
    // On Apple MacOS, pthread_setname_np() only takes in arg (name)
    //     and sets the name for the invoking thread.
    // On Linux gcc it takes two args: thread and name.
    pthread_setname_np ("gdbstub");
#endif

    // Keep files open across all sessions; we manually close below.
    params->autoclose_logfile_stop_fd = false;

    while (true) {
	fd_set rfds, wfds, efds;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	FD_SET(sockfd, &rfds);
	int fd_max = sockfd;
	if (stop_fd > 0) {
	    FD_SET(stop_fd, &rfds);
	    if (stop_fd > fd_max) {
		fd_max = stop_fd;
	    }
	}

	if (select (fd_max + 1, &rfds, &wfds, &efds, NULL) > 0) {
	    if (stop_fd >= 0 && FD_ISSET(stop_fd, &rfds)) {
		break;
	    }

	    struct sockaddr_in sa;
	    socklen_t salen = sizeof (sa);
	    int gdb_fd = accept (sockfd, (struct sockaddr *) (& sa), & salen);
	    if (gdb_fd < 0) {
		if (logfile) {
		    fprintf (logfile,
			     "ERROR: %s: Failed to accept connection: %s\n",
			     __FUNCTION__, strerror (errno));
		}
		continue;
	    }

	    fprintf (stdout, "Connection accepted\n");
	    if (logfile) {
		char buf[INET_ADDRSTRLEN];
		const char *str = inet_ntop (AF_INET, & sa.sin_addr, buf, sizeof (buf));
		if (str == NULL) {
		    str = "(unknown)";
		}
		fprintf (logfile, "%s: Accepted connection from %s:%u\n",
			 __FUNCTION__, str, ntohs (sa.sin_port));
	    }

	    params->gdb_fd = gdb_fd;
	    main_gdbstub (params);
	}
    }

    if (autoclose_logfile_stop_fd) {
	if (logfile) {
	    fclose (logfile);
	}
	if (stop_fd >= 0) {
	    close (stop_fd);
	}
    }
    close (sockfd);
    return NULL;
}

// ****************************************************************

const unsigned short default_gdb_portnum = 30001;
const char default_logfile_name [] = "gdbserver.log";

int main (int argc, char **argv)
{
    Gdbstub_FE_Params gdbstub_params;

    // Open logfile for communications
    FILE *logfile = fopen (default_logfile_name, "w");
    if (logfile == NULL) {
	fprintf (stdout, "ERROR: unable to open logfile: %s\n", default_logfile_name);
    }
    else
	fprintf (stdout, "Communications logfile: %s\n", default_logfile_name);
    gdbstub_params.logfile = logfile;

    // Open listening socket (connection from GDB)
    fprintf (stdout, "Listening on tcp port %0d for GDB connection ...\n",
	     default_gdb_portnum);
    int rc = gdbstub_start_tcp (default_gdb_portnum, & gdbstub_params);
    if (rc <= 0)
	return 1;

    gdbstub_params.stop_fd = -1;
    gdbstub_params.autoclose_logfile_stop_fd = false;

    main_gdbstub_accept (& gdbstub_params);
    return 0;
}
