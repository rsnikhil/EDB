// Copyright (c) 2020-2022 Bluespec, Inc.  All Rights Reserved

// ================================================================
// Client communications over TCP/IP

// Sends and receives bytevecs over a TCP socket to/from a remote server

// ----------------
// Acknowledgement: portions of TCP code adapted from example ECHOSERV
//   ECHOSERV
//   (c) Paul Griffiths, 1999
//   http://www.paulgriffiths.net/program/c/echoserv.php

// ================================================================
// C lib includes

// General
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

// For comms polling
#include <poll.h>
#include <sched.h>

// For TCP
#include <sys/socket.h>       /*  socket definitions        */
#include <sys/types.h>        /*  socket types              */
#include <arpa/inet.h>        /*  inet (3) funtions         */
#include <fcntl.h>            /* To set non-blocking mode   */
#include <netinet/tcp.h>

// ----------------
// Project includes

#include "Status.h"
#include "TCP_Client_Lib.h"

// ================================================================
// The socket file descriptor

static int sockfd = 0;

// ================================================================
// Open a TCP socket as a client connected to specified remote
// listening server socket.
// Return STATUS_ERR or STATUS_OK.

uint32_t  tcp_client_open (const char *server_host, const uint16_t server_port)
{
    if (server_host == NULL) {
	fprintf (stdout, "ERROR: %s: server_host is NULL\n", __FUNCTION__);
	return STATUS_ERR;
    }
    if (server_port == 0) {
	fprintf (stdout, "ERROR: %s: server_port is 0\n", __FUNCTION__);
	return STATUS_ERR;
    }

    fprintf (stdout, "%s: connecting to '%s' port %0d\n",
	     __FUNCTION__, server_host, server_port);

    // Create the socket
    if ( (sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0 ) {
	fprintf (stdout, "ERROR: %s: unable to create socket.\n", __FUNCTION__);
	return STATUS_ERR;
    }

    struct sockaddr_in servaddr;  // socket address structure

    // Initialize socket address structure
    memset (& servaddr, 0, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port   = htons (server_port);

    // Set the remote IP address
    if (inet_aton (server_host, & servaddr.sin_addr) <= 0 ) {
	fprintf (stdout, "ERROR: %s: Invalid remote IP address.\n", __FUNCTION__);
	return STATUS_ERR;
    }

    // connect() to the remote server
    if (connect (sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr) ) < 0 ) {
	fprintf (stdout, "ERROR: %s: failed connect()\n", __FUNCTION__);
	return STATUS_ERR;
    }

    // This code copied from riscv-openocd's jtag_vpi.c, where they say:
    //    "This increases performance dramatically for local
    //     connections, which is the most likely arrangement ..."
    if (servaddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
	int flag = 1;
	setsockopt (sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) & flag, sizeof(int));
    }

    fprintf (stdout, "%s: connected\n", __FUNCTION__);
    return STATUS_OK;
}

// ================================================================
// Close the connection to the remote server.

uint32_t  tcp_client_close (uint32_t dummy)
{
    if (sockfd > 0) {
	// fprintf (stdout, "%s\n", __FUNCTION__);
	shutdown (sockfd, SHUT_RDWR);
	close (sockfd);
	sleep (1);
    }

    return  STATUS_OK;
}

// ================================================================
// Send a message

uint32_t  tcp_client_send (const uint32_t data_size, const uint8_t *data)
{
    int n;

    n = write (sockfd, data, data_size);

    if (n < 0) {
	fprintf (stdout, "ERROR: %s() = %0d\n", __FUNCTION__, n);
	perror ("    ");
	return STATUS_ERR;
    }
    return STATUS_OK;
}

// ================================================================
// Recv a message
// Return STATUS_OK/STATUS_UNAVAIL (no input data available)/STATUS_ERR

uint32_t  tcp_client_recv (bool do_poll, const uint32_t data_size, uint8_t *data)
{
    // Poll, if required
    if (do_poll) {
	struct pollfd  x_pollfd;
	x_pollfd.fd      = sockfd;
	x_pollfd.events  = POLLRDNORM;
	x_pollfd.revents = 0;

	int n = poll (& x_pollfd, 1, 0);

	if (n < 0) {
	    fprintf (stdout, "ERROR: %s: failed poll ()\n", __FUNCTION__);
	    return STATUS_ERR;
	}

	if ((x_pollfd.revents & POLLRDNORM) == 0) {
	    return STATUS_UNAVAIL;
	}
    }

    // Read data
    int  n_recd = 0;
    while (n_recd < data_size) {
	int n = read (sockfd, & (data [n_recd]), (data_size - n_recd));
	if ((n < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
	    fprintf (stdout, "ERROR: %s: read () failed on byte 0\n", __FUNCTION__);
	    return STATUS_ERR;
	}
	else if (n > 0) {
	    n_recd += n;
	}
    }
    return STATUS_OK;
}

// ================================================================
