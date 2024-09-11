# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

.PHONY: help
help:
	@echo "Targets:"
	@echo "  edb             Builds the EDB client program"
	@echo "  test_edbstub    Builds a test server program, to test edbstub"
	@echo "  all             Build both the above"
	@echo ""
	@echo "  clean           Remove temporary files"
	@echo "  full_clean      Restore directory to pristine state"

.PHONY: all
all: edb  test_edbstub

# ================================================================
# C compiler flags

CFLAGS += -std=gnu11 -g -Wall -Werror

# For include <gelf.h> on MacOS, after 'brew install libelf'
CFLAGS += -I /opt/homebrew/include
CFLAGS += -I /opt/homebrew/include/libelf/

# For libelf.a on MacOS
CFLAGS += -L /opt/homebrew/lib

LDLIBS  = -lelf
LDLIBS += -lreadline

# ================================================================
# EDB

SRCS_C_EDB += ../src_C/Pkts.c
SRCS_C_EDB += ../src_C/TCP_Client_Lib.c
SRCS_C_EDB += ../src_C/loadELF.c

SRCS_H_EDB  = ../src_C/Status.h
SRCS_H_EDB  = ../src_C/Pkts.h
SRCS_H_EDB += ../src_C/TCP_Client_Lib.h
SRCS_H_EDB += ../src_C/loadELF.h

edb:  ../src_C/edb.c  $(SRCS_H_EDB)  $(SRCS_C_EDB)
	$(CC) $(CFLAGS) -o edb  -I ../src_C/  ../src_C/edb.c  $(SRCS_C_EDB)  $(LDLIBS)

# ================================================================
# Test server

SRCS_C_TEST  = ../src_C/edbstub.c
SRCS_C_TEST += ../src_C/Pkts.c

SRCS_H_TEST += ../src_C/Pkts.h

test_edbstub: ../src_C/test_edbstub.c  $(SRCS_H_TEST)  $(SRCS_C_TEST)
	$(CC) $(CFLAGS) -o  test_edbstub  -I ../src_C/  ../src_C/test_edbstub.c  $(SRCS_C_TEST)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~  ../*~  ../src_C/*~

.PHONY: full_clean
full_clean: clean
	rm -r -f  edb*  test_edbstub*

# ================================================================
