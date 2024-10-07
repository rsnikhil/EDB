# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

EXE1 ?= exe_test_BDPI_RSPS_TCP_server
EXE2 ?= exe_test_loadELF

.PHONY: help
help:
	@echo "Targets:"
	@echo "  $(EXE1)"
	@echo "                  A test RSPS_TCP server program (fake CPU) to test EDB/GDB"
	@echo "  $(EXE2)"
	@echo "                  A standalone test program for loadELF"
	@echo ""
	@echo "  Housekeeping/convenience:"
	@echo "    exe1          make EXE1 (=  $(EXE1))"
	@echo "    exe2          make EXE2 (=  $(EXE2))"
	@echo "    all           make EXE1  EXE2"
	@echo "    clean         Remove temporary files"
	@echo "    full_clean    Restore directory to pristine state"

# ================================================================
# Convenience

.PHONY: all exe1 exe2
exe1: $(EXE1)
exe2: $(EXE2)
all: $(EXE1) $(EXE2)

# ================================================================
# C compiler flags

CFLAGS += -std=gnu11 -g -Wall -Werror

# For include <gelf.h> on MacOS, after 'brew install libelf'
CFLAGS += -I /opt/homebrew/include
CFLAGS += -I /opt/homebrew/include/libelf/

# For libelf.a on MacOS
CFLAGS += -L /opt/homebrew/lib

LDLIBS  = -lelf

# ================================================================
# Tb RSPS TCP server

MAIN_C_EXE1  = Test_BDPI_RSPS_TCP_server.c
SRCS_C_EXE1 += ../src_C/BDPI_RSPS_TCP_server.c
SRCS_C_EXE1 += ../src_C/Dbg_Pkts.c

SRCS_H_EXE1 += ../src_C/Dbg_Pkts.h

$(EXE1): $(MAIN_C_EXE1)  $(SRCS_H_EXE1)  $(SRCS_C_EXE1)
	$(CC) $(CFLAGS) -o $(EXE1)  -I ../src_C/  \
		$(MAIN_C_EXE1)  $(SRCS_C_EXE1)

# ================================================================
# Tb loadELF

SRCS_C_EXE2  = ../src_C/loadELF.c
SRCS_H_EXE2 += ../src_C/loadELF.h

$(EXE2): test_loadELF.c  $(SRCS_H_EXE2)  $(SRCS_C_EXE2)
	$(CC) $(CFLAGS) -o $(EXE2)  -I ../src_C/  \
	  test_loadELF.c  $(SRCS_C_EXE2) \
	  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  $(EXE1)  $(EXE1).dSYM  $(EXE2)  $(EXE2).dSYM

# ================================================================
