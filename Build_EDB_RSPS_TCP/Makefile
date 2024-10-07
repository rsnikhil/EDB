# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

EXE = edb_RSPS_TCP

.PHONY: help
help:
	@echo "Targets:"
	@echo "  all                    make $(EXE)"
	@echo ""
	@echo "  clean                  Remove temporary files"
	@echo "  full_clean             Restore directory to pristine state"

.PHONY: all
all: $(EXE)

# ================================================================
# C compiler flags

CFLAGS += -std=gnu11 -g -Wall -Werror
CFLAGS += -I $(VENDOR_GDBSTUB)

# For include <gelf.h> on MacOS, after 'brew install libelf'
CFLAGS += -I /opt/homebrew/include
CFLAGS += -I /opt/homebrew/include/libelf/

# For libelf.a on MacOS
CFLAGS += -L /opt/homebrew/lib

LDLIBS  = -lelf
LDLIBS += -lreadline

# ================================================================
# Sources

SRC_C          = ../src_C
VENDOR_GDBSTUB = ../vendor/bluespec_RISCV_gdbstub

SRCS_C_EDB += $(SRC_C)/Dbg_Pkts.c
SRCS_C_EDB += $(SRC_C)/ISA_Defs.c
SRCS_C_EDB += $(SRC_C)/TCP_Client_Lib.c
SRCS_C_EDB += $(SRC_C)/loadELF.c
SRCS_C_EDB += $(SRC_C)/gdbstub_be_RSPS_TCP.c

SRCS_H_EDB  = $(SRC_C)/Status.h
SRCS_H_EDB  = $(SRC_C)/Dbg_Pkts.h
SRCS_H_EDB  = $(SRC_C)/ISA_Defs.h
SRCS_H_EDB += $(SRC_C)/TCP_Client_Lib.h
SRCS_H_EDB += $(SRC_C)/loadELF.h
SRCS_H_EDB += $(VENDOR_GDBSTUB)/gdbstub_be.h

# ================================================================

$(EXE):  $(SRC_C)/edb.c  $(SRCS_H_EDB)  $(SRCS_C_EDB)
	$(CC) $(CFLAGS) -o $(EXE)  -I $(SRC_C)/  $(SRC_C)/edb.c  $(SRCS_C_EDB)  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  edb_RSPS_TCP*

# ================================================================
