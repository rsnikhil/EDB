# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

EXE = exe_gdbstub_RSPS_TCP

.PHONY: help
help:
	@echo "Targets:"
	@echo "  $(EXE)    Standalone executable intermediary between GDB and dut"
	@echo ""
	@echo "  Housekeeping and convenience"
	@echo "  all           make $(EXE)"
	@echo "  clean         Remove temporary files"
	@echo "  full_clean    Restore directory to pristine state"

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

# ================================================================
# Sources

MAIN_C         = ../src_C/main_gdbstub_RSPS_TCP.c

SRC_C          = ../src_C
VENDOR_GDBSTUB = ../vendor/bluespec_RISCV_gdbstub

# SRCS_C += $(SRC_C)/ISA_Defs.c
SRCS_C += $(SRC_C)/Dbg_Pkts.c
SRCS_C += $(SRC_C)/TCP_Client_Lib.c
SRCS_C += $(SRC_C)/loadELF.c
SRCS_C += $(SRC_C)/gdbstub_be_RSPS_TCP.c
SRCS_C += $(VENDOR_GDBSTUB)/gdbstub_fe.c

# SRCS_H  = $(SRC_C)/ISA_Defs.h
SRCS_H  = $(SRC_C)/Status.h
SRCS_H  = $(SRC_C)/Dbg_Pkts.h
SRCS_H += $(SRC_C)/TCP_Client_Lib.h
SRCS_H += $(SRC_C)/loadELF.h
SRCS_H += $(VENDOR_GDBSTUB)/gdbstub_be.h
SRCS_H += $(VENDOR_GDBSTUB)/gdbstub_fe.h

# ================================================================

$(EXE):  $(MAIN_C)  $(SRCS_H)  $(SRCS_C)
	$(CC) $(CFLAGS) -o $(EXE)  -I $(SRC_C)  $(MAIN_C)  $(SRCS_C)  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  $(EXE)  $(EXE).dSYM

# ================================================================
