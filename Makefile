# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

.PHONY: help
help:
	@echo "Targets:"
	@echo "  edb                    Builds the EDB client program"
	@echo "  exe_Elf_to_Memhex32    Builds the Elf-to-Memhex32 program"
	@echo ""
	@echo "  all                    make all the above targets"
	@echo "  clean                  Remove temporary files"
	@echo "  full_clean             Restore directory to pristine state"

.PHONY: all
all: edb  exe_Elf_to_Memhex32

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

SRCS_C_EDB += src_C/Dbg_Pkts.c
SRCS_C_EDB += src_C/ISA_Defs.c
SRCS_C_EDB += src_C/TCP_Client_Lib.c
SRCS_C_EDB += src_C/loadELF.c

SRCS_H_EDB  = src_C/Status.h
SRCS_H_EDB  = src_C/Dbg_Pkts.h
SRCS_H_EDB  = src_C/ISA_Defs.h
SRCS_H_EDB += src_C/TCP_Client_Lib.h
SRCS_H_EDB += src_C/loadELF.h

edb:  src_C/edb.c  $(SRCS_H_EDB)  $(SRCS_C_EDB)
	$(CC) $(CFLAGS) -o edb  -I src_C/  src_C/edb.c  $(SRCS_C_EDB)  $(LDLIBS)

# ================================================================
# exe_Elf_to_Memhex32

SRCS_C_E2MH += src_C/loadELF.c

SRCS_H_E2MH  = src_C/Status.h
SRCS_H_E2MH += src_C/loadELF.h

exe_Elf_to_Memhex32: src_C/Elf_to_Memhex32.c $(SRCS_H_E2MH) $(SRCS_C_E2MH)
	$(CC) $(CFLAGS) -o exe_ELF_to_Memhex32 -I src_C  src_C/Elf_to_Memhex32.c \
	  $(SRCS_C_E2MH)  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	make -C test clean
	rm -r -f  *~  src_C/*~

.PHONY: full_clean
full_clean: clean
	make -C test full_clean
	rm -r -f  edb*  exe_ELF_to_Memhex32*  *.memhex32

# ================================================================
