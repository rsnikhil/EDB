# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

.PHONY: help
help:
	@echo "Targets:"
	@echo "  all                 make EXE      (= $(EXE))"
	@echo "  test                run  EXE ARGS (= $(EXE) $(ARGS))"
	@echo "  exe_test_edbstub    Builds a test server program to test edbstub"
	@echo "  exe_test_loadELF    Builds a standalone test program for loadELF"
	@echo ""
	@echo "  clean               Remove temporary files"
	@echo "  full_clean          Restore directory to pristine state"

# ================================================================
# Temporary convenience

EXE  ?= exe_test_loadELF
ARGS ?= RTOSDemo.elf

.PHONY: all test
all: $(EXE)

test: $(EXE)
	./$(EXE)  $(ARGS)

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
# exe_test_edbstub

SRCS_C_TEST_EDBSTUB  = edbstub.c
SRCS_C_TEST_EDBSTUB += ../src_C/Dbg_Pkts.c

SRCS_H_TEST_EDBSTUB += ../src_C/Dbg_Pkts.h

exe_test_edbstub: test_edbstub.c  $(SRCS_H_TEST_EDBSTUB)  $(SRCS_C_TEST_EDBSTUB)
	$(CC) $(CFLAGS) -o  exe_test_edbstub  -I ../src_C/  \
		test_edbstub.c  $(SRCS_C_TEST_EDBSTUB)

# ================================================================
# exe_test_loadELF

SRCS_C_LOADELF  = ../src_C/loadELF.c
SRCS_H_LOADELF += ../src_C/loadELF.h

exe_test_loadELF: test_loadELF.c  $(SRCS_H_LOADELF)  $(SRCS_C_LOADELF)
	$(CC) $(CFLAGS) -o  exe_test_loadELF  -I ../src_C/  \
	  test_loadELF.c  $(SRCS_C_LOADELF) \
	  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  exe_test_edbstub*  exe_test_loadELF*

# ================================================================
