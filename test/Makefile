# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

.PHONY: help
help:
	@echo "Targets:"
	@echo "  all/exe_test_edbstub    Builds a test server program to test edbstub"
	@echo ""
	@echo "  clean                   Remove temporary files"
	@echo "  full_clean              Restore directory to pristine state"

.PHONY: all
all: exe_test_edbstub

# ================================================================
# C compiler flags

CFLAGS += -std=gnu11 -g -Wall -Werror

# ================================================================
# Test server

SRCS_C_TEST  = edbstub.c
SRCS_C_TEST += ../src_C/Dbg_Pkts.c

SRCS_H_TEST += ../src_C/Dbg_Pkts.h

exe_test_edbstub: test_edbstub.c  $(SRCS_H_TEST)  $(SRCS_C_TEST)
	$(CC) $(CFLAGS) -o  exe_test_edbstub  -I ../src_C/  test_edbstub.c  $(SRCS_C_TEST)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  exe_test_edbstub*

# ================================================================
