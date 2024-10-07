# Copyright (c) 2024 Rishiyur S. Nikhil and Bluespec, Inc.  All Rights Reserved.
# ================================================================

.PHONY: help
help:
	@echo "Targets:"
	@echo "  exe_Elf_to_Memhex32    Builds the Elf-to-Memhex32 program"
	@echo ""
	@echo "  all                    make $(EXE)"
	@echo "  clean                  Remove temporary files"
	@echo "  full_clean             Restore directory to pristine state"

EXE = exe_Elf_to_Memhex32

.PHONY: all
all: $(EXE)

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
# Sources

SRC_C = ../src_C

MAIN_C = $(SRC_C)/main_Elf_to_Memhex32.c

SRCS_C += $(SRC_C)/loadELF.c

SRCS_H  = $(SRC_C)/Status.h
SRCS_H += $(SRC_C)/loadELF.h

$(EXE): $(MAIN_C) $(SRCS_H) $(SRCS_C)
	$(CC) $(CFLAGS) -o exe_ELF_to_Memhex32 -I $(SRC_C)  $(MAIN_C) \
	  $(SRCS_C)  $(LDLIBS)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  $(EXE)  $(EXE).dSYM  *.memhex32

# ================================================================
