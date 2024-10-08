// Copyright (c) 2020-2022 Bluespec, Inc.  All Rights Reserved
// Author: Rishiyur S.Nikhil

// Please see Elf_read.c for documentation

#pragma once

// ****************************************************************
// Extern decls for Elf_read.c

extern
int loadELF (const int   verbosity,
	     const bool  do_readback_check,
	     const char *elf_filename);

// ****************************************************************
