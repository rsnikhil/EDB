// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// RISC-V ISA definitions

// ****************************************************************
// Includes from C library

// General
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

// ================================================================
// Includes for this project

#include "ISA_Defs.h"

// ****************************************************************

// ================================================================
// GPR names

Name_Value GPR_ABI_Names [] = {
    { "zero",  0},  { "ra",   1},  { "sp",   2}, { "gp",   3},
    { "tp",    4},  { "t0",   5},  { "t1",   6}, { "t2",   7},
    { "fp",    8},
    { "s0",    8},  { "s1",   9},  { "a0",  10}, { "a1",  11},
    { "a2",   12},  { "a3",  13},  { "a4",  14}, { "a5",  15},
    { "a6",   16},  { "a7",  17},  { "s2",  18}, { "s3",  19},
    { "s4",   20},  { "s5",  21},  { "s6",  22}, { "s7",  23},
    { "s8",   24},  { "s9",  25},  { "s10", 26}, { "s11", 27},
    { "t3",   28},  { "t4",  29},  { "t5",  30}, { "t6",  31},

    { NULL,    0}
};

// ================================================================
// FPR names

Name_Value FPR_ABI_Names [] = {
    { "ft0",   0},  { "ft1",  1},  { "ft2",   2}, { "ft3",   3},
    { "ft4",   4},  { "ft5",  5},  { "ft6",   6}, { "ft7",   7},
    { "fs0",   8},  { "fs1",  9},  { "fa0",  10}, { "fa1",  11},
    { "fa2",  12},  { "fa3", 13},  { "fa4",  14}, { "fa5",  15},
    { "fa6",  16},  { "fa7", 17},  { "fs2",  18}, { "fs3",  19},
    { "fs4",  20},  { "fs5", 21},  { "fs6",  22}, { "fs7",  23},
    { "fs8",  24},  { "fs9", 25},  { "fs10", 26}, { "fs11", 27},
    { "ft8",  28},  { "ft9", 29},  { "ft10", 30}, { "ft11", 31},

    { NULL,    0}
};

// ================================================================
// CSR names
// NOTE: This is only a PARTIAL list of CSR names.
//       All csrs can be addressed with a hex addr.

Name_Value CSR_Names [] = {
    { "fflags",     0x001},
    { "frm",        0x002},
    { "fcsr",       0x003},

    { "cycle",      0xC00},
    { "time",       0xC01},
    { "instret",    0xC02},
    { "cycleh",     0xC80},
    { "timeh",      0xC81},
    { "instreth",   0xC82},

    { "mvendorid",  0xF11},
    { "marchid",    0xF12},
    { "mimpid",     0xF13},
    { "mhartid",    0xF14},

    { "mstatus",    0x300},
    { "misa",       0x301},
    { "medeleg",    0x302},
    { "mideleg",    0x303},
    { "mie",        0x304},
    { "mtvec",      0x305},

    { "mscratch",   0x340},
    { "mepc",       0x341},
    { "mcause",     0x342},
    { "mtval",      0x343},
    { "mip",        0x344},

    { "mcycle",     0xB00},
    { "minstret",   0xB02},
    { "mcycle",     0xB80},
    { "minstret",   0xB82},

    { "dcsr",       0x7B0},
    { "dpc",        0x7B1},
    { "dscratch0",  0x7B2},
    { "dscratch1",  0x7B3},

    { NULL,        0}
};

// ================================================================
