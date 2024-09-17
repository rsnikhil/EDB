// ================================================================
// Copyright (c) 2024 Rishiyur S. Nikhil. All Rights Reserved

// RISC-V ISA definitions

// ****************************************************************

typedef struct {
    char *name;
    int  val;
} Name_Value;

// ================================================================
// GPR names

extern
Name_Value GPR_ABI_Names [];

// ================================================================
// FPR names

extern
Name_Value FPR_ABI_Names [];

// ================================================================
// CSR names

extern
Name_Value CSR_Names [];

// ================================================================
