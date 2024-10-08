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
// RISC-V DCSR halt cause

typedef enum {DM_DCSR_CAUSE_RESERVED0    = 0,
	      DM_DCSR_CAUSE_EBREAK       = 1,
	      DM_DCSR_CAUSE_TRIGGER      = 2,
	      DM_DCSR_CAUSE_HALTREQ      = 3,
	      DM_DCSR_CAUSE_STEP         = 4,
	      DM_DCSR_CAUSE_RESETHALTREQ = 5,
	      DM_DCSR_CAUSE_RESERVED6    = 6,
	      DM_DCSR_CAUSE_RESERVED7    = 7
} DM_DCSR_Cause;

// ================================================================
