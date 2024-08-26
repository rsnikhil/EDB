EDBSTUB_DIR = $(HOME)/Git/Fife/src_Top
EDBSTUB_C   = $(EDBSTUB_DIR)/edbstub.c
PKTS_H      = $(EDBSTUB_DIR)/Pkts.h
PKTS_C      = $(EDBSTUB_DIR)/Pkts.c

.PHONY: all
all: edb  test_edbstub

edb: src_C/edb.c  src_C/TCP_Client_Lib.c  src_C/TCP_Client_Lib.h  $(PKTS_H)  $(PKTS_C)
	$(CC) -Wall -o  edb  -I$(EDBSTUB_DIR)  src_C/edb.c  src_C/TCP_Client_Lib.c  $(PKTS_C)

test_edbstub: $(EDBSTUB_C)  $(PKTS_H)  $(PKTS_C)
	$(CC) -Wall -o  test_edbstub  -DTEST  -I$(EDBSTUB_DIR)  $(EDBSTUB_C)  $(PKTS_C)

# ================================================================

.PHONY: clean
clean:
	rm -r -f  *~  src*/*~

.PHONY: full_clean
full_clean: clean
	rm -r -f  edb  exe_*  test_edbstub
