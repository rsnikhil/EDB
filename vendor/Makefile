.PHONY: help
help:
	@echo "Targets:"
	@echo "  $(TARGETS)"
	@echo "  all           All targets"
	@echo "  clean         Delete temporary files"
	@echo "  full_clean    Restore to pristine state"
	@echo "See each <target>.vendor.hjson for details of remote repos etc."

# ================================================================
VENDOR_PY = ./vendor.py

TARGETS += bluespec_RISCV_gdbstub
LOCKS   += bluespec_RISCV_gdbstub.lock.hjson
.PHONY: bluespec_RISCV_gdbstub
bluespec_RISCV_gdbstub:
	$(VENDOR_PY)  bluespec_RISCV_gdbstub.vendor.hjson

# ================================================================

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -r -f  *~

.PHONY: full_clean
full_clean: clean
	rm -r -f  bluespec_RISCV_gdbstub  bluespec_RISCV_gdbstub.lock.hjson
