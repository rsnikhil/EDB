This 'vendor/' dir contains sources from external git repos

Each <foo>.vendor.hjson specifies an external repo, and specifies
which files are to be copied from that repo.

The Makefile describes how each such resource is created.
Briefly, each resource <foo> is created by:

    $ ../Tools/vendor.py    <foo>

The tool '../Tools/vendor.py' is downloaded from:
    https://github.com/lowRISC/opentitan/blob/master/util/vendor.py

    It is an alternative to using Git sub-modules for external repositories.

The git repo code has a back-end (gdbstub_be.c) intended to drive a
hardware RISC-V Debug Module using DMI commands (Debug Module
Interface).

Here, we replace gdbstub_be.c with a version that directly accesses
CissrV2 components.
