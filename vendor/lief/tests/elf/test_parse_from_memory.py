import ctypes

import lief
import pytest


@pytest.mark.linux
def test_parse_loaded_library():
    """
    Parse an ELF shared library that is already loaded in this process
    by reading its base address from /proc/self/maps.
    """

    ctypes.CDLL("libc.so.6")
    libc_path = None
    libc_base = None

    with open("/proc/self/maps") as f:
        for line in f:
            if "libc" in line and line.strip().endswith(".so.6"):
                parts = line.split()
                libc_base = int(parts[0].split("-")[0], 16)
                libc_path = parts[-1].strip()
                break

    if libc_base is None or libc_path is None:
        pytest.skip("Could not locate libc in /proc/self/maps")

    file_bin = lief.ELF.parse(libc_path)
    assert file_bin is not None

    # Parse the loaded library from its base address in memory
    mem_bin = lief.ELF.parse_from_memory(libc_base)
    assert mem_bin is not None
    assert mem_bin.header.machine_type == file_bin.header.machine_type
    assert len(mem_bin.segments) == len(file_bin.segments)
