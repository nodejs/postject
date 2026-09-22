import lief
import pytest
from utils import get_sample


@pytest.mark.private
def test_parse_from_dump():
    dump_path = get_sample("private/ELF/lief_extended_7f9b98e00000.dump")
    elf = lief.ELF.parse_from_dump(dump_path, 0x7F9B98E00000)
    assert elf is not None

    assert elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
    assert elf.header.machine_type == lief.ELF.ARCH.X86_64
    assert len(elf.segments) > 0

    load = [s for s in elf.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
    assert len(load) > 0
    first = min(load, key=lambda s: s.virtual_address)
    assert bytes(first.content[:4]) == b"\x7fELF"
