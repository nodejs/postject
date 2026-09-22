import lief
import pytest
from utils import get_sample


@pytest.mark.private
def test_parse_from_dump():
    dump_path = get_sample("private/PE/_lief_extended_7ffd21b80000.pyd")
    pe = lief.PE.parse_from_dump(dump_path, 0x7FFD21B80000)
    assert pe is not None

    assert len(pe.sections) > 0

    assert len(pe.imports) > 0
    assert pe.has_exports
