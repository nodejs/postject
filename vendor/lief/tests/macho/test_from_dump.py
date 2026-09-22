import lief
import pytest
from utils import get_sample


@pytest.mark.private
def test_parse_from_dump():
    dump_path = get_sample("private/MachO/runtime-simple-lib_11e32c000.dump")
    fat = lief.MachO.parse_from_dump(dump_path, 0x11E32C000)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None

    assert len(macho.segments) > 0

    text = macho.get_segment("__TEXT")
    assert text is not None
    assert bytes(text.content[:4]) == b"\xcf\xfa\xed\xfe"

    assert len(macho.libraries) > 0
