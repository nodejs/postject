import lief
import pytest
from utils import parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def test_small_method():
    """
    Make sure the "relative" offset is correctly defined
    """

    macho = parse_macho("MachO/ios17/DebugHierarchyKit").at(0)
    assert macho is not None
    metadata = macho.objc_metadata
    assert metadata is not None
    DBGDataCoordinator = metadata.get_class("DBGDataCoordinator")
    assert DBGDataCoordinator is not None

    methods = list(DBGDataCoordinator.methods)

    _m0 = methods[0]
    assert _m0 is not None
    assert _m0.address == 0x15B00


def test_issue_1353():
    """
    Non-regression for https://github.com/lief-project/LIEF/issues/1353
    """
    macho = parse_macho("private/MachO/issue_1353").at(0)
    assert macho is not None
    metadata = macho.objc_metadata
    assert metadata is not None

    Foo = metadata.get_class("Foo")
    assert Foo is not None

    methods = list(Foo.methods)
    assert len(methods) == 1

    bar = methods[0]
    assert bar is not None
    assert bar.name == "bar"
    assert bar.address == 0x100000728
