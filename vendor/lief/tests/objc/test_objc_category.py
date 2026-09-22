import lief
import pytest
from utils import parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


def _get_metadata():
    macho = parse_macho("MachO/ios17/DebugHierarchyKit").at(0)
    assert macho is not None
    metadata = macho.objc_metadata
    assert metadata is not None
    return metadata


def test_categories():
    metadata = _get_metadata()

    categories = list(metadata.categories)
    assert len(categories) == 1

    cat = categories[0]
    assert cat.class_name == "DebugHierarchyRequest"
    assert cat.name == "DebugHierarchyTargetHub"

    methods = list(cat.methods)
    assert len(methods) == 2
    assert methods[0].name == "lldbExpressionReturningNSDataOutError:"
    assert methods[0].is_instance
    assert methods[1].name == "lldbExpressionInPlaceOutError:"


def test_adopted_protocols():
    """
    Protocols adopted by another protocol (``@protocol Foo <Bar>``).
    """
    metadata = _get_metadata()

    standalone = metadata.get_protocol("DBGStandaloneDataSourceConnection")
    assert standalone is not None
    adopted = list(standalone.protocols)
    assert len(adopted) == 1
    assert adopted[0].mangled_name == "DBGDataSourceConnection"

    value = metadata.get_protocol("DBGValue")
    assert value is not None
    adopted = list(value.protocols)
    assert len(adopted) == 1
    assert adopted[0].mangled_name == "NSObject"


def test_superclass():
    metadata = _get_metadata()

    coordinator = metadata.get_class("DBGDataCoordinator")
    assert coordinator is not None
    assert coordinator.super_name == "NSObject"
    assert coordinator.super_class is None

    hub = metadata.get_class("DBGDataCoordinatorTargetHub")
    assert hub is not None
    assert hub.super_name == "DBGDataCoordinator"
    assert hub.super_class is not None
    assert hub.super_class.name == "DBGDataCoordinator"

    assert hub.super_class.super_name == "NSObject"
    assert hub.super_class.super_class is None

    on_disk = metadata.get_class("DBGDataCoordinatorOnDiskTargetHub")
    assert on_disk is not None
    assert on_disk.super_name == "DBGDataCoordinatorTargetHub"
    assert on_disk.super_class is not None
    assert on_disk.super_class.name == "DBGDataCoordinatorTargetHub"
    assert on_disk.super_class.super_name == "DBGDataCoordinator"
