import lief
import pytest
from utils import resolve_runtime_library

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.LINUX:
    pytest.skip("skipping: linux only", allow_module_level=True)


@pytest.mark.runtime
def test_list_modules():
    modules = [m for m in lief.runtime.modules() if m is not None]
    assert len(modules) > 0

    assert all(m.imagebase > 0 for m in modules if m.name)
    assert all(isinstance(m, lief.runtime.linux.Module) for m in modules)

    lief_module = [m for m in modules if m.name in {"_lief.so", "_lief_extended.so"}]
    assert len(lief_module) == 1
    assert len(lief_module[0].path) > 0
    assert lief_module[0].size > 0


@pytest.mark.runtime
def test_handle_and_dlsym():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None
    assert libc.handle is not None
    assert libc.dlsym("malloc") is not None
    assert libc.dlsym("__lief_does_not_exist__") is None

    libc_mod = lief.runtime.linux.Module.from_handle(libc.handle)
    assert libc_mod is not None
    assert libc_mod.imagebase == libc.imagebase

    library = resolve_runtime_library("runtime-base-addr")
    module = lief.runtime.linux.dlopen(library)
    assert module is not None
    mod_from_hdl = lief.runtime.linux.Module.from_handle(module.handle)
    assert mod_from_hdl is not None
    assert mod_from_hdl.imagebase == module.imagebase


@pytest.mark.runtime
def test_parse_from_path():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    binary = libc.parse_from_path()
    assert isinstance(binary, lief.ELF.Binary)
    assert binary.entrypoint > 0

    binary = libc.parse_from_path(lief.ELF.ParserConfig.all)
    assert isinstance(binary, lief.ELF.Binary)


def test_parse_from_memory():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    libc.parse_from_memory()
    libc.parse_from_memory(lief.ELF.ParserConfig.all)


@pytest.mark.runtime
def test_dump(tmp_path):
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    data = libc.dump()
    assert isinstance(data, bytes)
    assert len(data) == libc.size
    assert data[:4] == b"\x7fELF"

    out = tmp_path / "libc.dump"
    written = libc.dump(str(out))
    assert isinstance(written, bytes)
    assert len(written) == libc.size
    assert written[:4] == b"\x7fELF"
    assert out.read_bytes() == written

    elf = lief.ELF.parse_from_dump(written, libc.imagebase)
    assert isinstance(elf, lief.ELF.Binary)
