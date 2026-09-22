import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.WINDOWS:
    pytest.skip("skipping: windows only", allow_module_level=True)


@pytest.mark.runtime
def test_peb():
    peb = lief.runtime.windows.Process.peb
    assert peb is not None
    assert isinstance(peb, lief.runtime.windows.PEB)

    assert peb.ldr != 0
    assert peb.process_parameters != 0

    assert isinstance(peb.being_debugged, bool)

    assert isinstance(peb.atl_thunk_slist_ptr, int)
    assert isinstance(peb.atl_thunk_slist_ptr32, int)
    assert isinstance(peb.post_process_init_routine, int)
    assert isinstance(peb.session_id, int)


@pytest.mark.runtime
def test_peb_entries():
    peb = lief.runtime.windows.Process.peb
    assert peb is not None

    entries = list(peb.entries)
    assert len(entries) > 1
    assert all(isinstance(e, lief.runtime.windows.LdrDataTableEntry) for e in entries)

    first = entries[0]
    assert first is not None
    assert first.dll_base != 0
    assert first.size_of_image > 0
    assert first.base_dll_name != ""
    assert first.full_dll_name.lower().endswith(first.base_dll_name.lower())
    assert isinstance(first.entry_point, int)

    names = [e.base_dll_name.lower() for e in entries if e is not None]
    assert "ntdll.dll" in names


@pytest.mark.runtime
def test_peb_entry_extended_fields():
    peb = lief.runtime.windows.Process.peb
    assert peb is not None

    first = next(iter(peb.entries), None)
    assert first is not None

    assert isinstance(first.flags, int)
    assert isinstance(first.obsolete_load_count, int)
    assert isinstance(first.tls_index, int)
    assert isinstance(first.time_date_stamp, int)
    assert isinstance(first.entry_point_activation_context, int)
    assert isinstance(first.lock, int)

    version_t = lief.runtime.windows.Host.version_t
    version = lief.runtime.windows.Host.version

    win8_fields = (
        first.ddag_node,
        first.load_context,
        first.parent_dll_base,
        first.switch_back_context,
        first.original_base,
        first.load_time,
        first.base_name_hash_value,
        first.load_reason,
        first.implicit_path_options,
        first.reference_count,
        first.dependent_load_flags,
    )
    if version >= version_t(6, 2, 9200):
        assert all(v is not None for v in win8_fields)
        assert all(isinstance(v, int) for v in win8_fields)
    else:
        assert all(v is None for v in win8_fields)

    win10_fields = (first.signing_level, first.check_sum)
    if version >= version_t(10, 0, 10240):
        assert all(v is not None for v in win10_fields)
        assert all(isinstance(v, int) for v in win10_fields)
    else:
        assert all(v is None for v in win10_fields)

    win11_fields = (first.active_patch_image_base, first.hot_patch_state)
    if version >= version_t(10, 0, 22000):
        assert all(v is not None for v in win11_fields)
        assert all(isinstance(v, int) for v in win11_fields)
    else:
        assert all(v is None for v in win11_fields)
