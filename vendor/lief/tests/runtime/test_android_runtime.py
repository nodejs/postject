import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

IS_ANDROID = lief.runtime.platform == lief.runtime.PLATFORMS.ANDROID


@pytest.mark.runtime
def test_host():
    Host = lief.runtime.android.Host
    sdk = Host.sdk_version
    assert sdk is None or isinstance(sdk, int)
    if IS_ANDROID:
        assert sdk is not None and sdk > 0


@pytest.mark.runtime
def test_process():
    Process = lief.runtime.android.Process
    Property = lief.runtime.android.Property
    assert issubclass(Process, lief.runtime.Process)

    prop = Process.get_system_property("ro.build.version.sdk")
    assert prop is None or isinstance(prop, Property)

    cmdline = Process.cmdline
    assert isinstance(cmdline, str)

    props = Process.properties
    assert isinstance(props, list)
    for value in props:
        assert isinstance(value, Property)
        assert isinstance(value.name, str)

    if IS_ANDROID:
        assert prop is not None
        assert prop.name == "ro.build.version.sdk"
        assert isinstance(prop.value, str)
        assert isinstance(prop.serial, int)
        assert str(prop)
        assert Process.get_system_property("lief.does.not.exist") is None

        assert len(props) > 0
        assert any(p.name == "ro.build.version.sdk" for p in props)
        print(cmdline)
