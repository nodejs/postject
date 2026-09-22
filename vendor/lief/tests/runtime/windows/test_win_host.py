import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.WINDOWS:
    pytest.skip("skipping: windows only", allow_module_level=True)


@pytest.mark.runtime
def test_version_t():
    version_t = lief.runtime.windows.Host.version_t

    default = version_t()
    assert default.major == 0
    assert default.minor == 0
    assert default.build_number == 0
    assert str(default) == "0.0.0"

    v = version_t(10, 0, 26200)
    assert v.major == 10
    assert v.minor == 0
    assert v.build_number == 26200
    assert str(v) == "10.0.26200"

    assert v == version_t(10, 0, 26200)
    assert v != default
    assert v > default
    assert v >= default
    assert default < v
    assert default <= v

    win10_rtm = version_t(10, 0, 10240)
    win11_24h2 = version_t(10, 0, 26100)
    assert win10_rtm < win11_24h2
    assert win11_24h2 > win10_rtm
    assert win10_rtm <= win11_24h2
    assert win11_24h2 >= win10_rtm


@pytest.mark.runtime
def test_host_version():
    version = lief.runtime.windows.Host.version
    assert isinstance(version, lief.runtime.windows.Host.version_t)
    # Any supported Windows host should be at least Windows 7 (6.1.x)
    assert version >= lief.runtime.windows.Host.version_t(6, 1, 0)
