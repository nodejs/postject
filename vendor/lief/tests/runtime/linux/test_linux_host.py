import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.LINUX:
    pytest.skip("skipping: linux only", allow_module_level=True)


@pytest.mark.runtime
def test_host():
    Host = lief.runtime.linux.Host
    assert Host.sys_name == "Linux"
    assert Host.sys_release != ""
    assert Host.sys_version != ""
    assert Host.hardware != ""
