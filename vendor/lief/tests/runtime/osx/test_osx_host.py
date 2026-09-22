import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.OSX:
    pytest.skip("skipping: osx only", allow_module_level=True)


@pytest.mark.runtime
def test_host():
    assert lief.runtime.osx.Host.os_version_name != ""
    assert lief.runtime.osx.Host.os_version >= lief.runtime.osx.Host.version_t.big_sur()
