import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.OSX:
    pytest.skip("skipping: osx only", allow_module_level=True)


@pytest.mark.runtime
def test_process():
    assert int(lief.runtime.osx.Process.dyld_version) >= 1335
