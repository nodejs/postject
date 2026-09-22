import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.LINUX:
    pytest.skip("skipping: linux only", allow_module_level=True)


@pytest.mark.runtime
def test_process():
    assert lief.runtime.linux.Process.glibc_version != ""

    cmdline = lief.runtime.linux.Process.cmdline
    assert isinstance(cmdline, str)
    assert cmdline != ""
