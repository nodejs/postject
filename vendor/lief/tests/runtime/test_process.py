import os

import lief
import pytest

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)


@pytest.mark.runtime
def test_simple():
    assert lief.runtime.Process.pid == os.getpid()
    assert lief.runtime.Process.page_size in (0x1000, 0x4000)
    assert lief.runtime.Process.tid > 0
    assert lief.runtime.Process.arch != lief.runtime.ARCH.NONE
    assert lief.runtime.Process.platform != lief.runtime.PLATFORMS.NONE

    os.environ["HELLO"] = "WORLD"
    assert lief.runtime.Process.get_env("HELLO") == "WORLD"
    assert lief.runtime.Process.get_env("__NONE__") is None

    env_vars = dict(lief.runtime.Process.envs.vars)
    assert "HELLO" in env_vars
