import lief
import pytest
from lief.runtime import Host

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)


@pytest.mark.runtime
def test_basic():
    assert Host.name
    assert Host.cache_dir != ""
    assert Host.tmp_dir != ""
    assert Host.config_dir != ""
    assert Host.home_dir != ""
