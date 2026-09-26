"""unix_time from the contract templates against the standard library.

The contract cannot import datetime, so it converts the runner datetime by
hand, and an off-by-one day there would expire signatures early or late
without any other test noticing. The Router and the KeyCache carry the same
function for their delays, so every copy is checked, and the copies are held
to one another.
"""

import ast
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
TEMPLATES = [
    CONTRACTS / "verifier" / "verifier_template.py",
    CONTRACTS / "router" / "router_template.py",
    CONTRACTS / "keycache" / "keycache_template.py",
]


def unix_time_node(template):
    for node in ast.parse(template.read_text(encoding="ascii")).body:
        if isinstance(node, ast.FunctionDef) and node.name == "unix_time":
            return node
    raise AssertionError("unix_time is not in %s" % (template.name,))


def load_unix_time(template):
    namespace = {}
    module = ast.Module([unix_time_node(template)], [])
    exec(compile(module, str(template), "exec"), namespace)
    return namespace["unix_time"]


def test_every_copy_is_the_same_code():
    # Compared without comments, which may differ from one template to the
    # next; the statements may not.
    dumps = {ast.dump(unix_time_node(t)) for t in TEMPLATES}
    assert len(dumps) == 1


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda t: t.parent.name)
def test_unix_time_matches_the_standard_library(template):
    unix_time = load_unix_time(template)
    rng = random.Random(6376)
    offsets = [0, 3600, -18000, 19800, -34200, 50400]
    for _ in range(5000):
        seconds = rng.randint(0, 4102444800)
        zone = timezone(timedelta(seconds=rng.choice(offsets)))
        moment = datetime.fromtimestamp(seconds, zone).replace(
            microsecond=rng.randint(0, 999999))
        for text in (moment.isoformat(), str(moment),
                     moment.isoformat(timespec="seconds")):
            assert unix_time(text) == seconds, text


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda t: t.parent.name)
def test_unix_time_zone_spellings(template):
    unix_time = load_unix_time(template)
    expected = int(datetime(2026, 9, 22, 16, 35, 41, tzinfo=timezone.utc).timestamp())
    for text in ("2026-09-22T16:35:41Z", "2026-09-22T16:35:41",
                 "2026-09-22T16:35:41+00:00", "2026-09-22T18:35:41+0200",
                 "2026-09-22T11:35:41.5-05:00"):
        assert unix_time(text) == expected, text
