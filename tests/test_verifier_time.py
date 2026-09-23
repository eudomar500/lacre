"""unix_time from the Verifier template against the standard library.

The contract cannot import datetime, so it converts the runner datetime by
hand, and an off-by-one day there would expire signatures early or late
without any other test noticing.
"""

import ast
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "contracts" / "verifier" / "verifier_template.py"


def load_unix_time():
    source = TEMPLATE.read_text(encoding="ascii")
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name == "unix_time":
            namespace = {}
            exec(compile(ast.Module([node], []), str(TEMPLATE), "exec"), namespace)
            return namespace["unix_time"]
    raise AssertionError("unix_time is not in the template")


def test_unix_time_matches_the_standard_library():
    unix_time = load_unix_time()
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


def test_unix_time_zone_spellings():
    unix_time = load_unix_time()
    expected = int(datetime(2026, 9, 22, 16, 35, 41, tzinfo=timezone.utc).timestamp())
    for text in ("2026-09-22T16:35:41Z", "2026-09-22T16:35:41",
                 "2026-09-22T16:35:41+00:00", "2026-09-22T18:35:41+0200",
                 "2026-09-22T11:35:41.5-05:00"):
        assert unix_time(text) == expected, text
