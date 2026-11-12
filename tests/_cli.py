"""Run the CLI from the source tree (tests call this with python -I, which ignores PYTHONPATH)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from mintmap.cli import entry  # noqa: E402

sys.exit(entry())
