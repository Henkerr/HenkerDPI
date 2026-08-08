"""CI entry point: run the macOS selftest against the source tree.

The same checks run again against the built .app in the next CI step, which is
the run that catches a missing PyInstaller hiddenimport.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from macos.selftest import run  # noqa: E402

sys.exit(run())
