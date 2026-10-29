"""Allow ``python -m passcheck``."""

import sys

from .cli import main

sys.exit(main())
