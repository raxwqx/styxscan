#!/usr/bin/env python3
"""Backwards-compatible entry point for StyxScan.

The supported interfaces are ``python -m styxscan`` and the ``styxscan``
console script. This file is kept so existing ``python styxscan.py`` commands
continue to work.
"""

from styxscan.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
