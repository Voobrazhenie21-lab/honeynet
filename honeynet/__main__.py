"""HoneyNet package executable entry point.

Allows executing the daemon via `python -m honeynet`.
"""
from __future__ import annotations

from honeynet.cli import main

if __name__ == "__main__":
    main()
