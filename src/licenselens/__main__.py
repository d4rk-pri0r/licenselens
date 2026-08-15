"""Module entry point shared by ``python -m licenselens`` and the frozen exe.

PyInstaller launches this file as ``__main__`` so both invocation paths route
through the same ``licenselens.cli.main`` entrypoint.
"""

from __future__ import annotations

from licenselens.cli import main

if __name__ == "__main__":
    main()
