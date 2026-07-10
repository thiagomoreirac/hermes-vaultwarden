"""Test bootstrap: make the hermes-agent checkout and this plugin importable.

The plugin has no packaging of its own — at runtime the Hermes plugin
loader imports it in-process, so tests replicate that by putting the
hermes-agent source tree (``HERMES_AGENT_SRC``, default
``~/Code/hermes-agent``) and the plugin root on ``sys.path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERMES_SRC = Path(
    os.environ.get("HERMES_AGENT_SRC", Path.home() / "Code" / "hermes-agent")
).resolve()

if not (HERMES_SRC / "agent" / "secret_sources" / "base.py").exists():
    raise RuntimeError(
        f"hermes-agent checkout not found at {HERMES_SRC} (or too old — "
        "agent/secret_sources/base.py missing).  Set HERMES_AGENT_SRC."
    )

sys.path.insert(0, str(HERMES_SRC))
sys.path.insert(0, str(Path(__file__).parent))
