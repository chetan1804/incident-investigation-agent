#!/usr/bin/env python3
"""Verify the base project setup is working."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from incident_investigation_agent.config.settings import settings


def main() -> None:
    """Print a compact status summary for the project baseline."""
    print("Incident Investigation Agent")
    print(f"app_name={settings.app_name}")
    print(f"environment={settings.environment}")
    print(f"log_level={settings.log_level}")
    print(f"api_port={settings.api_port}")
    print("setup_verification=ok")


if __name__ == "__main__":
    main()
