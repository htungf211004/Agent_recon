"""A bounded launch probe: an installed Python package alone is not a runtime."""

import subprocess
import sys
from pathlib import Path


def chromium_available() -> bool:
    """Probe in a separate process, also safe when the caller has an asyncio loop."""
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--probe"],
            capture_output=True, timeout=15, check=False, shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def probe() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True, timeout=5000)
            try:
                context = browser.new_context(service_workers="block", accept_downloads=False)
                try:
                    return callable(getattr(context, "route_web_socket", None))
                finally:
                    context.close()
            finally:
                browser.close()
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(0 if probe() else 1)
