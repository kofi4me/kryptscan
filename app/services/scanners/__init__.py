from __future__ import annotations

from app.services.scanners.greenbone import GreenboneScannerProvider
from app.services.scanners.mock import MockScannerProvider
from app.services.scanners.nuclei import NucleiScannerProvider


def greenbone_is_available() -> bool:
    try:
        import gvm  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_backend_name(settings, asset_type: str) -> str:
    backend = settings.scanner_backend
    if backend in {"adaptive", "hybrid"}:
        if asset_type == "website":
            return "nuclei" if NucleiScannerProvider.is_available(settings) else "mock"
        if greenbone_is_available():
            return "greenbone"
        if NucleiScannerProvider.is_available(settings):
            return "nuclei"
        return "mock"
    return backend


def get_scanner_provider(settings, backend_name: str | None = None):
    selected_backend = (backend_name or settings.scanner_backend).lower()
    if selected_backend == "greenbone":
        return GreenboneScannerProvider(settings)
    if selected_backend == "nuclei":
        return NucleiScannerProvider(settings)
    return MockScannerProvider()
