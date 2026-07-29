from __future__ import annotations

from app.services.scanners.ethical import EthicalToolkitScannerProvider
from app.services.scanners.free_preview import FreePreviewScannerProvider
from app.services.scanners.greenbone import GreenboneScannerProvider
from app.services.scanners.mock import MockScannerProvider
from app.services.scanners.nuclei import NucleiScannerProvider
from app.services.scanners.worker import WorkerScannerProvider


def greenbone_is_available() -> bool:
    try:
        import gvm  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_backend_name(settings, asset_type: str, assessment_mode: str = "vulnerability_assessment") -> str:
    backend = settings.scanner_backend
    if backend in {"worker", "scanner_worker"}:
        return "worker"

    if backend in {"kryptnet_toolkit", "ethical_toolkit", "full_toolkit"}:
        return "ethical_toolkit"

    if assessment_mode == "ethical_pentesting":
        return "ethical_toolkit"

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
    if selected_backend in {"worker", "scanner_worker"}:
        return WorkerScannerProvider(settings)
    if selected_backend == "greenbone":
        return GreenboneScannerProvider(settings)
    if selected_backend == "free_preview":
        return FreePreviewScannerProvider()
    if selected_backend in {"ethical_toolkit", "kryptnet_toolkit", "full_toolkit"}:
        return EthicalToolkitScannerProvider(settings)
    if selected_backend == "nuclei":
        return NucleiScannerProvider(settings)
    return MockScannerProvider()
