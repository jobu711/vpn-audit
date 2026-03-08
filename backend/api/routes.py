"""REST API routes for VPN audit operations."""

from dataclasses import asdict

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.core.external_ip import ExternalIPChecker
from backend.core.fingerprint import TrafficFingerprinter
from backend.core.killswitch import KillSwitchTester
from backend.core.leak_detect import LeakDetector
from backend.core.monitor import ConnectionMonitor

router = APIRouter(prefix="/api")

# In-memory storage for latest audit results, keyed by audit type.
_results: dict[str, dict] = {}

# Module-level singleton for external IP checks (preserves cache across requests).
_ip_checker = ExternalIPChecker()


@router.post("/audit/leaks")
async def audit_leaks():
    """Run DNS, WebRTC, and IPv6 leak detection."""
    try:
        detector = LeakDetector()
        result = detector.run()
        result_dict = asdict(result)
        _results["leaks"] = result_dict
        return result_dict
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/audit/fingerprint")
async def audit_fingerprint():
    """Run traffic fingerprinting analysis."""
    try:
        fingerprinter = TrafficFingerprinter()
        result = fingerprinter.run()
        result_dict = asdict(result)
        _results["fingerprint"] = result_dict
        return result_dict
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/audit/killswitch")
async def audit_killswitch():
    """Run kill switch effectiveness test."""
    try:
        tester = KillSwitchTester()
        result = tester.run()
        result_dict = asdict(result)
        _results["killswitch"] = result_dict
        return result_dict
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/audit/full")
async def audit_full():
    """Run all audit modules and return combined results."""
    try:
        leak_result = asdict(LeakDetector().run())
        fingerprint_result = asdict(TrafficFingerprinter().run())
        killswitch_result = asdict(KillSwitchTester().run())

        _results["leaks"] = leak_result
        _results["fingerprint"] = fingerprint_result
        _results["killswitch"] = killswitch_result

        combined = {
            "leaks": leak_result,
            "fingerprint": fingerprint_result,
            "killswitch": killswitch_result,
        }
        _results["full"] = combined
        return combined
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.get("/external-ip")
async def external_ip():
    """Return current external IP with geolocation and VPN masking status."""
    try:
        result = _ip_checker.lookup()
        _results["external_ip"] = result
        return result
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.get("/status")
async def status():
    """Return current connection status snapshot."""
    try:
        monitor = ConnectionMonitor()
        return monitor.snapshot()
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.get("/results")
async def results():
    """Return latest stored audit results."""
    return _results
