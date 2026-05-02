import time
import logging
import requests

logger = logging.getLogger(__name__)

_PRIVATE_RANGES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "::1",
)

_cache: dict[str, dict] = {}
_CACHE_TTL = 3600


def _is_private(ip: str) -> bool:
    return any(ip.startswith(r) for r in _PRIVATE_RANGES)

def lookup(ip: str) -> dict:
    if _is_private(ip):
        return {"country": "Private", "city": None, "latitude": None,
                "longitude": None, "asn": None, "isp": None}

    now = time.time()
    cached = _cache.get(ip)
    if cached and now - cached["_ts"] < _CACHE_TTL:
        return {k: v for k, v in cached.items() if k != "_ts"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,as,isp"},
            timeout=4,
        )
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "country":   data.get("country"),
                "city":      data.get("city"),
                "latitude":  data.get("lat"),
                "longitude": data.get("lon"),
                "asn":       data.get("as"),
                "isp":       data.get("isp"),
                "_ts":       now,
            }
        else:
            result = {"country": None, "city": None, "latitude": None,
                      "longitude": None, "asn": None, "isp": None, "_ts": now}
    except Exception as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        result = {"country": None, "city": None, "latitude": None,
                  "longitude": None, "asn": None, "isp": None, "_ts": now}

    _cache[ip] = result
    return {k: v for k, v in result.items() if k != "_ts"}
