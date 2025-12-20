import ipaddress, signal, os, tarfile
import geoip2.database
from pydivert import WinDivert
from urllib.request import urlretrieve

RUNNING = True
CURRENT_DIVERT = None

_BLOCK_COUNTRIES = {"GB", "DE"}  # ISO country codes to block
_IP_COUNTRY_CACHE = {}
GEOIP_DB_FILE = 'GeoLite2-Country.mmdb'
MIN_DST_PORT = 10000  # Only monitor destination ports above this value


def is_local_ip(ip):
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local
    except Exception:
        return False


def download_geoip_db():
    """Download GeoLite2 Country database if not present."""
    if os.path.exists(GEOIP_DB_FILE):
        print(f"✓ GeoIP database found: {GEOIP_DB_FILE}")
        return True
    
    print("⬇ Downloading GeoLite2-Country database...")
    # Using a mirror that doesn't require license key
    url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
    
    try:
        urlretrieve(url, GEOIP_DB_FILE)
        print(f"✓ Successfully downloaded {GEOIP_DB_FILE}")
        return True
    except Exception as e:
        print(f"✗ Failed to download GeoIP database: {e}")
        print("  Please download manually from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return False


# Download and initialize GeoIP2 reader
download_geoip_db()

try:
    _GEOIP_READER = geoip2.database.Reader(GEOIP_DB_FILE)
    print(f"✓ GeoIP database loaded successfully\n")
except Exception as e:
    print(f"⚠ Warning: Could not load GeoIP database: {e}\n")
    _GEOIP_READER = None


def get_ip_country(ip):
    """Return ISO country code for IP (cached)."""
    v = _IP_COUNTRY_CACHE.get(ip)
    if v is not None:
        return v
    country = None
    if _GEOIP_READER:
        try:
            response = _GEOIP_READER.country(ip)
            country = response.country.iso_code
        except Exception:
            pass
    _IP_COUNTRY_CACHE[ip] = country
    return country


def _signal_stop(signum, frame):
    global RUNNING, CURRENT_DIVERT
    RUNNING = False
    # Close the divert handle if open; closing the handle will unblock the iterator
    if CURRENT_DIVERT:
        try:
            CURRENT_DIVERT.close()
        except Exception:
            pass


signal.signal(signal.SIGINT, _signal_stop)


def block_countries_for_process():
    """Intercept outbound IP packets and drop those whose destination country is blocked for destination ports > MIN_DST_PORT."""
    global CURRENT_DIVERT
    print("🌍 Starting GeoBlock...")
    print(f"📡 Monitoring outbound traffic on destination ports > {MIN_DST_PORT}")
    print(f"🚫 Blocking countries: {', '.join(_BLOCK_COUNTRIES)}\n")

    try:
        with WinDivert("outbound and ip") as w:
            CURRENT_DIVERT = w
            try:
                for pkt in w:
                    if not RUNNING:
                        print("\n👋 Shutting down...")
                        break
                    if pkt is None:
                        continue
                    try:
                        dst = getattr(pkt, 'dst_addr', None)

                        if is_local_ip(dst):
                            w.send(pkt)
                            continue

                        src_port = getattr(pkt, 'src_port', None)
                        dst_port = getattr(pkt, 'dst_port', None)

                        # Check if destination port is greater than MIN_DST_PORT
                        if dst_port is None or dst_port <= MIN_DST_PORT:
                            w.send(pkt)
                            continue

                        country = get_ip_country(dst) or 'Unknown'
                        if country and country.upper() in _BLOCK_COUNTRIES:
                            print(f"🚫 BLOCKED  {dst}:{dst_port} [{country}]")
                            # Drop by not reinjecting
                            continue
                        # Otherwise reinject
                        print(f"✓ Allowed  {dst}:{dst_port} [{country}]")
                        w.send(pkt)
                    except Exception as e:
                        # During shutdown the handle may become invalid; if stopping, break
                        if not RUNNING:
                            break
                        print(f"⚠ Error handling packet: {e}")
                        try:
                            w.send(pkt)
                        except Exception:
                            pass
            except Exception as e:
                # recv/iterator error - suppress during shutdown
                if RUNNING:
                    print(f"⚠ WinDivert error: {e}")
    except Exception as e:
        if RUNNING:
            print(f"✗ WinDivert setup error: {e}")
    finally:
        CURRENT_DIVERT = None


if __name__ == '__main__':
    block_countries_for_process()