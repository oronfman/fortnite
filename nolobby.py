import ctypes
import ipaddress, signal, os, time, sys
from datetime import datetime, timedelta
import geoip2.database
from pydivert import WinDivert
from urllib.request import urlretrieve

RUNNING = True
CURRENT_DIVERT = None

_BLOCK_COUNTRIES = {"GB"}  # ISO country codes to block
_IP_COUNTRY_CACHE = {}
GEOIP_DB_FILE = 'GeoLite2-Country.mmdb'


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
    
def is_local_ip(ip):
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local
    except Exception:
        return False


def is_db_outdated():
    """Check if GeoIP database is older than a month."""
    if not os.path.exists(GEOIP_DB_FILE):
        return True
    
    file_modified_time = os.path.getmtime(GEOIP_DB_FILE)
    file_age = datetime.now() - datetime.fromtimestamp(file_modified_time)
    
    # Check if older than 30 days
    if file_age > timedelta(days=30):
        print(f"⚠ GeoIP database is {file_age.days} days old (last updated: {datetime.fromtimestamp(file_modified_time).strftime('%Y-%m-%d')})")
        return True
    
    return False


def download_geoip_db():
    """Download GeoLite2 Country database if not present or outdated."""
    if os.path.exists(GEOIP_DB_FILE) and not is_db_outdated():
        file_modified_time = os.path.getmtime(GEOIP_DB_FILE)
        print(f"✓ GeoIP database found: {GEOIP_DB_FILE} (age: {(datetime.now() - datetime.fromtimestamp(file_modified_time)).days} days)")
        return True
    
    if os.path.exists(GEOIP_DB_FILE):
        print("⬇ Updating GeoLite2-Country database...")
    else:
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
    """Intercept UDP both directions and drop traffic to/from blocked countries."""
    global CURRENT_DIVERT
    print(r"""
         _     _   _       
 ___ ___| |___| |_| |_ _ _ 
|   | . | | . | . | . | | |
|_|_|___|_|___|___|___|_  |
                      |___|
    """)
    print(f"  🚫 Blocking: {', '.join(_BLOCK_COUNTRIES)}")
    print(f"  📡 Corrupting inbound UDP from blocked countries\n")

    try:
        with WinDivert("inbound and udp and udp.SrcPort >= 15000 and udp.SrcPort <= 15999") as w:
            CURRENT_DIVERT = w
            try:
                for pkt in w:
                    if not RUNNING:
                        print("\n👋 Shutting down...")
                        break
                    if pkt is None:
                        continue
                    try:
                        src = getattr(pkt, 'src_addr', None)
                        src_port = getattr(pkt, 'src_port', None)

                        # Always allow DNS responses (port 53)
                        if src_port == 53:
                            w.send(pkt)
                            continue

                        if src and not is_local_ip(src):
                            country = get_ip_country(src)
                            if country and country.upper() in _BLOCK_COUNTRIES:
                                # Scramble the UDP payload with random bytes
                                if pkt.payload and len(pkt.payload) > 0:
                                    pkt.payload = os.urandom(len(pkt.payload))
                                print(f"💥 CORRUPT  {src}:{src_port} [{country}]")
                            else:
                                print(f"✓ Allowed  {src}:{src_port} [{country}]")

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
    if not is_admin():
        # Re-launch the script with UAC elevation prompt
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    block_countries_for_process()