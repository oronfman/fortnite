import pyshark, requests, ipaddress, psutil, time, signal

RUNNING = True
CURRENT_CAPTURE = None

FORTNITE_PORT_RANGE = range(12000,65000)
PROCESS_NAME = "FortniteClient-Win64-Shipping.exe"
INTERFACE = "Ethernet"

_IPINFO_CACHE = {}

def is_local_ip(ip):
    try:
        o=ipaddress.ip_address(ip); return o.is_private or o.is_loopback or o.is_link_local
    except:
        return False

def get_ip_info(ip):
    """Cached IP -> region lookup."""
    v = _IPINFO_CACHE.get(ip)
    if v is not None:
        return v
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        d = r.json()
        val = f"{d.get('country')} - {d.get('region')} ({d.get('city')})"
    except Exception:
        val = "Unknown"
    _IPINFO_CACHE[ip] = val
    return val

def get_ports_for_process(name):
    p=set(); n=name.lower()
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info.get('name','').lower()!=n: continue
            for c in proc.net_connections(kind='inet'):
                if c.laddr and getattr(c.laddr,'port',None): p.add(c.laddr.port)
                if c.raddr and getattr(c.raddr,'port',None): p.add(c.raddr.port)
        except:
            continue
    return p

def build_bpf(ports):
    return None if not ports else "udp and ("+" or ".join(f"port {p}" for p in sorted(ports))+")"

def _signal_stop(signum, frame):
    global RUNNING, CURRENT_CAPTURE
    RUNNING = False
    if CURRENT_CAPTURE:
        try:
            CURRENT_CAPTURE.close()
        except:
            pass

signal.signal(signal.SIGINT, _signal_stop)

def capture_process_traffic(name):
    iface = INTERFACE
    print(f"Sniffing UDP for: {name} on {iface}")
    while RUNNING:
        ports=get_ports_for_process(name)
        if not ports: time.sleep(2); continue
        b=build_bpf(ports)
        if not b: time.sleep(2); continue
        try:
            cap=pyshark.LiveCapture(interface=iface,bpf_filter=b)
            global CURRENT_CAPTURE
            CURRENT_CAPTURE = cap
            for pkt in cap.sniff_continuously():
                if not RUNNING:
                    break
                try:
                    if not hasattr(pkt,'udp'): continue
                    sp=int(pkt.udp.srcport); dst=pkt.ip.dst
                    if is_local_ip(dst): continue
                    print(f"UDP {sp} -> {dst} ; {get_ip_info(dst)}")
                except: pass
            try:
                cap.close()
            except:
                pass
            CURRENT_CAPTURE = None
        except Exception as e:
            print("cap err",iface,e); time.sleep(2)
    print("Exiting")

if __name__=='__main__':
    capture_process_traffic(PROCESS_NAME)