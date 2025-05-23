import pyshark
import requests
import ipaddress

# Interface name (change based on your adapter)
INTERFACE = "Ethernet"  # or "Wi-Fi", "eth0", etc.

# Known Fortnite UDP port range
FORTNITE_PORT_RANGE = range(12000, 65000)

def is_local_ip(ip):
    """Check if an IP address is a local/private address."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a private address (RFC 1918)
        if ip_obj.is_private:
            return True
        
        # Check if it's a loopback address
        if ip_obj.is_loopback:
            return True
            
        # Check if it's a link-local address
        if ip_obj.is_link_local:
            return True
            
        return False
    except ValueError:
        # If IP parsing fails, assume it's not local
        return False

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return f"{data.get('country')} - {data.get('region')} ({data.get('city')})"
    except:
        return "Unknown"

def capture_fortnite_traffic():
    print("[*] Sniffing outgoing Fortnite packets...")
    capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="udp")

    for packet in capture.sniff_continuously():
        try:
            src_port = int(packet.udp.srcport)
            dst_ip = packet.ip.dst
            
            # Skip local/private IP addresses
            if is_local_ip(dst_ip):
                continue
            
            # If source port is in the Fortnite range, it's an outgoing packet
            if src_port in FORTNITE_PORT_RANGE:
                print(f"[+] Detected outgoing Fortnite traffic to {dst_ip}")
                region = get_ip_info(dst_ip)
                print(f"    ⮑ Server Region Info: {region}")
                break
        except Exception as e:
            continue

capture_fortnite_traffic()