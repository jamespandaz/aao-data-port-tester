#!/usr/bin/env python3
import os
import sys
import subprocess
import venv
import argparse
import netifaces
import json
import ipaddress
from functools import partial

VENV_DIR = ".venv"
REQUIREMENTS = "requirements.txt"

def print_banner():
    banner = r"""
     _____ _   _ _____ _   __ _   __  ___
    |  _  | | | |  _  | | / /| | / / / _ \
    | | | | | | | | | | |/ / | |/ / / /_\ \
    | | | | | | | | | |    \ |    \ |  _  |
    \ \/' / |_| \ \_/ / |\  \| |\  \| | | |
     \_/\_\\___/ \___/\_| \_/\_| \_/\_| |_/

         QUOKKA v0.5
Quick Observation Of LAN K(K)nowledge Acquisition
"""
    print(banner)

def ensure_venv():
    """Ensure virtual environment exists and requirements are installed."""
    if not os.path.exists(VENV_DIR):
        print("[+] Creating virtual environment...")
        venv.create(VENV_DIR, with_pip=True)

    pip_path = os.path.join(VENV_DIR, "bin", "pip")
    python_path = os.path.join(VENV_DIR, "bin", "python")

    print("[+] Installing dependencies...")
    subprocess.check_call([pip_path, "install", "-r", REQUIREMENTS])

    if os.path.realpath(sys.executable) != os.path.realpath(python_path):
        print("[+] Re-executing inside venv...")
        os.execv(python_path, [python_path] + sys.argv)

    print("Done installing dependencies.")
    print_banner()

def get_ip_info(iface):
    """Return IP info as (IP, netmask, CIDR)"""
    try:
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs.get(netifaces.AF_INET, [{}])[0]
        ip = ip_info.get('addr', 'N/A')
        netmask = ip_info.get('netmask', 'N/A')
        if ip != 'N/A' and netmask != 'N/A':
            cidr = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False).prefixlen
        else:
            cidr = "N/A"
        return ip, netmask, cidr
    except Exception:
        return "N/A", "N/A", "N/A"

def load_vlan_map(path):
    """Load VLAN mapping from JSON file"""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Could not load VLAN map: {e}")
        return {}

def estimate_vlan(ip, vlan_map):
    """Return VLAN based on subnet map using proper CIDR matching"""
    try:
        ip_addr = ipaddress.IPv4Address(ip)
        for subnet_cidr, vlan_id in vlan_map.items():
            network = ipaddress.IPv4Network(subnet_cidr, strict=False)
            if ip_addr in network:
                return vlan_id
        return "Unknown"
    except Exception:
        return "Unknown"

def run_netool(iface, vlan_map):
    from scapy.all import sniff, Ether, Raw

    def parse_lldp(raw):
        """Parse LLDP info for the switch information"""
        tlvs = {}
        i = 0
        while i < len(raw):
            if i + 2 > len(raw):
                break
            tlv_header = int.from_bytes(raw[i:i+2], "big")
            tlv_type = (tlv_header >> 9) & 0x7F
            tlv_len = tlv_header & 0x1FF
            tlv_val = raw[i+2:i+2+tlv_len]

            if tlv_type == 1:
                tlvs["chassis_id"] = tlv_val.hex()
            elif tlv_type == 2:
                tlvs["port_id"] = tlv_val[1:].decode(errors="ignore")
            elif tlv_type == 5:
                tlvs["system_name"] = tlv_val.decode(errors="ignore")
            elif tlv_type == 6:
                tlvs["system_desc"] = tlv_val.decode(errors="ignore")
            elif tlv_type == 8:
                if len(tlv_val) > 1:
                    tlvs["mgmt_ip"] = ".".join(str(b) for b in tlv_val[1:5])
            elif tlv_type == 127:
                if tlv_val[:3] == b"\x00\x12\x0f":
                    subtype = tlv_val[3]
                    if subtype == 3:
                        vlan_id = int.from_bytes(tlv_val[4:6], "big")
                        tlvs["pvid"] = vlan_id
            i += 2 + tlv_len
        return tlvs

    def handle_pkt(pkt, iface, vlan_map):
        """Handle LLDP packet and print single-line summary"""
        if pkt.haslayer(Raw) and pkt.haslayer(Ether):
            if pkt[Ether].type == 0x88cc:
                info = parse_lldp(pkt[Raw].load)
                ip, netmask, cidr = get_ip_info(iface)
                vlan_display = info.get('pvid') if info.get('pvid') else estimate_vlan(ip, vlan_map)
                # Multi-line LLDP info
                print("\n=== LLDP Info ===")
                print(f" Switch Hostname : {info.get('system_name','?')}")
                print(f" Switch Port     : {info.get('port_id','?')}")
                print(f" Mgmt IP         : {info.get('mgmt_ip','?')}")
                print(f" VLAN (PVID)     : {info.get('pvid','?')}")
                print(f" Description     : {info.get('system_desc','?')}\n")
                # Single-line summary
                print(f"[QUOKKA] Interface: {iface} | Switch: {info.get('system_name','?')} | "
                      f"Port: {info.get('port_id','?')} | VLAN: {vlan_display} | IP: {ip}/{cidr} | Netmask: {netmask}\n")

    def get_dhcp_info(iface):
        """Gets DHCP info"""
        try:
            subprocess.run(["dhclient", "-r", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out = subprocess.check_output(["dhclient", "-v", iface], stderr=subprocess.STDOUT)
            return out.decode(errors="ignore")
        except Exception as e:
            return f"DHCP error: {e}"

    print(f"Starting Data Port listener on {iface}...")
    print("Press Ctrl+C to stop.\n")

    # Get DHCP info
    print("=== DHCP Info ===")
    print(get_dhcp_info(iface))

    # Print initial summary even if no LLDP frames are seen
    ip, netmask, cidr = get_ip_info(iface)
    vlan_estimate = estimate_vlan(ip, vlan_map)
    print(f"[QUOKKA] Interface: {iface} | Switch: ? | Port: ? | VLAN: {vlan_estimate} | IP: {ip}/{cidr} | Netmask: {netmask}\n")

    sniff(filter="ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc",
          prn=partial(handle_pkt, iface=iface, vlan_map=vlan_map),
          store=0, iface=iface)

if __name__ == "__main__":
    ensure_venv()

    parser = argparse.ArgumentParser(description="QUOKKA - Data Port LLDP/CDP and DHCP tester")
    parser.add_argument("iface", help="Interface to use (e.g., eth0, eno1, ens33, etc.)")
    parser.add_argument("--vlan-map", help="Path to JSON file with subnet-to-VLAN mapping")
    args = parser.parse_args()

    vlan_map = load_vlan_map(args.vlan_map) if args.vlan_map else {}

    run_netool(args.iface, vlan_map)
