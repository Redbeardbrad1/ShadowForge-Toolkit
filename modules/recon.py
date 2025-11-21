import subprocess
import json
import xml.etree.ElementTree as ET

# Raw ANSI colors – no utils dependency, pure ranch steel
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def print_green(text):
    print(f"{GREEN}{text}{RESET}")

def print_yellow(text):
    print(f"{YELLOW}{text}{RESET}")

def run_nmap(target, intensity="-sT -sV --top-ports 1000 -Pn -T4 --reason --verbose"):
    print_green(f"[+] Firing live Nmap recon on {target}...")
    cmd = ["nmap", "-oX", "-", intensity, target]
    print_yellow(f"[DEBUG] Running: {' '.join(cmd)}")  # <-- exact command dump
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0 or "Scantype not supported" in result.stderr:
        print("[-] Nmap FAILED HARD – raw error dump:")
        print(result.stderr.strip() or "No stderr – possible Npcap not loaded or not Admin")
        print("\n[+] Raw stdout preview:")
        print(result.stdout[:1000] if result.stdout else "No output")
        return None
    
    try:
        root = ET.fromstring(result.stdout)
    except Exception as e:
        print(f"[-] XML parse failed: {e}")
        print(result.stdout[:1000])
        return None
    
    # ... keep ALL your existing parsing code below unchanged ...
    host = root.find(".//host") or root.find("host")
    if host is None:
        return {"host": target, "status": "down"}
    
    ports = []
    services = {}
    
    for port in host.findall(".//port"):
        state_elem = port.find("state")
        if state_elem is not None and state_elem.get("state") == "open":
            portid = port.get("portid")
            ports.append(int(portid))
            service = port.find("service")
            if service is not None:
                name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
                services[portid] = f"{name} {product} {version}".strip()
    
    scan_data = {
        "host": target,
        "status": "up",
        "ports": ports,
        "services": services,
        "os": "OS detection skipped on Windows – scapy Week 3"
    }
    print_green("[+] Recon complete – live versions forged.")
    return scan_data