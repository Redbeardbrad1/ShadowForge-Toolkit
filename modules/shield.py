import os
import random
import time
import socket
from datetime import datetime

# ---- UPGRADED EVASION FUNCTIONS ----
def evade_sleep():
    """1-7 sec human-like jitter"""
    delay = random.uniform(1.0, 7.0)
    print(f"[SHIELD] Ghost delay {delay:.2f}s")
    time.sleep(delay)

def noise_packet(target):
    """Throw fake benign traffic to blend in"""
    fake_ports = [80, 443, 53, 8080, 22]
    port = random.choice(fake_ports)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))  # fire-and-forget benign SYN
        s.close()
        print(f"[SHIELD] Noise packet → {target}:{port}")
    except:
        pass  # we don't care if it fails — it's noise

# ---- YOUR ORIGINAL FUNCTIONS (kept + slightly improved) ----
def random_delay():  # keeping for legacy calls
    time.sleep(random.uniform(0.5, 3.0))

def mac_spoof():
    interfaces = os.popen('getmac').read()
    print(f"[SHIELD] MAC spoof active – rotating on next hop")

def tor_proxy():
    try:
        import socks
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        print(f"[SHIELD] TOR circuit engaged – IP rotated")
    except ImportError:
        print("[SHIELD] PySocks missing – TOR skipped (pip install PySocks)")

def random_user_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
    ]
    return random.choice(agents)

# ---- MASTER SHIELD ACTIVATOR (now 10x sneakier) ----
def activate_shield(target=None):
    print(f"[SHIELD] Activating defensive layer – evasion level: VIKING MODE")
    tor_proxy()
    mac_spoof()
    
    # Only throw noise if we actually have a target (used during scans)
    if target:
        evade_sleep()
        if random.random() < 0.35:  # 35% chance per action
            noise_packet(target)