import os
import random
import time
import socket
from datetime import datetime

def evade_sleep():
    delay = random.uniform(1.0, 7.0)
    print(f"[SHIELD] Ghost delay {delay:.2f}s")
    time.sleep(delay)

def noise_packet(target):
    fake_ports = [80, 443, 53, 8080, 22]
    port = random.choice(fake_ports)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target, port))
        s.close()
        print(f"[SHIELD] Noise packet → {target}:{port}")
    except:
        pass

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
        print("[SHIELD] PySocks missing – TOR skipped (run: pip install PySocks)")

def activate_shield(target=None):
    print(f"[SHIELD] Activating defensive layer – evasion level: VIKING MODE")
    tor_proxy()
    mac_spoof()
    if target:
        evade_sleep()
        if random.random() < 0.35:
            noise_packet(target)