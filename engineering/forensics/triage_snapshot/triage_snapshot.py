import psutil
import platform
import json
import hashlib
import datetime
import os
import sys

def get_file_hash_sha256(path):
    """Generates a SHA-256 hash of an executable for IOC matching."""
    if not path or not os.path.exists(path):
        return "N/A"
    try:
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            # Read in 4KB chunks to remain memory efficient
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        # Can be triggered by locked system files or permission issues
        return "Access Denied"

def collect_triage():
    """Captures volatile system state: Processes, Network, and System Info."""
    snapshot = {
        "metadata": {
            "timestamp_utc": datetime.datetime.utcnow().isoformat(),
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
        },
        "processes": [],
        "network_connections": []
    }

    # Collect Process List with expanded metadata
    # We include 'cmdline' and 'ppid' to help identify 'Living off the Land' attacks
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline']):
        try:
            pinfo = proc.info
            # Add SHA-256 hash of the binary
            pinfo['sha256'] = get_file_hash_sha256(pinfo['exe'])
            snapshot["processes"].append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Collect Network Connections (TCP/UDP)
    try:
        for conn in psutil.net_connections(kind='inet'):
            snapshot["network_connections"].append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid,
                "type": "TCP" if conn.type == 1 else "UDP"
            })
    except psutil.AccessDenied:
        print("[!] Warning: Access denied while fetching network connections. Run as Admin/Root.")

    return snapshot

def main():
    # Check for administrative privileges
    is_admin = False
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0
    except AttributeError:
        pass

    if not is_admin:
        print("[!] Warning: Script is not running with elevated privileges.")
        print("[!] Some process paths, hashes, and network details will be unavailable.\n")

    print("Gathering system snapshot...")
    data = collect_triage()
    
    filename = f"triage_{data['metadata']['hostname']}_{datetime.date.today()}.json"
    
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[*] Triage complete. Data saved to: {filename}")
    except Exception as e:
        print(f"[#] Error saving file: {e}")

if __name__ == "__main__":
    main()
