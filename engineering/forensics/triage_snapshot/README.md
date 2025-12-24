# Live Triage Snapshot

This utility captures volatile forensic data from a running system. It is designed for use during the initial phase of an incident response to record evidence—such as active network connections and running processes—that would be lost if the system were rebooted or shut down.

## Data Points Captured
*   **Process Inventory:** Lists all active PIDs, Parent PIDs (PPID), and the user accounts associated with them.
*   **Execution Metadata:** Captures the full command-line arguments for each process, which is essential for identifying malicious scripts or "Living off the Land" binaries.
*   **SHA-256 Hashing:** Automatically generates SHA-256 hashes for all accessible process executables to facilitate threat intelligence lookups.
*   **Network Activity:** Records all active IPv4/IPv6 connections, including local/remote ports and the PID responsible for the traffic.
*   **System Context:** Captures hostname, OS version, and system boot time.

## Prerequisites
*   **Python 3.x**
*   **Library:** `psutil`
    ```bash
    pip install psutil
    ```

## Usage
For the most accurate results, the script must be run with elevated privileges (Administrator on Windows or `sudo` on Linux) to access protected process memory and hashes.

```bash
python triage_snapshot.py
