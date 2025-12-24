# Memory Forensic Scanner

A Python-based utility for identifying artifacts within raw memory dumps. This tool is designed for investigative use to find indicators of fileless malware, shellcode, and encrypted payloads that may not leave a footprint on a physical disk.

## Overview
The script performs a heuristic scan of a memory dump to identify four specific indicators:

*   **PE Header Discovery:** Locates 'MZ' signatures to identify executables and DLLs mapped in RAM.
*   **Suspicious Strings:** Scans for system-critical terms (e.g., powershell, cmd.exe, kernel32.dll) that are often leveraged in post-exploitation.
*   **NOP Sled Detection:** Identifies sequences of `0x90` bytes commonly used in buffer overflows and shellcode stabilization.
*   **Entropy Analysis:** Calculates Shannon entropy for data blocks. High entropy scores (near 8.0) suggest the presence of encrypted, packed, or compressed data.

## Requirements
*   **Python 3.x**
*   No external libraries are required (uses standard `math`, `re`, and `os` modules).

## Usage

### Testing
Running the script without modification will trigger a simulation. It generates a small mock memory dump in your system's RAM to demonstrate how the detection logic handles various artifacts.


