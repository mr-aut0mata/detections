# Windows Prefetch Parser

This script extracts execution history from Windows Prefetch (.pf) files. It is used to prove that a specific application was run on a system, even if the application itself has been deleted.

### What it extracts:
*   **Executable Name:** The name of the process that ran.
*   **Run Count:** How many times the application has been launched.
*   **Last Run Times:** Timestamps for the last 8 executions (on Windows 8.1/10/11).
*   **File Metrics:** A list of DLLs and handles accessed by the process during its first 10 seconds of execution.

### Prerequisites
*   Python 3.x
*   Dependency: `pip install windowsprefetch`

### Usage
Analyze the system's prefetch directory (requires Admin/Elevated privileges):
```bash
python prefetch_parser.py -d C:\Windows\Prefetch

Analyze a specific file:
python prefetch_parser.py -f CMD.EXE-AC12B3.pf
