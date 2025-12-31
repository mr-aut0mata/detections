#!/usr/bin/env python3
"""
Windows Prefetch Forensic Parser - v2.0
Supports multiprocessing for multiple prefetch files
"""

import argparse
import json
import logging
import sys
import ctypes
import time
import os
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, Any, Optional, Iterator

# ============================================================================
# [USER INPUT REQUIRED] EXTERNAL DEPENDENCIES
# ============================================================================
# This script requires the 'windowsprefetch' library.
# Install it via pip before running:
# pip install windowsprefetch
try:
    import windowsprefetch
except ImportError:
    print("CRITICAL ERROR: 'windowsprefetch' library not found.")
    print("Please install it using: pip install windowsprefetch")
    sys.exit(1)

# ============================================================================
# [USER INPUT REQUIRED] CONFIGURATION
# ============================================================================

# Performance Tuning:
# Adjust this based on your CPU cores. Prefetch parsing is CPU-heavy.
# Default: 4 (Safe for most standard workstations). 
# Set to 8 or 16 for high-end forensic workstations.
MAX_WORKERS = 4 

# Default Output Filename:
# If the user does not supply '-o' via CLI, this name is used.
DEFAULT_OUTPUT_FILE = "prefetch_events.jsonl"

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("PrefetchParser")

# ============================================================================
# FORENSIC UTILITIES
# ============================================================================

class ForensicsUtils:
    @staticmethod
    def is_admin() -> bool:
        """Checks if the script has Administrator privileges (Required for C:\\Windows\\Prefetch)."""
        try:
            return os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def extract_hash_from_name(filename: str) -> Optional[str]:
        """
        Extracts the 8-char hex hash from the prefetch filename.
        Example: SVCHOST.EXE-6F24CAF3.pf -> 6F24CAF3
        This hash is critical to identify WHERE the binary ran from.
        """
        try:
            # Strip extension .pf
            stem = Path(filename).stem
            # Split by hyphen and take the last part
            parts = stem.rsplit('-', 1)
            if len(parts) == 2 and len(parts[1]) == 8:
                return parts[1]
        except Exception:
            pass
        return None

def parse_pf_file(file_path: Path) -> Dict[str, Any]:
    """
    Worker function to parse a single .pf file.
    Executed in parallel processes.
    """
    try:
        # windowsprefetch library requires string input
        pf = windowsprefetch.Prefetch(str(file_path))
        
        # Calculate derived forensic metrics
        pf_hash = ForensicsUtils.extract_hash_from_name(file_path.name)
        
        # Normalize timestamps to ISO 8601 strings for JSON compatibility
        last_runs = []
        if pf.lastRunTimes:
            for t in pf.lastRunTimes:
                if t:
                    last_runs.append(str(t))

        # Construct structured event
        result = {
            "metadata": {
                "source_file": file_path.name,
                "prefetch_hash": pf_hash,
                "parsed_at": datetime.now(timezone.utc).isoformat()
            },
            "execution": {
                "executable": pf.executableName,
                "run_count": pf.runCount,
                "last_run_times": last_runs
            },
            "files_referenced": [m.filename for m in pf.fileMetrics]
        }
        return result

    except Exception as e:
        # Gracefully handle corrupted files without stopping the batch
        return {
            "error": str(e),
            "source_file": file_path.name,
            "status": "failed"
        }

def scan_directory(directory: Path) -> Iterator[Path]:
    """Yields .pf files from directory, handling permission errors."""
    try:
        for entry in directory.glob("*.pf"):
            if entry.is_file():
                yield entry
    except PermissionError:
        logger.error(f"Permission denied accessing {directory}. Run as Administrator.")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    # --- [USER INPUT REQUIRED] COMMAND LINE ARGUMENTS ---
    parser = argparse.ArgumentParser(description="High-Performance Windows Prefetch Parser")
    
    # Input Source (User must provide one of these)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=Path, help="Path to a single .pf file")
    group.add_argument("-d", "--dir", type=Path, help="Directory containing .pf files (e.g., C:\\Windows\\Prefetch)")
    
    # Output Options
    parser.add_argument("-o", "--output", type=Path, default=Path(DEFAULT_OUTPUT_FILE), 
                       help=f"Output JSONL file (default: {DEFAULT_OUTPUT_FILE})")
    
    # Worker Override
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, 
                       help=f"Number of parallel processes (default: {MAX_WORKERS})")
    
    args = parser.parse_args()

    # 1. Environment Checks
    if not ForensicsUtils.is_admin():
        logger.warning("WARNING: Not running as Administrator.")
        logger.warning("Access to C:\\Windows\\Prefetch usually requires elevated privileges.")

    # 2. Collect Targets
    targets = []
    if args.file:
        if args.file.exists():
            targets.append(args.file)
        else:
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
    elif args.dir:
        if args.dir.exists():
            targets = list(scan_directory(args.dir))
            logger.info(f"Found {len(targets)} .pf files in {args.dir}")
        else:
            logger.error(f"Directory not found: {args.dir}")
            sys.exit(1)

    if not targets:
        logger.info("No files to process. Exiting.")
        sys.exit(0)

    # 3. Execution (Parallel)
    logger.info(f"Starting analysis with {args.workers} workers...")
    logger.info("Streaming results to disk (JSONL format)...")
    
    start_time = time.time()
    success_count = 0
    error_count = 0

    try:
        # Open output file once, write line-by-line
        with open(args.output, 'w', encoding='utf-8') as outfile:
            with ProcessPoolExecutor(max_workers=args.workers) as executor:
                # Submit all tasks map futures to source files
                future_to_file = {executor.submit(parse_pf_file, f): f for f in targets}
                
                for future in as_completed(future_to_file):
                    data = future.result()
                    
                    # Write to disk immediately to save RAM
                    outfile.write(json.dumps(data) + '\n')
                    
                    if "error" in data:
                        error_count += 1
                        logger.debug(f"Failed to parse {data.get('source_file')}: {data.get('error')}")
                    else:
                        success_count += 1
                        
                    # Progress Indicator
                    total = success_count + error_count
                    if total % 100 == 0:
                        logger.info(f"Processed {total}/{len(targets)} files...")

    except IOError as e:
        logger.error(f"Failed to write to output file: {e}")
        sys.exit(1)

    # 4. Final Report
    duration = time.time() - start_time
    logger.info("-" * 40)
    logger.info(f"Analysis Complete in {duration:.2f} seconds")
    logger.info(f"Successful: {success_count}")
    logger.info(f"Failed:     {error_count}")
    logger.info(f"Results:    {args.output.absolute()}")
    logger.info("-" * 40)

if __name__ == "__main__":
    main()
