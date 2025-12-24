import argparse
import json
import os
import windowsprefetch

def parse_prefetch_file(file_path):
    """Parses a single .pf file and returns a dictionary of results."""
    try:
        prefetch = windowsprefetch.Prefetch(file_path)
        
        # Gathering core execution data
        data = {
            "executable_name": prefetch.executableName,
            "run_count": prefetch.runCount,
            "last_run_times": [str(t) for t in prefetch.lastRunTimes if t],
            "file_metrics": [],
            "source_file": os.path.basename(file_path)
        }
        
        # Get list of files referenced by this executable (e.g. DLLs loaded)
        for entry in prefetch.fileMetrics:
            data["file_metrics"].append(entry.filename)
            
        return data
    except Exception as e:
        return {"error": f"Failed to parse {file_path}: {str(e)}"}

def main():
    parser = argparse.ArgumentParser(description="Windows Prefetch Forensic Parser")
    parser.add_argument("-f", "--file", help="Path to a single .pf file")
    parser.add_argument("-d", "--dir", help="Directory containing .pf files (usually C:\\Windows\\Prefetch)")
    parser.add_argument("-o", "--output", help="Output JSON file name", default="prefetch_report.json")
    
    args = parser.parse_args()
    results = []

    if args.file:
        results.append(parse_prefetch_file(args.file))
    elif args.dir:
        files = [os.path.join(args.dir, f) for f in os.listdir(args.dir) if f.endswith(".pf")]
        print(f"Parsing {len(files)} files...")
        for f in files:
            results.append(parse_prefetch_file(f))
    else:
        parser.print_help()
        return

    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
    
    print(f"Analysis complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()
