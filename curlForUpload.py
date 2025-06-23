#!/usr/bin/env python3

import os
import json
import argparse
import sys
import subprocess
import random
import string
import time
from datetime import datetime
from urllib.parse import urlparse

def ensure_directories(base_dir="results"):
    """Create the necessary output directories if they don't exist."""
    try:
        directories = [
            base_dir,
            f"{base_dir}/uploads",
            f"{base_dir}/logs",
            f"{base_dir}/successful",
            f"{base_dir}/failed"
        ]
        
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"Created '{directory}' directory")
                
        return True
    except Exception as e:
        print(f"Error creating directories: {e}")
        return False

def load_json_data(json_file):
    """Load and parse the JSON input file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading file: {e}")
        sys.exit(1)

def generate_test_files(file_types, content_size=1024, directory="results/uploads"):
    """Generate test files of the specified types with random content."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    files = {}
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    for file_type in file_types:
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        filename = f"test_upload_{timestamp}_{random_str}.{file_type}"
        filepath = os.path.join(directory, filename)
        
        try:
            with open(filepath, 'w') as f:
                # Generate random content
                if file_type.lower() in ['html', 'js', 'php']:
                    # For script-like files, include a basic identifiable payload
                    f.write(f"<!-- Penetration Test File: {timestamp}_{random_str} -->\n")
                    f.write("<script>alert('This is a penetration test upload');</script>\n")
                    # Pad with random data
                    f.write(''.join(random.choices(string.ascii_letters + string.digits, k=content_size)))
                else:
                    # For other files just use random data
                    f.write(''.join(random.choices(string.ascii_letters + string.digits, k=content_size)))
            
            files[file_type] = filepath
            print(f"  [*] Created test file: {filename}")
            
        except Exception as e:
            print(f"  [!] Error generating test file for {file_type}: {e}")
    
    return files

def attempt_upload(ip, port, protocol, file_path, method="POST"):
    """Attempt to upload a file to the specified target using curl."""
    url = f"{protocol}://{ip}:{port}"
    filename = os.path.basename(file_path)
    
    # Prepare the curl command
    curl_cmd = [
        'curl',
        '-X', method,
        '-k',  # Skip SSL verification
        '-s',  # Silent mode
        '-w', '%{http_code}\\n',  # Write out the HTTP status code
        '-F', f"file=@{file_path}",  # Upload the file
        '-H', f"X-Filename: {filename}",  # Add a header with the filename
        '-H', "Content-Type: multipart/form-data",
        url
    ]
    
    try:
        # Execute the curl command
        result = subprocess.run(
            curl_cmd,
            capture_output=True,
            text=True
        )
        
        # Extract the HTTP status code
        response_body = result.stdout[:-4] if len(result.stdout) > 4 else ""
        status_code = result.stdout[-4:].strip() if len(result.stdout) > 0 else "000"
        
        try:
            status_code = int(status_code)
        except ValueError:
            status_code = 0
            
        return {
            "success": status_code >= 200 and status_code < 300,
            "status_code": status_code,
            "response": response_body,
            "error": result.stderr,
            "url": url,
            "file": filename
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": 0,
            "response": "",
            "error": str(e),
            "url": url,
            "file": filename
        }

def save_result(result, base_dir="results"):
    """Save the result of an upload attempt to appropriate output files."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    result_dir = f"{base_dir}/successful" if result["success"] else f"{base_dir}/failed"
    
    # Create a filename based on the target and result
    filename = f"{result_dir}/{timestamp}_{result['url'].replace('://', '_').replace(':', '_').replace('/', '_')}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(result, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving result: {e}")
        return False

def test_upload(ip, port, protocol, file_path):
    """Test file upload for a given IP:port combination."""
    results = []
    
    # Try POST method
    print(f"      [*] Testing POST to {protocol}://{ip}:{port}")
    post_result = attempt_upload(ip, port, protocol, file_path, "POST")
    results.append(post_result)
    
    # Wait 10 seconds between attempts
    print(f"      [*] Waiting 10 seconds before next request...")
    time.sleep(10)
    
    # If POST failed, try PUT method
    if not post_result["success"]:
        print(f"      [*] Testing PUT to {protocol}://{ip}:{port}")
        put_result = attempt_upload(ip, port, protocol, file_path, "PUT")
        results.append(put_result)
        
        # Wait 10 seconds between attempts
        print(f"      [*] Waiting 10 seconds before next request...")
        time.sleep(10)
        
    return results

def process_target(ip_data, test_files, base_dir):
    """Process a single IP target from the JSON data."""
    ip = ip_data["IP"]
    all_results = []
    
    print(f"\n[+] Testing file uploads for IP: {ip}")
    
    # Test each service for the IP
    for service in ip_data.get("services", []):
        port = service.get("Port", "")
        protocol = service.get("Service", "").lower()
        
        # Skip non-HTTP services
        if protocol not in ["http", "https"]:
            if protocol in ["ftp", "ssh", "sftp"]:
                print(f"  [i] Service {protocol} on port {port} could support file uploads but requires specific authentication.")
            else:
                print(f"  [i] Skipping non-HTTP service {protocol} on port {port}")
            continue
            
        # Use http as the protocol for URLs
        url_protocol = "https" if protocol == "https" else "http"
        
        print(f"  [+] Testing service: {protocol} on port {port}")
        
        # Try each file type
        for file_type, file_path in test_files.items():
            print(f"    [*] Testing upload of file type: {file_type}")
            
            # Test upload only to the root endpoint
            upload_results = test_upload(ip, port, url_protocol, file_path)
            
            for result in upload_results:
                all_results.append(result)
                
                # Save individual result
                save_result(result, base_dir)
                
                # Print result summary
                status = "SUCCESS" if result["success"] else "FAILED"
                print(f"      [{status}] {result['url']} - Status: {result['status_code']}")
    
    return all_results

def generate_summary_report(results, output_file):
    """Generate a summary report of all test results."""
    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    
    try:
        with open(output_file, 'w') as f:
            f.write("# File Upload Testing Summary Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Total Tests: {len(results)}\n")
            f.write(f"Successful Uploads: {len(successful)}\n")
            f.write(f"Failed Uploads: {len(failed)}\n\n")
            
            # List successful uploads
            f.write("## Successful Uploads\n")
            if successful:
                for result in successful:
                    f.write(f"- {result['url']} - {result['status_code']} - {result['file']}\n")
            else:
                f.write("No successful uploads found.\n")
                
            f.write("\n## Failed Uploads\n")
            if failed:
                for result in failed:
                    f.write(f"- {result['url']} - {result['status_code']}\n")
            else:
                f.write("No failed uploads found.\n")
                
        print(f"\nSummary report generated: {output_file}")
        return True
    except Exception as e:
        print(f"Error generating summary report: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Test file uploads against targets specified in a JSON file')
    parser.add_argument('json_file', help='JSON file containing target information')
    parser.add_argument('--output-dir', default='results', help='Directory for output files (default: results)')
    parser.add_argument('--file-types', default='php,js,html,svg,jpg,pdf,zip', help='Comma-separated list of file types to test')
    parser.add_argument('--limit', type=int, default=0, 
                      help='Limit testing to the first N IPs in the JSON file (default: 0 = test all)')
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.json_file):
        print(f"Input file {args.json_file} does not exist")
        sys.exit(1)
        
    # Setup directories
    if not ensure_directories(args.output_dir):
        sys.exit(1)
        
    # Load the JSON data
    targets = load_json_data(args.json_file)
    
    # Apply IP limit if specified
    if args.limit > 0 and args.limit < len(targets):
        print(f"[+] Limiting test to the first {args.limit} IPs out of {len(targets)} total IPs")
        targets = targets[:args.limit]
    
    # Parse file types
    file_types = [t.strip() for t in args.file_types.split(',')]
    
    # Output startup message
    print(f"[+] Starting file uploads test with {len(targets)} targets")
    print(f"[+] Testing {len(file_types)} file types: {', '.join(file_types)}")
    print(f"[+] Testing uploads to root endpoint only")
    
    # Generate test files (one per file type)
    print(f"[+] Generating test files...")
    test_files = generate_test_files(file_types, directory=f"{args.output_dir}/uploads")
    if not test_files:
        print(f"[!] Failed to generate test files. Exiting.")
        sys.exit(1)
    
    all_results = []
    
    # Process each target
    for target in targets:
        results = process_target(target, test_files, args.output_dir)
        all_results.extend(results)
        
    # Generate summary report
    summary_file = f"{args.output_dir}/summary_report.txt"
    generate_summary_report(all_results, summary_file)
    
    # Print final statistics
    successful = [r for r in all_results if r["success"]]
    print(f"\n[+] Testing completed!")
    print(f"[+] Total tests: {len(all_results)}")
    print(f"[+] Successful uploads: {len(successful)}")
    print(f"[+] Failed uploads: {len(all_results) - len(successful)}")
    
    # Print successful uploads for quick reference
    if successful:
        print("\n[+] Successful uploads:")
        for result in successful:
            print(f"  - {result['url']} - Status: {result['status_code']} - File: {result['file']}")
    else:
        print("\n[i] No successful uploads found")
        
    # Exit with status code based on success
    sys.exit(0 if successful else 1)

if __name__ == "__main__":
    main()
