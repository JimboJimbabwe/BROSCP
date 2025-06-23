#!/usr/bin/env python3
import json
import subprocess
import argparse
import time
import os
import random
import logging
import signal
import sys
import re
from concurrent.futures import ThreadPoolExecutor

# Global variable to track if we need to exit
should_exit = False

def signal_handler(sig, frame):
    """Handle keyboard interrupts (CTRL+C)"""
    global should_exit
    print("\n[!] Keyboard interrupt detected! Gracefully shutting down...")
    should_exit = True
    return True

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("curl_script.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("curl_script")

def load_targets(json_file):
    """Load targets from a JSON file."""
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data

def load_payloads(wordlist_file):
    """Load payloads from a wordlist file."""
    with open(wordlist_file, 'r') as f:
        payloads = [line.strip() for line in f if line.strip()]
    return payloads

def parse_payload(payload):
    """Parse payload to extract headers, data, and actual path."""
    headers = []
    data = None
    path = payload
    
    # Look for header flags (-H) in the payload
    header_pattern = r'-H\s+("[^"]+"|\'[^\']+\'|\S+)'
    header_matches = re.findall(header_pattern, payload)
    
    if header_matches:
        # Extract headers
        for match in header_matches:
            # Remove quotes if they exist
            header_value = match.strip('"\'')
            headers.append(header_value)
        
        # Remove header parts from the path
        path = re.sub(r'-H\s+("[^"]+"|\'[^\']+\'|\S+)', '', payload).strip()
    
    # Look for data flag (-d) in the payload
    data_pattern = r'-d\s+("[^"]+"|\'[^\']+\'|\S+)'
    data_match = re.search(data_pattern, payload)
    
    if data_match:
        # Extract data
        data_value = data_match.group(1).strip('"\'')
        data = data_value
        
        # Remove data part from the path
        path = re.sub(r'-d\s+("[^"]+"|\'[^\']+\'|\S+)', '', path).strip()
    
    return headers, data, path

def execute_curl(ip, port, payload, timeout=10, output_dir=None, logger=None):
    """Execute a curl command against a target."""
    global should_exit
    if should_exit:
        return ip, port, payload, "ABORTED"
    
    # Parse payload for any curl options embedded in it
    headers, data, path = parse_payload(payload)
    
    # Construct the URL with the path part of the payload
    url = f"http://{ip}:{port}/{path}"
    
    # Base curl command
    command = ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}"]
    
    # Add custom headers if found in payload
    if headers:
        for header in headers:
            command.extend(["-H", header])
    else:
        # Default User-Agent if no custom headers
        command.extend(["-A", "Mozilla/5.0"])
    
    # Add data if found in payload
    if data:
        command.extend(["-d", data])
    
    # Add the URL
    command.append(url)
    
    # Log the command being executed
    command_str = " ".join(command)
    if logger:
        logger.info(f"Executing: {command_str}")
    else:
        print(f"Executing: {command_str}")
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        status_code = result.stdout.strip()
        
        # If we get interesting responses (non-404), save them
        if status_code != "404" and status_code != "000":
            message = f"[+] {url} - Status: {status_code}"
            if logger:
                logger.info(message)
            else:
                print(message)
            
            # Save output if directory specified
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                save_filename = f"{ip}_{port}_{path.replace('/', '_')}"
                if len(save_filename) > 200:  # Avoid overly long filenames
                    save_filename = save_filename[:200]
                output_file = os.path.join(output_dir, f"{save_filename}.txt")
                
                # For saving content, use the same URL but without the write-out option
                save_command = command.copy()
                
                # Remove -o and -w flags for saving the actual content
                if "-o" in save_command:
                    idx = save_command.index("-o")
                    save_command.pop(idx)  # Remove -o
                    save_command.pop(idx)  # Remove /dev/null
                
                if "-w" in save_command:
                    idx = save_command.index("-w")
                    save_command.pop(idx)  # Remove -w
                    save_command.pop(idx)  # Remove %{http_code}
                
                # Log the save command
                save_command_str = " ".join(save_command) + f" > {output_file}"
                if logger:
                    logger.info(f"Saving output: {save_command_str}")
                else:
                    print(f"Saving output: {save_command_str}")
                
                with open(output_file, 'w') as f:
                    subprocess.run(save_command, stdout=f)
        
        return ip, port, payload, status_code
    except subprocess.TimeoutExpired:
        error_msg = f"[!] Timeout: {url}"
        if logger:
            logger.warning(error_msg)
        else:
            print(error_msg)
        return ip, port, payload, "TIMEOUT"
    except Exception as e:
        error_msg = f"[!] Error with {url}: {str(e)}"
        if logger:
            logger.error(error_msg)
        else:
            print(error_msg)
        return ip, port, payload, "ERROR"

def worker(args):
    """Worker function for thread pool."""
    global should_exit
    if should_exit:
        return None, None, None, "ABORTED"
        
    ip, port, payload, delay, timeout, output_dir, logger = args
    if delay > 0:
        time.sleep(delay)
    return execute_curl(ip, port, payload, timeout, output_dir, logger)

def extract_ips_from_json(targets_data):
    """Extract IP addresses from the specific JSON structure provided"""
    target_ips = []
    
    for target in targets_data:
        if isinstance(target, dict) and "Target" in target:
            # In the provided structure, "Target" directly contains the IP value
            if isinstance(target["Target"], str):
                target_ips.append(target["Target"])
    
    # If no IPs found with the specific structure, try a fallback with regex
    if not target_ips:
        import re
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        def extract_ips_with_regex(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and ip_pattern.match(v):
                        target_ips.append(v)
                    elif isinstance(v, (dict, list)):
                        extract_ips_with_regex(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract_ips_with_regex(item)
        
        extract_ips_with_regex(targets_data)
    
    return target_ips

def process_work_items(work_items, concurrency, logger):
    """Process work items with proper error handling and graceful shutdown"""
    global should_exit
    results = []
    
    if concurrency == 1:
        # Single-threaded processing
        logger.info(f"Running in single-threaded mode (concurrency=1)")
        for i, item in enumerate(work_items):
            if should_exit:
                logger.info("Aborting remaining tasks due to keyboard interrupt")
                break
            try:
                result = worker(item)
                results.append(result)
                
                # Print progress periodically
                if (i + 1) % 10 == 0 or i + 1 == len(work_items):
                    logger.info(f"Progress: {i + 1}/{len(work_items)} ({(i + 1) / len(work_items) * 100:.2f}%)")
                
            except Exception as e:
                logger.error(f"Error processing item: {e}")
    else:
        # Multi-threaded processing
        logger.info(f"Running in multi-threaded mode with {concurrency} threads")
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            
            # Submit all tasks
            for item in work_items:
                futures.append(executor.submit(worker, item))
            
            # Process results as they complete
            completed = 0
            for future in futures:
                if should_exit:
                    logger.info("Aborting remaining tasks due to keyboard interrupt")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress periodically
                    completed += 1
                    if completed % 20 == 0 or completed == len(work_items):
                        logger.info(f"Progress: {completed}/{len(work_items)} ({completed / len(work_items) * 100:.2f}%)")
                    
                except Exception as e:
                    logger.error(f"Error processing task: {e}")
    
    return results

def main():
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    global should_exit
    
    parser = argparse.ArgumentParser(description="Curl automation script for Synack mission")
    parser.add_argument("-t", "--targets", required=True, help="JSON file containing targets")
    parser.add_argument("-w", "--wordlist", required=True, help="File containing payloads/wordlist")
    parser.add_argument("-r", "--rate-limit", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("-o", "--output-dir", help="Directory to save interesting responses")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Number of concurrent threads (set to 1 for sequential processing)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for curl requests in seconds")
    parser.add_argument("--testing", action="store_true", help="Test mode: use only one random IP from targets")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to test (default: 80,8080,8443,443)")
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging()
    logger.info(f"Starting curl automation script with args: {args}")
    logger.info(f"Press Ctrl+C at any time to gracefully stop the script")
    
    try:
        # Load targets and payloads
        targets_data = load_targets(args.targets)
        payloads = load_payloads(args.wordlist)
        
        logger.info(f"Loaded {len(targets_data)} target entries and {len(payloads)} payloads")
        
        # Extract IPs from the targets data structure
        target_ips = extract_ips_from_json(targets_data)
        logger.info(f"Extracted {len(target_ips)} IP addresses")
        
        if not target_ips:
            logger.error("No IP addresses found in the targets file. Exiting.")
            return
        
        # If testing mode is enabled, just pick one random IP
        if args.testing:
            test_ip = random.choice(target_ips)
            logger.info(f"TESTING MODE: Using only IP {test_ip}")
            target_ips = [test_ip]
        
        # Prepare work items
        ports = [80, 8080, 8443, 443]  # Default ports
        if args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
            logger.info(f"Using custom ports: {ports}")
        
        work_items = []
        
        # Create work items for each combination
        for ip in target_ips:
            for port in ports:
                for payload in payloads:
                    work_items.append((ip, port, payload, args.rate_limit, args.timeout, args.output_dir, logger))
        
        logger.info(f"Starting {len(work_items)} curl requests with concurrency={args.concurrency}")
        
        # Process work items
        results = process_work_items(work_items, args.concurrency, logger)
        
        # Summary of results
        if should_exit:
            logger.info("Script was interrupted by user - partial results:")
            
        completed_count = len(results)
        planned_count = len(work_items)
        success_count = sum(1 for r in results if r[3] not in ["TIMEOUT", "ERROR", "404", "000", "ABORTED"])
        
        logger.info(f"Completed {completed_count}/{planned_count} requests. Found {success_count} interesting responses")
        
        # Display some example interesting responses if any were found
        if success_count > 0:
            interesting = [r for r in results if r[3] not in ["TIMEOUT", "ERROR", "404", "000", "ABORTED"]]
            logger.info("Sample of interesting responses:")
            for i, (ip, port, payload, status) in enumerate(interesting[:5]):  # Show at most 5 examples
                logger.info(f"  {i+1}. http://{ip}:{port}/{parse_payload(payload)[2]} - Status: {status}")
            
            if success_count > 5:
                logger.info(f"  ... and {success_count - 5} more")
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
    
    logger.info("Script execution completed")

if __name__ == "__main__":
    main()
