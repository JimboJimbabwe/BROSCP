#!/usr/bin/env python3
"""
Client-Side Redirect Analyzer Script
Finds script paths in POST requests and matches them against other requests in the dataset
"""

import xml.etree.ElementTree as ET
import base64
import re
from urllib.parse import urlparse
import argparse


class RedirectAnalyzer:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.post_requests = []
        self.all_requests = []
        self.script_patterns = [
            r'/[a-zA-Z0-9_\-/]+\.js',           # .js files
            r'/[a-zA-Z0-9_\-/]+\.ts',           # .ts files  
            r'/[a-zA-Z0-9_\-/]+\.jsx',          # .jsx files
            r'/[a-zA-Z0-9_\-/]+\.tsx',          # .tsx files
            r'/[a-zA-Z0-9_\-/]+\.coffee',       # .coffee files
            r'/[a-zA-Z0-9_\-/]+\.php',          # .php files
            r'/[a-zA-Z0-9_\-/]+\.py',           # .py files
            r'/[a-zA-Z0-9_\-/]+\.rb',           # .rb files
            r'/[a-zA-Z0-9_\-/]+\.pl',           # .pl files
            r'/[a-zA-Z0-9_\-/]+\.go',           # .go files
            r'/[a-zA-Z0-9_\-/]+\.java',         # .java files
            r'/[a-zA-Z0-9_\-/]+\.jsp',          # .jsp files
            r'/[a-zA-Z0-9_\-/]+\.asp',          # .asp files
            r'/[a-zA-Z0-9_\-/]+\.aspx',         # .aspx files
            r'/[a-zA-Z0-9_\-/]+\.cgi',          # .cgi files
            r'/api/[a-zA-Z0-9_\-/]+',           # API endpoints
            r'/v\d+/[a-zA-Z0-9_\-/]+',          # Versioned endpoints
            r'/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+', # General path patterns
        ]
        
    def parse_burp_xml(self):
        """Parse Burp Suite XML file and extract all requests"""
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()
            
            for item in root.findall('.//item'):
                request_elem = item.find('request')
                if request_elem is not None:
                    # Decode base64 request
                    request_data = base64.b64decode(request_elem.text).decode('utf-8', errors='ignore')
                    
                    url = item.find('url').text if item.find('url') is not None else 'Unknown'
                    
                    request_info = {
                        'raw_request': request_data,
                        'url': url,
                        'method': self.extract_method(request_data),
                        'path': urlparse(url).path if url != 'Unknown' else ''
                    }
                    
                    self.all_requests.append(request_info)
                    
                    # Separate POST requests
                    if request_data.startswith('POST'):
                        self.post_requests.append(request_info)
                        
        except Exception as e:
            print(f"Error parsing XML: {e}")
    
    def extract_method(self, request_data):
        """Extract HTTP method from request"""
        first_line = request_data.split('\n')[0]
        return first_line.split(' ')[0] if ' ' in first_line else 'UNKNOWN'
    
    def find_script_paths(self, request_data):
        """Find script paths in request data"""
        found_paths = []
        
        for pattern in self.script_patterns:
            matches = re.findall(pattern, request_data, re.IGNORECASE)
            found_paths.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for path in found_paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)
        
        return unique_paths
    
    def find_matching_requests(self, script_path):
        """Find requests in dataset that match the script path"""
        matches = []
        
        for req in self.all_requests:
            # Check if the script path appears in the URL path
            if script_path in req['path'] or script_path in req['url']:
                matches.append(req)
        
        return matches
    
    def extract_function_names(self, request_data, script_path):
        """Extract function names associated with the script path"""
        functions = []
        
        # Common patterns for function calls with paths
        patterns = [
            rf'(\w+)\s*\([^)]*["\']?{re.escape(script_path)}["\']?[^)]*\)',  # function('/path/to/script')
            rf'(\w+)\s*\(\s*["\']?{re.escape(script_path)}["\']?\s*\)',      # function('/path/to/script')
            rf'(\w+)\.call\([^)]*["\']?{re.escape(script_path)}["\']?',      # obj.call('/path/to/script')
            rf'(\w+)\.apply\([^)]*["\']?{re.escape(script_path)}["\']?',     # obj.apply('/path/to/script')
            rf'require\s*\(\s*["\']?{re.escape(script_path)}["\']?\s*\)\.(\w+)', # require('/path').function
            rf'import\s+\{{([^}}]+)\}}\s+from\s+["\']?{re.escape(script_path)}["\']?', # import {func} from '/path'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, request_data, re.IGNORECASE)
            if isinstance(matches[0], tuple) if matches else False:
                # Handle tuple results from groups
                for match in matches:
                    if isinstance(match, tuple):
                        functions.extend([m for m in match if m])
                    else:
                        functions.append(match)
            else:
                functions.extend(matches)
        
        # Also look for function names near the script path
        lines = request_data.split('\n')
        for line in lines:
            if script_path in line:
                # Look for function-like patterns in the same line
                func_matches = re.findall(r'(\w+)\s*\(', line)
                functions.extend(func_matches)
        
        # Remove duplicates and common non-function words
        common_words = {'function', 'var', 'let', 'const', 'if', 'for', 'while', 'return', 'new', 'this'}
        unique_functions = list(set(func for func in functions if func.lower() not in common_words))
        
        return unique_functions
    
    def analyze(self):
        """Main analysis function"""
        print("=== CLIENT-SIDE REDIRECT ANALYZER RESULTS ===\n")
        
        self.parse_burp_xml()
        
        if not self.post_requests:
            print("No POST requests found in the dataset.")
            return
        
        print(f"Total requests in dataset: {len(self.all_requests)}")
        print(f"POST requests found: {len(self.post_requests)}\n")
        
        found_redirects = []
        
        for i, post_req in enumerate(self.post_requests, 1):
            print(f"--- Analyzing POST Request #{i} ---")
            print(f"URL: {post_req['url']}")
            
            # Find script paths in POST request
            script_paths = self.find_script_paths(post_req['raw_request'])
            
            if script_paths:
                print(f"✓ Script paths found: {len(script_paths)}")
                
                for script_path in script_paths:
                    print(f"\n  Script Path: {script_path}")
                    
                    # Find matching requests in dataset
                    matching_requests = self.find_matching_requests(script_path)
                    
                    if matching_requests:
                        print(f"  ✓ Found {len(matching_requests)} matching request(s) in dataset:")
                        
                        for match in matching_requests:
                            print(f"    - {match['method']} {match['url']}")
                        
                        # Extract function names from original POST request
                        functions = self.extract_function_names(post_req['raw_request'], script_path)
                        
                        if functions:
                            print(f"  ✓ Potential function names: {', '.join(functions)}")
                            
                            found_redirects.append({
                                'post_url': post_req['url'],
                                'script_path': script_path,
                                'matching_requests': matching_requests,
                                'functions': functions
                            })
                        else:
                            print("  ✗ No function names extracted")
                    else:
                        print("  ✗ No matching requests found in dataset")
            else:
                print("✗ No script paths found")
            
            print()
        
        # Summary
        print("=== SUMMARY ===")
        print(f"POST requests analyzed: {len(self.post_requests)}")
        print(f"Potential client-side redirects found: {len(found_redirects)}")
        
        if found_redirects:
            print("\nDetailed findings:")
            for i, redirect in enumerate(found_redirects, 1):
                print(f"\n{i}. POST URL: {redirect['post_url']}")
                print(f"   Script Path: {redirect['script_path']}")
                print(f"   Functions: {', '.join(redirect['functions'])}")
                print(f"   Handled by: {redirect['matching_requests'][0]['method']} {redirect['matching_requests'][0]['url']}")


def main():
    parser = argparse.ArgumentParser(description='Analyze Burp Suite XML for client-side redirects')
    parser.add_argument('xml_file', help='Path to Burp Suite XML file')
    
    args = parser.parse_args()
    
    analyzer = RedirectAnalyzer(args.xml_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
