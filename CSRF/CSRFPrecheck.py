#!/usr/bin/env python3
"""
CSRF Analyzer Script
Analyzes Burp Suite XML data for POST requests with body parameters and cookies
"""

import xml.etree.ElementTree as ET
import base64
import re
from urllib.parse import parse_qs, unquote
import argparse


class CSRFAnalyzer:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.post_requests = []
        
    def parse_burp_xml(self):
        """Parse Burp Suite XML file and extract POST requests"""
        try:
            tree = ET.parse(self.xml_file)
            root = tree.getroot()
            
            for item in root.findall('.//item'):
                request_elem = item.find('request')
                if request_elem is not None:
                    # Decode base64 request
                    request_data = base64.b64decode(request_elem.text).decode('utf-8', errors='ignore')
                    
                    # Check if it's a POST request
                    if request_data.startswith('POST'):
                        self.post_requests.append({
                            'raw_request': request_data,
                            'url': item.find('url').text if item.find('url') is not None else 'Unknown'
                        })
                        
        except Exception as e:
            print(f"Error parsing XML: {e}")
    
    def extract_body_parameters(self, request_data):
        """Extract body parameters from POST request"""
        try:
            # Split headers and body
            if '\r\n\r\n' in request_data:
                headers, body = request_data.split('\r\n\r\n', 1)
            elif '\n\n' in request_data:
                headers, body = request_data.split('\n\n', 1)
            else:
                return {}
            
            # Parse URL-encoded form data
            if 'application/x-www-form-urlencoded' in headers or ('=' in body and '&' in body):
                try:
                    parsed = parse_qs(body, keep_blank_values=True)
                    # Flatten single-value lists
                    return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                except:
                    pass
            
            # For JSON or other content types, try to find key=value patterns
            param_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*([^&\n\r]+)'
            matches = re.findall(param_pattern, body)
            if matches:
                return {match[0]: match[1].strip('"\'') for match in matches}
            
            return {}
            
        except Exception as e:
            return {}
    
    def extract_cookies(self, request_data):
        """Extract cookies from request headers"""
        cookies = {}
        
        # Look for Cookie header (case insensitive)
        cookie_pattern = r'(?i)^cookie:\s*(.+)$'
        
        for line in request_data.split('\n'):
            match = re.match(cookie_pattern, line.strip())
            if match:
                cookie_string = match.group(1)
                
                # Parse cookie string
                for cookie in cookie_string.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name.strip()] = value.strip()
                    else:
                        cookies[cookie.strip()] = ''
                        
        return cookies
    
    def has_cookie_header(self, request_data):
        """Check if request has Cookie header"""
        cookie_pattern = r'(?i)^cookie:'
        
        for line in request_data.split('\n'):
            if re.match(cookie_pattern, line.strip()):
                return True
        return False
    
    def analyze(self):
        """Main analysis function"""
        print("=== CSRF ANALYZER RESULTS ===\n")
        
        self.parse_burp_xml()
        
        if not self.post_requests:
            print("No POST requests found in the dataset.")
            return
        
        print(f"Total POST requests found: {len(self.post_requests)}\n")
        
        requests_with_body_params = []
        
        for i, req in enumerate(self.post_requests, 1):
            print(f"--- POST Request #{i} ---")
            print(f"URL: {req['url']}")
            
            # Extract body parameters
            body_params = self.extract_body_parameters(req['raw_request'])
            
            if body_params:
                requests_with_body_params.append(req)
                print(f"✓ Has body parameters: YES")
                print(f"Body parameter count: {len(body_params)}")
                print("Body parameters:")
                for param, value in body_params.items():
                    print(f"  - {param}: {value}")
            else:
                print("✓ Has body parameters: NO")
            
            # Check for cookies
            has_cookies = self.has_cookie_header(req['raw_request'])
            cookies = self.extract_cookies(req['raw_request'])
            
            print(f"✓ Has Cookie header: {'YES' if has_cookies else 'NO'}")
            
            if cookies:
                print(f"Cookie count: {len(cookies)}")
                print("Cookies:")
                for name, value in cookies.items():
                    print(f"  - {name}: {value}")
            else:
                print("Cookie count: 0")
            
            print()
        
        # Summary
        print("=== SUMMARY ===")
        print(f"Total POST requests: {len(self.post_requests)}")
        print(f"POST requests with body parameters: {len(requests_with_body_params)}")
        
        total_with_cookies = sum(1 for req in self.post_requests 
                               if self.has_cookie_header(req['raw_request']))
        print(f"POST requests with cookies: {total_with_cookies}")


def main():
    parser = argparse.ArgumentParser(description='Analyze Burp Suite XML for CSRF vulnerabilities')
    parser.add_argument('xml_file', help='Path to Burp Suite XML file')
    
    args = parser.parse_args()
    
    analyzer = CSRFAnalyzer(args.xml_file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
