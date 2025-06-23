import xml.etree.ElementTree as ET
import base64
import sys
import re

def decode_burp_data(encoded_data):
    """Decode base64 data from Burp XML file."""
    try:
        return base64.b64decode(encoded_data).decode('utf-8', errors='replace')
    except:
        return ""

def parse_headers(header_text):
    """Parse headers from text into a dictionary."""
    headers = {}
    if not header_text:
        return headers
    
    for line in header_text.split('\n'):
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value
    return headers

def get_status_code(response_data):
    """Extract HTTP status code from response."""
    if not response_data:
        return None
    
    # Look for HTTP/1.x status line
    match = re.match(r"HTTP/\d\.\d\s+(\d+)", response_data)
    if match:
        return int(match.group(1))
    return None

def analyze_cors_headers(request_headers, response_headers, status_code):
    """Analyze CORS headers for security issues."""
    issues = []
    
    # Only analyze successful responses (200 status code)
    if status_code != 200:
        return issues
    
    # Check for basic CORS headers
    if 'access-control-allow-origin' in response_headers:
        acao = response_headers['access-control-allow-origin']
        
        # Check for wildcard origin
        if acao == '*':
            issues.append("Wildcard Access-Control-Allow-Origin: *")
            
            # Check if credentials are also allowed (should never happen)
            if 'access-control-allow-credentials' in response_headers and response_headers['access-control-allow-credentials'].lower() == 'true':
                issues.append("CRITICAL: Wildcard origin with credentials allowed")
        
        # Check for origin reflection
        if 'origin' in request_headers and acao == request_headers['origin']:
            issues.append(f"Origin reflection detected: {acao}")
            
            # Check if credentials are also allowed with reflection
            if 'access-control-allow-credentials' in response_headers and response_headers['access-control-allow-credentials'].lower() == 'true':
                issues.append("CRITICAL: Reflected origin with credentials allowed")
    
    # Check for overly permissive CORS methods
    if 'access-control-allow-methods' in response_headers:
        methods = response_headers['access-control-allow-methods']
        if '*' in methods or all(m in methods for m in ['GET', 'POST', 'PUT', 'DELETE']):
            issues.append(f"Permissive methods allowed: {methods}")
    
    # Check for overly permissive CORS headers
    if 'access-control-allow-headers' in response_headers and '*' in response_headers['access-control-allow-headers']:
        issues.append("Wildcard Access-Control-Allow-Headers: *")
    
    return issues

def scan_burp_xml(xml_file):
    """Scan Burp XML file for CORS headers."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return
    
    print("\n=== CORS Header Analysis Report (200 Responses Only) ===\n")
    
    # Counter for vulnerable endpoints
    vulnerable_count = 0
    total_endpoints = 0
    
    # Iterate through items
    for item in root.findall('.//item'):
        url_element = item.find('./url')
        if url_element is None:
            continue
        
        url = url_element.text
        total_endpoints += 1
        
        # Get request and response
        request_b64 = item.find('./request')
        response_b64 = item.find('./response')
        
        if request_b64 is None or response_b64 is None:
            continue
        
        request_data = decode_burp_data(request_b64.text)
        response_data = decode_burp_data(response_b64.text)
        
        # Get status code
        status_code = get_status_code(response_data)
        if status_code is None:
            continue
        
        # Split headers from body
        try:
            request_headers_text = request_data.split('\r\n\r\n')[0]
            response_headers_text = response_data.split('\r\n\r\n')[0]
        except:
            continue
        
        # Parse headers
        request_headers = parse_headers(request_headers_text)
        response_headers = parse_headers(response_headers_text)
        
        # Analyze CORS headers (only for 200 responses)
        issues = analyze_cors_headers(request_headers, response_headers, status_code)
        
        if issues:
            vulnerable_count += 1
            print(f"URL: {url}")
            print(f"Status Code: {status_code}")
            print("Issues found:")
            for issue in issues:
                print(f"  - {issue}")
            print("\nRequest headers:")
            for key, value in request_headers.items():
                if key in ['origin', 'host', 'referer']:
                    print(f"  {key}: {value}")
            print("\nResponse CORS headers:")
            for key, value in response_headers.items():
                if 'access-control' in key:
                    print(f"  {key}: {value}")
            print("\n" + "-"*50 + "\n")
    
    print(f"Scan complete. Found {vulnerable_count} endpoints with potential CORS issues out of {total_endpoints} total endpoints.")
    if vulnerable_count > 0:
        print("\nNext steps:")
        print("1. Create a test HTML page using the CORS POC template")
        print("2. Replace the target URL with the vulnerable endpoint(s)")
        print("3. Host the page using Python's HTTP server")
        print("4. Test to confirm exploitability")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_cors.py <burp_xml_file>")
        sys.exit(1)
    
    scan_burp_xml(sys.argv[1])
