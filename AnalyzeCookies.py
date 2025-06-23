import xml.etree.ElementTree as ET
import base64
import sys
import re
import json

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

def extract_response_body(response_data):
    """Extract the response body from the full response."""
    if not response_data:
        return ""
    
    parts = response_data.split('\r\n\r\n', 1)
    if len(parts) > 1:
        return parts[1]
    return ""

def extract_sensitive_data(body):
    """Look for patterns of sensitive data in response body."""
    sensitive_patterns = {
        'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'API Key': r'api[_-]?key[=:]\s*["\'`]?([a-zA-Z0-9]{16,64})["\'`]?',
        'Authentication Token': r'(auth|bearer|token)[=:]\s*["\'`]?([a-zA-Z0-9]{16,64})["\'`]?',
        'Session ID': r'(session|sid)[=:]\s*["\'`]?([a-zA-Z0-9]{16,64})["\'`]?',
        'User Credentials': r'(username|email|user|pass|password)[=:]\s*["\'`]?([^"\'`\s]{3,64})["\'`]?',
        'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
        'Social Security Number': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'
    }
    
    findings = {}
    for name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            findings[name] = matches[:3]  # Limit to 3 examples
    
    return findings

def analyze_cache_headers(url, request_headers, response_headers, response_body, status_code):
    """Analyze headers related to browser caching and storage for security issues."""
    issues = []
    
    # Only analyze successful responses
    if status_code < 200 or status_code >= 400:
        return issues
    
    # Check for missing Cache-Control header
    if 'cache-control' not in response_headers:
        issues.append({
            'severity': 'Medium',
            'issue': 'Missing Cache-Control header',
            'detail': 'No Cache-Control header specified, which may lead to unintentional caching of sensitive content'
        })
    else:
        cache_control = response_headers['cache-control'].lower()
        
        # Check for permissive Cache-Control directives
        if 'private' not in cache_control and 'no-store' not in cache_control:
            if any(term in url.lower() for term in ['login', 'auth', 'account', 'profile', 'admin', 'dashboard', 'payment']):
                issues.append({
                    'severity': 'High',
                    'issue': 'Sensitive page without proper cache restrictions',
                    'detail': f'Cache-Control value "{response_headers["cache-control"]}" may allow caching of sensitive content'
                })
        
        # Check for very long cache expiration
        if 'max-age=' in cache_control:
            try:
                max_age = int(re.search(r'max-age=(\d+)', cache_control).group(1))
                if max_age > 86400:  # More than 24 hours
                    issues.append({
                        'severity': 'Low',
                        'issue': 'Long cache expiration',
                        'detail': f'Cache expiration set to {max_age} seconds ({max_age/86400:.1f} days)'
                    })
            except:
                pass
    
    # Check for missing Pragma: no-cache
    if 'pragma' not in response_headers and 'cache-control' not in response_headers:
        issues.append({
            'severity': 'Low',
            'issue': 'Missing Pragma: no-cache',
            'detail': 'For backwards compatibility with HTTP/1.0 caches, consider adding Pragma: no-cache'
        })
    
    # Check for sensitive information in the response that might be cached
    sensitive_data = extract_sensitive_data(response_body)
    if sensitive_data:
        # Higher severity if cache headers are missing or permissive
        severity = 'Critical' if 'cache-control' not in response_headers or \
                              ('no-store' not in response_headers.get('cache-control', '').lower() and \
                               'private' not in response_headers.get('cache-control', '').lower()) \
                            else 'Medium'
        
        issues.append({
            'severity': severity,
            'issue': 'Sensitive data potentially cached',
            'detail': f'Detected potential {", ".join(sensitive_data.keys())} that may be cached by the browser'
        })
    
    # Check for Storage-* headers (HTML5 storage configurations)
    storage_headers = [h for h in response_headers if h.startswith('storage-')]
    if storage_headers:
        for header in storage_headers:
            issues.append({
                'severity': 'Info',
                'issue': f'Custom storage header found: {header}',
                'detail': f'Value: {response_headers[header]}'
            })
    
    # Check for Set-Cookie headers without proper attributes
    if 'set-cookie' in response_headers:
        cookies = response_headers['set-cookie'].split(', ')
        for cookie in cookies:
            if 'httponly' not in cookie.lower():
                issues.append({
                    'severity': 'Medium',
                    'issue': 'Cookie without HttpOnly flag',
                    'detail': f'Cookie vulnerable to XSS attacks: {cookie.split(";")[0]}'
                })
            if 'secure' not in cookie.lower() and url.startswith('https'):
                issues.append({
                    'severity': 'Medium',
                    'issue': 'Cookie without Secure flag',
                    'detail': f'Cookie may be transmitted over insecure connections: {cookie.split(";")[0]}'
                })
            if 'samesite' not in cookie.lower():
                issues.append({
                    'severity': 'Low',
                    'issue': 'Cookie without SameSite attribute',
                    'detail': f'Cookie may be vulnerable to CSRF attacks: {cookie.split(";")[0]}'
                })
            
            # Check for sensitive data in cookie names
            cookie_name = cookie.split('=')[0].strip()
            if any(term in cookie_name.lower() for term in ['session', 'auth', 'token', 'id', 'jwt', 'key']):
                if 'no-store' not in response_headers.get('cache-control', '').lower():
                    issues.append({
                        'severity': 'High',
                        'issue': 'Session/Auth cookie without proper cache control',
                        'detail': f'Cookie {cookie_name} may contain authentication data that could be cached'
                    })
    
    # Check for X-Frame-Options to prevent clickjacking (related to UI security)
    if 'x-frame-options' not in response_headers:
        issues.append({
            'severity': 'Low',
            'issue': 'Missing X-Frame-Options header',
            'detail': 'Page may be vulnerable to clickjacking attacks'
        })
    
    return issues

def scan_burp_xml(xml_file):
    """Scan Burp XML file for browser cache and storage security issues."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return
    
    print("\n=== Browser Cache & Storage Security Analysis Report ===\n")
    
    # Counters for reporting
    total_endpoints = 0
    vulnerable_endpoints = 0
    issues_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    # Store findings for final report
    findings = []
    
    # Iterate through items
    items = root.findall('.//item')
    total_requests = len(items)
    
    for index, item in enumerate(items, 1):
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
        
        # Extract response body
        response_body = extract_response_body(response_data)
        
        # Analyze cache and storage headers
        issues = analyze_cache_headers(url, request_headers, response_headers, response_body, status_code)
        
        if issues:
            vulnerable_endpoints += 1
            # Track issues by severity
            for issue in issues:
                issues_by_severity[issue['severity']] += 1
            
            # Store finding
            findings.append({
                'request_id': f"{index}/{total_requests}",
                'url': url,
                'status_code': status_code,
                'issues': issues,
                'cache_headers': {k: v for k, v in response_headers.items() 
                                 if k in ['cache-control', 'pragma', 'expires', 'etag', 'last-modified'] 
                                    or k.startswith('storage-')
                                    or k.startswith('x-cache')}
            })
    
    # Report summary
    print(f"Scan complete. Found {vulnerable_endpoints} endpoints with potential browser cache/storage issues out of {total_endpoints} total endpoints.")
    print("\nIssues by severity:")
    for severity, count in issues_by_severity.items():
        print(f"  {severity}: {count}")
    
    # Report detailed findings
    if findings:
        print("\n" + "="*50)
        print("DETAILED FINDINGS")
        print("="*50 + "\n")
        
        for finding in findings:
            print(f"Request ID: {finding['request_id']}")
            print(f"URL: {finding['url']}")
            print(f"Status Code: {finding['status_code']}")
            
            print("\nIssues found:")
            for issue in finding['issues']:
                print(f"  [{issue['severity']}] {issue['issue']}")
                print(f"      {issue['detail']}")
            
            print("\nRelevant headers:")
            if finding['cache_headers']:
                for key, value in finding['cache_headers'].items():
                    print(f"  {key}: {value}")
            else:
                print("  No relevant cache headers found")
            
            print("\n" + "-"*50 + "\n")
    
    # Next steps and recommendations
    print("\nNext steps and recommendations:")
    print("1. For sensitive pages (login, account settings, payments), ensure these headers are set:")
    print("   - Cache-Control: no-store, no-cache, must-revalidate, private")
    print("   - Pragma: no-cache")
    print("   - Expires: 0")
    print("2. For cookies containing authentication or session data:")
    print("   - Set HttpOnly flag to prevent JavaScript access")
    print("   - Set Secure flag to ensure transmission only over HTTPS")
    print("   - Set SameSite=Strict or SameSite=Lax to prevent CSRF attacks")
    print("3. Use the browser's developer tools to inspect each flagged endpoint:")
    print("   - In Chrome: Application tab > Storage section")
    print("   - In Firefox: Storage tab")
    print("   - Check localStorage, sessionStorage, IndexedDB, and cookies")
    print("4. Implement proper logout procedures that clear browser storage data")
    print("5. For APIs returning sensitive data, verify proper cache headers are set")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_browser_cache.py <burp_xml_file>")
        sys.exit(1)
    
    scan_burp_xml(sys.argv[1])
