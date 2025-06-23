"""
Directory and Path Finder Module

This module scans HTTP responses for paths, directories, and file references
that could potentially be used for further reconnaissance or exploitation.
It identifies leaked file paths, directory structures, and potential sensitive files.
"""

import re
import tkinter as tk
from tkinter import ttk
from urllib.parse import urljoin, urlparse
import json
import os
import time

# Module metadata
MODULE_NAME = "Path Finder"
MODULE_DESCRIPTION = "Detects paths, directories, and file references in HTTP responses"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"

# Configuration
config = {
    "scan_request": True,
    "scan_response": True,
    "scan_headers": True,
    "scan_body": True,
    "extract_hrefs": True,
    "extract_src_attrs": True,
    "extract_absolute_paths": True,
    "extract_relative_paths": True,
    "extract_file_extensions": True,
    "ignore_common_exts": True,
    "interesting_extensions": [
        "php", "asp", "aspx", "jsp", "jspx", "do", "action", "json", "xml", 
        "conf", "config", "cfg", "ini", "env", "log", "bak", "backup", "old",
        "txt", "sql", "db", "mdb", "sqlite", "csv", "xls", "xlsx", "doc", "docx",
        "pdf", "zip", "tar", "gz", "7z", "rar", "war", "jar", "pem", "key", "cert"
    ],
    "interesting_directory_names": [
        "admin", "administrator", "backup", "backups", "bak", "beta", "conf", "config",
        "configs", "configuration", "data", "database", "db", "deploy", "dev", "development",
        "includes", "internal", "log", "logs", "private", "prod", "production", "secret",
        "secrets", "secure", "security", "server", "servers", "staging", "test", "tests",
        "tmp", "temp", "upload", "uploads", "user", "users", "web", "www", "wwwroot",
        "api", "v1", "v2", "v3", "svn", "git", "cvs", "jenkins", "jira", "confluence",
        "wp-admin", "wp-content", "wp-includes"
    ],
    "potential_sensitive_files": [
        ".git/HEAD", ".git/config", ".svn/entries", ".env", ".htaccess", "web.config",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
        "phpinfo.php", "info.php", "server-status", "server-info", "elmah.axd",
        "trace.axd", "webpack.config.js", "package.json", "config.json", "settings.json",
        "wp-config.php", "wp-config.bak", "config.php.bak", ".bash_history", ".zsh_history",
        "id_rsa", "id_dsa", "authorized_keys", "known_hosts"
    ],
    "common_extensions_to_ignore": [
        "js", "css", "html", "htm", "png", "jpg", "jpeg", "gif", "svg", "webp", 
        "ico", "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3", "wav"
    ],
    "custom_patterns": []
}

# Regular expression patterns for path detection
PATH_PATTERNS = [
    # Common absolute paths (Unix/Linux)
    r'(?:^|[^\w/-])(\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+)(?:[^\w/]|$)',
    # Common absolute paths (Windows)
    r'(?:^|[^\w:\\-])([A-Z]:\\(?:[a-zA-Z0-9_-]+\\)*[a-zA-Z0-9_.-]+)(?:[^\w\\]|$)',
    # Relative web paths
    r'(?:^|[^\w/-])((?:\.\.\/|\.\/)?(?:[a-zA-Z0-9_-]+\/)+[a-zA-Z0-9_.-]+)(?:[^\w/]|$)',
    # URLs with path components
    r'(?:https?://[a-zA-Z0-9.-]+)(/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+)',
    # File paths in common attributes
    r'(?:src|href|action|data|url|path|include|require)["\']?\s*[:=]\s*["\']?([^"\'<>\s\)]+)["\']?',
]

# Regular expressions for file extensions
EXTENSION_PATTERN = r'\.([a-zA-Z0-9]{1,10})(?:["\'\s&?#]|$)'


def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
        
    # Create scrollable canvas for all the options
    canvas = tk.Canvas(frame)
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Create configuration widgets
    ttk.Label(scrollable_frame, text="Scan Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    row = 1
    
    # Checkboxes for scan targets
    for option, label in [
        ("scan_request", "Scan Request"),
        ("scan_response", "Scan Response"),
        ("scan_headers", "Scan Headers"),
        ("scan_body", "Scan Body"),
        ("extract_hrefs", "Extract href Attributes"),
        ("extract_src_attrs", "Extract src Attributes"),
        ("extract_absolute_paths", "Extract Absolute Paths"),
        ("extract_relative_paths", "Extract Relative Paths"),
        ("extract_file_extensions", "Extract File Extensions"),
        ("ignore_common_exts", "Ignore Common Extensions")
    ]:
        var = tk.BooleanVar(value=config[option])
        ttk.Checkbutton(scrollable_frame, text=label, variable=var,
                      command=lambda opt=option, v=var: update_config(opt, v.get())).grid(row=row, column=0, sticky="w")
        row += 1
    
    # Interesting extensions section
    ttk.Label(scrollable_frame, text="Interesting File Extensions", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    extensions_frame = ttk.Frame(scrollable_frame)
    extensions_frame.grid(row=row, column=0, columnspan=2, sticky="we")
    
    ext_listbox = tk.Listbox(extensions_frame, width=30, height=10)
    ext_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ext_scrollbar = ttk.Scrollbar(extensions_frame, orient=tk.VERTICAL, command=ext_listbox.yview)
    ext_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    ext_listbox['yscrollcommand'] = ext_scrollbar.set
    
    # Populate listbox
    for ext in config["interesting_extensions"]:
        ext_listbox.insert(tk.END, ext)
        
    row += 1
    
    # Add/remove extension controls
    ext_control_frame = ttk.Frame(scrollable_frame)
    ext_control_frame.grid(row=row, column=0, columnspan=2, sticky="we", pady=5)
    
    ext_entry = ttk.Entry(ext_control_frame, width=20)
    ext_entry.pack(side=tk.LEFT, padx=(0, 5))
    
    def add_extension():
        ext = ext_entry.get().strip().lower()
        if ext and ext not in config["interesting_extensions"]:
            config["interesting_extensions"].append(ext)
            ext_listbox.insert(tk.END, ext)
            ext_entry.delete(0, tk.END)
    
    def remove_extension():
        selection = ext_listbox.curselection()
        if selection:
            index = selection[0]
            ext = ext_listbox.get(index)
            ext_listbox.delete(index)
            config["interesting_extensions"].remove(ext)
    
    ttk.Button(ext_control_frame, text="Add", command=add_extension).pack(side=tk.LEFT, padx=5)
    ttk.Button(ext_control_frame, text="Remove", command=remove_extension).pack(side=tk.LEFT)
    
    row += 1
    
    # Interesting directories section
    ttk.Label(scrollable_frame, text="Interesting Directory Names", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    dir_frame = ttk.Frame(scrollable_frame)
    dir_frame.grid(row=row, column=0, columnspan=2, sticky="we")
    
    dir_listbox = tk.Listbox(dir_frame, width=30, height=10)
    dir_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    dir_scrollbar = ttk.Scrollbar(dir_frame, orient=tk.VERTICAL, command=dir_listbox.yview)
    dir_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    dir_listbox['yscrollcommand'] = dir_scrollbar.set
    
    # Populate listbox
    for dirname in config["interesting_directory_names"]:
        dir_listbox.insert(tk.END, dirname)
        
    row += 1
    
    # Add/remove directory controls
    dir_control_frame = ttk.Frame(scrollable_frame)
    dir_control_frame.grid(row=row, column=0, columnspan=2, sticky="we", pady=5)
    
    dir_entry = ttk.Entry(dir_control_frame, width=20)
    dir_entry.pack(side=tk.LEFT, padx=(0, 5))
    
    def add_directory():
        dirname = dir_entry.get().strip().lower()
        if dirname and dirname not in config["interesting_directory_names"]:
            config["interesting_directory_names"].append(dirname)
            dir_listbox.insert(tk.END, dirname)
            dir_entry.delete(0, tk.END)
    
    def remove_directory():
        selection = dir_listbox.curselection()
        if selection:
            index = selection[0]
            dirname = dir_listbox.get(index)
            dir_listbox.delete(index)
            config["interesting_directory_names"].remove(dirname)
    
    ttk.Button(dir_control_frame, text="Add", command=add_directory).pack(side=tk.LEFT, padx=5)
    ttk.Button(dir_control_frame, text="Remove", command=remove_directory).pack(side=tk.LEFT)
    
    row += 1
    
    # Custom pattern entry
    ttk.Label(scrollable_frame, text="Custom Patterns", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    pattern_entry = ttk.Entry(scrollable_frame, width=50)
    pattern_entry.grid(row=row, column=0, sticky="we", padx=(0, 5), pady=5)
    
    def add_custom_pattern():
        pattern = pattern_entry.get().strip()
        if pattern and pattern not in config["custom_patterns"]:
            config["custom_patterns"].append(pattern)
            pattern_listbox.insert(tk.END, pattern)
            pattern_entry.delete(0, tk.END)
    
    ttk.Button(scrollable_frame, text="Add Pattern", command=add_custom_pattern).grid(row=row, column=1, sticky="w")
    row += 1
    
    # List of custom patterns
    pattern_frame = ttk.Frame(scrollable_frame)
    pattern_frame.grid(row=row, column=0, columnspan=2, sticky="we", pady=5)
    
    pattern_listbox = tk.Listbox(pattern_frame, width=50, height=5)
    pattern_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    pattern_scrollbar = ttk.Scrollbar(pattern_frame, orient=tk.VERTICAL, command=pattern_listbox.yview)
    pattern_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    pattern_listbox['yscrollcommand'] = pattern_scrollbar.set
    
    # Populate custom patterns
    for pattern in config["custom_patterns"]:
        pattern_listbox.insert(tk.END, pattern)
    
    row += 1
    
    # Remove custom pattern button
    def remove_custom_pattern():
        selection = pattern_listbox.curselection()
        if selection:
            index = selection[0]
            pattern = pattern_listbox.get(index)
            pattern_listbox.delete(index)
            config["custom_patterns"].remove(pattern)
    
    ttk.Button(scrollable_frame, text="Remove Selected Pattern", 
              command=remove_custom_pattern).grid(row=row, column=0, sticky="w", pady=5)
    
    row += 1
    
    # XML Processing Section
    ttk.Label(scrollable_frame, text="XML Processing", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    xml_frame = ttk.Frame(scrollable_frame)
    xml_frame.grid(row=row, column=0, columnspan=2, sticky="we", pady=5)
    
    ttk.Label(xml_frame, text="XML File:").pack(side=tk.LEFT, padx=(0, 5))
    xml_file_entry = ttk.Entry(xml_frame, width=30)
    xml_file_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
    
    def browse_xml_file():
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select XML File",
            filetypes=(("XML files", "*.xml"), ("All files", "*.*"))
        )
        if filename:
            xml_file_entry.delete(0, tk.END)
            xml_file_entry.insert(0, filename)
    
    ttk.Button(xml_frame, text="Browse...", command=browse_xml_file).pack(side=tk.LEFT)
    
    row += 1
    
    # Base URL for relative URLs in XML
    base_url_frame = ttk.Frame(scrollable_frame)
    base_url_frame.grid(row=row, column=0, columnspan=2, sticky="we", pady=5)
    
    ttk.Label(base_url_frame, text="Base URL:").pack(side=tk.LEFT, padx=(0, 5))
    base_url_entry = ttk.Entry(base_url_frame, width=30)
    base_url_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
    
    row += 1
    
    # Process XML button
    def process_xml():
        xml_file = xml_file_entry.get().strip()
        base_url = base_url_entry.get().strip()
        
        if not xml_file:
            import tkinter.messagebox as messagebox
            messagebox.showerror("Error", "Please select an XML file")
            return
            
        xml_data = parse_xml_file(xml_file)
        if not xml_data:
            import tkinter.messagebox as messagebox
            messagebox.showerror("Error", "Failed to parse XML file or file is empty")
            return
            
        results = process_xml_dataset(xml_data, base_url)
        
        # Display or save results
        from tkinter import filedialog
        output_file = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if output_file:
            format = "json" if output_file.endswith(".json") else "txt"
            export_results(results, format, output_file)
            import tkinter.messagebox as messagebox
            messagebox.showinfo("Success", f"Results saved to {output_file}")
        
    ttk.Button(scrollable_frame, text="Process XML File", 
              command=process_xml).grid(row=row, column=0, sticky="w", pady=5)
    
def update_config(key, value):
    """Update a configuration value"""
    config[key] = value


def analyze(request_data, response_data, url, aggregate_results=None):
    """
    Analyze the request and response for paths, directories, and file references
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data
        url (str): The full URL
        aggregate_results (dict, optional): Existing results to merge with
        
    Returns:
        dict: Analysis results
    """
    if aggregate_results:
        results = aggregate_results
        # Update URL only if it's the base analysis (not combining from multiple sources)
        if "aggregate_source_count" not in results:
            results["aggregate_source_count"] = 0
            results["source_urls"] = []
        
        results["aggregate_source_count"] += 1
        if url not in results["source_urls"]:
            results["source_urls"].append(url)
    else:
        results = {
            "url": url,
            "base_url": get_base_url(url),
            "paths": [],
            "directories": [],
            "files": {
                "by_extension": {},
                "potentially_sensitive": []
            },
            "findings": [],
            "stats": {
                "total_paths": 0,
                "total_directories": 0,
                "total_files": 0,
                "interesting_extensions": 0
            },
            "source_urls": [url],
            "aggregate_source_count": 1
        }
    
    # Process request if enabled
    if config["scan_request"]:
        process_request(request_data, results)
    
    # Process response if enabled
    if config["scan_response"]:
        process_response(response_data, results)
    
    # Process the current URL
    process_url(url, results)
    
    # Check for potentially sensitive files
    check_sensitive_files(results)
    
    # Update stats
    results["stats"]["total_paths"] = len(results["paths"])
    results["stats"]["total_directories"] = len(results["directories"])
    results["stats"]["total_files"] = sum(len(files) for files in results["files"]["by_extension"].values())
    results["stats"]["interesting_extensions"] = sum(
        len(files) for ext, files in results["files"]["by_extension"].items() 
        if ext in config["interesting_extensions"]
    )
    
    return results


def process_request(request_data, results):
    """
    Process request data to extract paths and files
    
    Args:
        request_data (dict): The request data
        results (dict): Results to update
    """
    # Extract from headers if enabled
    if config["scan_headers"] and "headers" in request_data:
        for header_name, header_value in request_data["headers"].items():
            extract_paths_from_text(header_value, results, f"request:header:{header_name}")
    
    # Extract from body if enabled
    if config["scan_body"] and "body" in request_data and request_data["body"]:
        extract_paths_from_text(request_data["body"], results, "request:body")
    
    # Extract from path
    if "path" in request_data and request_data["path"]:
        process_single_path(request_data["path"], results, "request:path")


def process_response(response_data, results):
    """
    Process response data to extract paths and files
    
    Args:
        response_data (dict): The response data
        results (dict): Results to update
    """
    # Extract from headers if enabled
    if config["scan_headers"] and "headers" in response_data:
        for header_name, header_value in response_data["headers"].items():
            extract_paths_from_text(header_value, results, f"response:header:{header_name}")
    
    # Extract from body if enabled
    if config["scan_body"] and "body" in response_data and response_data["body"]:
        body = response_data["body"]
        
        # Extract paths from text
        extract_paths_from_text(body, results, "response:body")
        
        # Extract special HTML attributes if enabled
        if config["extract_hrefs"]:
            extract_html_attributes(body, "href", results)
        
        if config["extract_src_attrs"]:
            extract_html_attributes(body, "src", results)
            
        # Also try other common attributes
        for attr in ["action", "data", "url", "data-url", "data-src"]:
            extract_html_attributes(body, attr, results)


def process_url(url, results):
    """
    Process the current URL to extract paths and directories
    
    Args:
        url (str): The URL to process
        results (dict): Results to update
    """
    parsed = urlparse(url)
    
    # Process the path
    if parsed.path:
        process_single_path(parsed.path, results, "current_url")


def process_single_path(path, results, source="unknown"):
    """
    Process a single path to extract directories and files
    
    Args:
        path (str): The path to process
        results (dict): Results to update
        source (str): The source of the path
    """
    # Clean the path
    path = path.strip()
    
    # Skip empty paths
    if not path or path == "/":
        return
    
    # Add to paths if not already there
    if path not in results["paths"]:
        results["paths"].append(path)
        
        # Add a finding
        results["findings"].append({
            "type": "path",
            "path": path,
            "source": source
        })
    
    # Extract directory names
    path_parts = path.split("/")
    current_dir = ""
    
    for part in path_parts:
        if not part:  # Skip empty parts
            continue
            
        # Check if this looks like a file (has extension)
        if "." in part and not part.startswith("."):
            filename = part
            extension = part.split(".")[-1].lower()
            
            # Extract file if enabled and not ignored
            if config["extract_file_extensions"]:
                if not (config["ignore_common_exts"] and extension in config["common_extensions_to_ignore"]):
                    if extension not in results["files"]["by_extension"]:
                        results["files"]["by_extension"][extension] = []
                    
                    file_path = f"{current_dir}/{filename}" if current_dir else f"/{filename}"
                    
                    if file_path not in results["files"]["by_extension"][extension]:
                        results["files"]["by_extension"][extension].append(file_path)
                        
                        # Add a finding if it's an interesting extension
                        if extension in config["interesting_extensions"]:
                            results["findings"].append({
                                "type": "interesting_file",
                                "path": file_path,
                                "extension": extension,
                                "source": source
                            })
        else:
            # It's a directory
            if current_dir:
                current_dir += f"/{part}"
            else:
                current_dir = f"/{part}"
                
            if current_dir not in results["directories"]:
                results["directories"].append(current_dir)
                
                # Add a finding if it's an interesting directory
                if part.lower() in config["interesting_directory_names"]:
                    results["findings"].append({
                        "type": "interesting_directory",
                        "path": current_dir,
                        "name": part,
                        "source": source
                    })


def extract_paths_from_text(text, results, source="unknown"):
    """
    Extract paths from text using regular expressions
    
    Args:
        text (str): The text to extract paths from
        results (dict): Results to update
        source (str): The source of the text
    """
    # Ensure text is a string
    if not isinstance(text, str):
        return
    
    # Process with built-in patterns
    for pattern in PATH_PATTERNS:
        matches = re.finditer(pattern, text)
        for match in matches:
            path = match.group(1).strip()
            
            # Skip empty paths or common single character paths
            if not path or path in ["/", ".", "*"]:
                continue
                
            # Determine if it's a relative path, absolute path, or URL
            if path.startswith(("http://", "https://")):
                # It's a URL, extract the path part
                parsed = urlparse(path)
                process_single_path(parsed.path, results, f"{source}:url")
            elif config["extract_absolute_paths"] and path.startswith(("/", "\\")):
                # Absolute path
                process_single_path(path, results, f"{source}:absolute_path")
            elif config["extract_relative_paths"]:
                # Relative path
                process_single_path(path, results, f"{source}:relative_path")
    
    # Process custom patterns
    for pattern in config["custom_patterns"]:
        try:
            matches = re.finditer(pattern, text)
            for match in matches:
                # Try to get the first group, or the entire match if no groups
                path = match.group(1) if match.groups() else match.group(0)
                path = path.strip()
                
                # Skip empty paths
                if not path:
                    continue
                    
                process_single_path(path, results, f"{source}:custom_pattern")
        except re.error:
            # Skip invalid patterns
            pass
    
    # Extract file extensions
    if config["extract_file_extensions"]:
        matches = re.finditer(EXTENSION_PATTERN, text)
        for match in matches:
            extension = match.group(1).lower()
            
            # Skip if it's in the ignore list
            if config["ignore_common_exts"] and extension in config["common_extensions_to_ignore"]:
                continue
                
            # Add to the extensions list
            if extension not in results["files"]["by_extension"]:
                results["files"]["by_extension"][extension] = []
            
            # Since we just found the extension, we don't have the full path
            # We just count it as a discovered extension
            results["files"]["by_extension"][extension].append(f"[found in {source}]")


def extract_html_attributes(html, attribute, results):
    """
    Extract paths from specific HTML attributes
    
    Args:
        html (str): The HTML content
        attribute (str): The attribute to extract (e.g., "href", "src")
        results (dict): Results to update
    """
    # Simple regex to extract attribute values
    pattern = f'\\s{attribute}=["\']([^"\'\\s]+)["\']'
    matches = re.finditer(pattern, html)
    
    for match in matches:
        value = match.group(1).strip()
        
        # Skip empty values and JavaScript/data URLs
        if not value or value.startswith(("javascript:", "data:", "#", "mailto:")):
            continue
            
        # Process the attribute value
        if value.startswith(("http://", "https://")):
            # It's a full URL
            parsed = urlparse(value)
            process_single_path(parsed.path, results, f"html:{attribute}")
        else:
            # It's a relative or absolute path
            process_single_path(value, results, f"html:{attribute}")


def check_sensitive_files(results):
    """
    Check for potentially sensitive files
    
    Args:
        results (dict): Results to update
    """
    base_url = results["base_url"]
    
    for sensitive_file in config["potential_sensitive_files"]:
        # Check if we've already found it
        found = False
        
        for path in results["paths"]:
            if path.endswith(sensitive_file) or path == sensitive_file:
                found = True
                break
                
        if not found:
            # We can't confirm it exists, but it's worth checking
            full_url = urljoin(base_url, sensitive_file)
            
            # Add to potentially sensitive files
            if sensitive_file not in results["files"]["potentially_sensitive"]:
                results["files"]["potentially_sensitive"].append(sensitive_file)
                
                # Add a finding
                results["findings"].append({
                    "type": "potential_sensitive_file",
                    "path": sensitive_file,
                    "check_url": full_url,
                    "confirmed": False
                })


def get_base_url(url):
    """
    Get the base URL (scheme + netloc)
    
    Args:
        url (str): The full URL
        
    Returns:
        str: The base URL
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def parse_xml_file(file_path):
    """
    Parse an XML file containing HTTP responses
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        list: List of dictionaries with request, response data and URLs
    """
    import xml.etree.ElementTree as ET
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        items = []
        for item in root.findall('./item'):
            url_elem = item.find('url')
            request_elem = item.find('request')
            response_elem = item.find('response')
            
            url = url_elem.text if url_elem is not None else ""
            
            request_data = {}
            if request_elem is not None:
                headers_elem = request_elem.find('headers')
                body_elem = request_elem.find('body')
                path_elem = request_elem.find('path')
                
                headers = {}
                if headers_elem is not None:
                    for header in headers_elem.findall('header'):
                        name = header.get('name')
                        value = header.text
                        if name and value:
                            headers[name] = value
                
                request_data = {
                    "headers": headers,
                    "body": body_elem.text if body_elem is not None else "",
                    "path": path_elem.text if path_elem is not None else ""
                }
            
            response_data = {}
            if response_elem is not None:
                headers_elem = response_elem.find('headers')
                body_elem = response_elem.find('body')
                status_code_elem = response_elem.find('status_code')
                
                headers = {}
                if headers_elem is not None:
                    for header in headers_elem.findall('header'):
                        name = header.get('name')
                        value = header.text
                        if name and value:
                            headers[name] = value
                
                response_data = {
                    "headers": headers,
                    "body": body_elem.text if body_elem is not None else "",
                    "status_code": status_code_elem.text if status_code_elem is not None else "200"
                }
            
            items.append({
                "url": url,
                "request_data": request_data,
                "response_data": response_data
            })
        
        return items
    except Exception as e:
        print(f"Error parsing XML file: {str(e)}")
        return []

def process_xml_dataset(xml_data, base_url=None):
    """
    Process all items in the XML dataset and collate results
    
    Args:
        xml_data (list): List of items from the XML file
        base_url (str, optional): Base URL to use if URLs are relative
        
    Returns:
        dict: Combined analysis results
    """
    if not xml_data:
        return None
    
    combined_results = None
    
    for item in xml_data:
        url = item["url"]
        
        # If URL is relative and base_url is provided, join them
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        
        # Skip items without a valid URL
        if not url:
            continue
        
        # Analyze this item
        results = analyze(
            item["request_data"], 
            item["response_data"], 
            url, 
            aggregate_results=combined_results
        )
        
        # For the first item, initialize combined_results
        if combined_results is None:
            combined_results = results
        
    return combined_results or {}

def add_command_line_arguments(parser):
    """
    Add command line arguments
    
    Args:
        parser: ArgumentParser instance
    """
    # XML processing arguments
    parser.add_argument("--xml", "-x", dest="xml_file",
                      help="Path to XML file containing multiple HTTP responses")
    parser.add_argument("--base-url", "-b", dest="base_url",
                      help="Base URL to use for relative URLs in the XML file")
    
    # Result storage path arguments
    parser.add_argument("--base-path", dest="base_path",
                      help="Base path for storing results")
    parser.add_argument("--target", dest="target",
                      help="Target identifier")
    parser.add_argument("--auth-mode", dest="auth_mode", choices=["Auth", "Raw"],
                      help="Authentication mode (Auth or Raw)")
    parser.add_argument("--category", dest="category",
                      help="Test category")
    parser.add_argument("--test-type", dest="test_type",
                      help="Type of test being performed")
    
    # Output format options
    parser.add_argument("--output", "-o", dest="output_file",
                      help="Output file for the results (default: auto-generated path)")
    parser.add_argument("--format", "-f", dest="output_format", choices=["json", "txt"],
                      default="json", help="Output format (default: json)")

def export_results(results, output_format="json", output_file=None, 
                  base_path=None, target=None, auth_mode=None, category=None, test_type=None):
    """
    Export analysis results to a file or stdout
    
    Args:
        results (dict): Analysis results
        output_format (str): Output format (json or txt)
        output_file (str, optional): Explicit output file path
        base_path (str, optional): Base directory for results
        target (str, optional): Target identifier
        auth_mode (str, optional): Authentication mode
        category (str, optional): Category
        test_type (str, optional): Type of test
    """
    # Format the results
    if output_format == "json":
        output = json.dumps(results, indent=2)
    else:
        # Text format
        output = format_results_as_text(results)
    
    # If we have all the path components, build a structured path
    if base_path and target and auth_mode and category and test_type:
        # Build the path
        results_dir = build_results_path(base_path, target, auth_mode, category, test_type)
        
        # If no explicit output file is provided, use a default name
        if not output_file:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            output_file = os.path.join(results_dir, f"results-{timestamp}.{output_format}")
    
    # Write to file or stdout
    if output_file:
        # Ensure the parent directory exists
        parent_dir = os.path.dirname(output_file)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
            
        with open(output_file, "w") as f:
            f.write(output)
        print(f"Results written to {output_file}")
    else:
        print(output)

def format_results_as_text(results):
    """
    Format results as plain text
    
    Args:
        results (dict): Analysis results
        
    Returns:
        str: Formatted text
    """
    text = []
    text.append("PATH FINDER ANALYSIS RESULTS")
    text.append("=" * 40)
    text.append(f"URL: {results['url']}")
    text.append(f"Base URL: {results['base_url']}")
    text.append("")
    
    text.append("STATISTICS")
    text.append("-" * 40)
    text.append(f"Total Paths: {results['stats']['total_paths']}")
    text.append(f"Total Directories: {results['stats']['total_directories']}")
    text.append(f"Total Files: {results['stats']['total_files']}")
    text.append(f"Interesting Extensions: {results['stats']['interesting_extensions']}")
    text.append("")
    
    text.append("FINDINGS")
    text.append("-" * 40)
    for finding in results["findings"]:
        text.append(f"Type: {finding['type']}")
        text.append(f"Path: {finding.get('path', 'N/A')}")
        for key, value in finding.items():
            if key not in ["type", "path"]:
                text.append(f"{key.capitalize()}: {value}")
        text.append("")
    
    return "\n".join(text)

def build_results_path(base_path, target, auth_mode, category, test_type):
    """
    Build the path for saving results based on parameters
    
    Args:
        base_path (str): Base directory path
        target (str): Target name/identifier
        auth_mode (str): Authentication mode ("Auth" or "Raw")
        category (str): Test category
        test_type (str): Type of test
        
    Returns:
        str: Full path for results directory
    """
    # Sanitize path components to handle spaces and special characters safely
    # We'll preserve spaces but replace characters that are problematic in file paths
    
    def sanitize_path_component(component):
        # Replace characters that are problematic in file paths with underscores
        problematic_chars = '<>:"|?*'
        for char in problematic_chars:
            component = component.replace(char, '_')
        return component
    
    # Sanitize each component
    target = sanitize_path_component(target)
    # Auth mode should only be "Auth" or "Raw"
    auth_mode = "Auth" if auth_mode.lower() == "auth" else "Raw"
    category = sanitize_path_component(category)
    test_type = sanitize_path_component(test_type)
    
    # Build the path
    result_path = os.path.join(
        base_path,
        target,
        auth_mode,
        category,
        test_type,
        "Results"
    )
    
    # Ensure the directory exists
    ensure_directory_exists(result_path)
    
    return result_path

def ensure_directory_exists(directory_path):
    """
    Create directory and any parent directories if they don't exist
    
    Args:
        directory_path (str): Path to create
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)


# If this module is run directly, provide a simple test
if __name__ == "__main__":
    import argparse
    import os
    import time
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Directory and Path Finder Module")
    add_command_line_arguments(parser)
    args = parser.parse_args()
    
    # Process the input and generate results
    if args.xml_file:
        # XML processing
        print(f"Processing XML file: {args.xml_file}")
        xml_data = parse_xml_file(args.xml_file)
        if xml_data:
            results = process_xml_dataset(xml_data, args.base_url)
        else:
            print("Error: Failed to parse XML file or file is empty")
            exit(1)
    else:
        # Test data - use the same as before for backward compatibility
        print("No XML file provided. Using default test data.")
        test_response = {
            "status_code": "200",
            "headers": {
                "Server": "Apache/2.4.49",
                "X-Powered-By": "PHP/7.4.11",
                "Content-Type": "text/html; charset=UTF-8",
                "Set-Cookie": "PHPSESSID=abc123; path=/admin; HttpOnly"
            },
            "body": """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Test Page</title>
                <link rel="stylesheet" href="/css/styles.css">
                <script src="/js/jquery-3.5.1.min.js"></script>
                <script src="/js/app.js?v=1.2.3"></script>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to My Website</h1>
                    <a href="/admin/login.php">Admin Login</a>
                    <a href="/products/index.php">Products</a>
                    <a href="/files/brochure.pdf">Download Brochure</a>
                    <img src="/images/logo.png" alt="Logo">
                    <img src="/uploads/user/profile.jpg" alt="Profile">
                    
                    <!-- Configuration path: /var/www/html/config/database.php -->
                    <!-- TODO: Fix the backup script at /home/www-data/backup.sh -->
                    
                    <form action="/api/v1/contact" method="post">
                        <input type="text" name="name">
                        <input type="email" name="email">
                        <button type="submit">Send</button>
                    </form>
                    
                    <script>
                    const apiUrl = '/api/v2/products';
                    const configPath = '/config/app.json';
                    </script>
                </div>
            </body>
            </html>
            """
        }
        
        # Test the analyze function
        results = analyze({}, test_response, "https://example.com/index.php")
    
    # Export the results - MOVED OUTSIDE of the if/else block to handle both cases
    if args.base_path and args.target and args.auth_mode and args.category and args.test_type:
        # Use structured path
        print(f"Saving results using structured path: {args.base_path}/{args.target}/{args.auth_mode}/{args.category}/{args.test_type}/Results/")
        export_results(
            results=results,
            output_format=args.output_format,
            output_file=args.output_file,
            base_path=args.base_path,
            target=args.target,
            auth_mode=args.auth_mode,
            category=args.category,
            test_type=args.test_type
        )
    else:
        # Use simple output
        print("Using simple output (no structured path provided)")
        export_results(
            results=results,
            output_format=args.output_format,
            output_file=args.output_file
        )
