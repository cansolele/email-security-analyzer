"""
Email utility functions
"""

import email
import re
import ipaddress
from typing import Dict, List, Any

from .constants import JS_PATTERNS, DEFAULT_LANGUAGE, get_text


def decode_header(header_value: str) -> str:
    """Decode email headers"""
    if not header_value:
        return ""
    
    try:
        decoded_parts = email.header.decode_header(header_value)
        decoded_string = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                if encoding:
                    decoded_string += part.decode(encoding, errors='ignore')
                else:
                    decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += str(part)
        return decoded_string.strip()
    except Exception:
        return str(header_value)


def extract_domain_from_header(header: str) -> str:
    """Extract domain from email header"""
    try:
        match = re.search(r'@([a-zA-Z0-9.-]+)', header)
        return match.group(1).lower() if match else ""
    except:
        return ""


def extract_basic_info(msg) -> Dict[str, Any]:
    """Extract basic email information"""
    from_field = msg.get('From', '')
    if from_field:
        from_field = decode_header(from_field)
        from_field = re.sub(r'[<>]', '', from_field).strip()
    
    to_field = msg.get('To', '')
    if to_field:
        to_field = decode_header(to_field)
        to_field = re.sub(r'\s+', ' ', to_field.strip())
        to_field = re.sub(r'<\s*', '', to_field)
        to_field = re.sub(r'\s*>', '', to_field)
    
    return {
        'from': from_field,
        'to': to_field,
        'subject': decode_header(msg.get('Subject', '')),
        'return_path': msg.get('Return-Path', ''),
        'message_id': msg.get('Message-ID', ''),
        'date': msg.get('Date', ''),
        'content_type': msg.get_content_type(),
        'is_multipart': msg.is_multipart()
    }


def extract_all_headers(msg) -> Dict[str, str]:
    """Extract all email headers"""
    headers = {}
    for key, value in msg.items():
        headers[key] = decode_header(value)
    return headers


def analyze_routing(msg, language: str = DEFAULT_LANGUAGE) -> List[Dict[str, Any]]:
    """Analyze email routing from Received headers"""
    received_headers = msg.get_all('Received', [])
    routing_path = []
    
    for i, received in enumerate(received_headers):
        hop_info = {
            'hop_number': i + 1,
            'raw_header': received,
            'from_host': '',
            'by_host': '',
            'ip_addresses': [],
            'timestamp': '',
            'warnings': []
        }
        
        from_match = re.search(r'from\s+([^\s\(]+)', received)
        if from_match:
            hop_info['from_host'] = from_match.group(1)
        
        by_match = re.search(r'by\s+([^\s\(]+)', received)
        if by_match:
            hop_info['by_host'] = by_match.group(1)
        
        ip_matches = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
        hop_info['ip_addresses'] = ip_matches
        
        time_match = re.search(r';.*?([A-Z][a-z]{2},.*?\+?\d{4})', received)
        if time_match:
            hop_info['timestamp'] = time_match.group(1).strip()
        
        for ip in ip_matches:
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
                hop_info['warnings'].append(get_text('suspicious_ip', language).format(ip))
        
        routing_path.append(hop_info)
    
    return routing_path


def is_suspicious_ip(ip: str) -> bool:
    """Check if IP address is suspicious"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except:
        return True


def extract_urls(content: str) -> List[Dict[str, str]]:
    """
    Extract URLs and their corresponding link texts from HTML content.
    Finds both hrefs in <a> tags and raw URLs in text, avoiding duplicates.
    """
    extracted = []
    content_for_raw_scan = content

    # Regex for <a href="..."> tags
    a_tag_pattern = re.compile(r'<a\s+[^>]*?href="([^"]*)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    
    # Use finditer to process matches and modify the content for the next step
    matches = list(a_tag_pattern.finditer(content))
    
    # To avoid messing up string indices, we replace matched parts after finding them all.
    # We replace from end to start.
    for match in reversed(matches):
        href = match.group(1).strip()
        # Remove any inner HTML tags from the link's text content
        text = re.sub('<[^<]+?>', '', match.group(2)).strip()
        
        if href:
            # Prepend to maintain original order, since we are iterating backwards
            extracted.insert(0, {'href': href, 'text': text or href})
        
        # Remove the entire <a> tag from the content to avoid re-scanning its text
        content_for_raw_scan = content_for_raw_scan[:match.start()] + content_for_raw_scan[match.end():]

    # Regex for raw http/https URLs not in an <a> tag
    raw_url_pattern = re.compile(r'https?://[^\s<>"]+[^\s<>".,]')
    
    for match in raw_url_pattern.finditer(content_for_raw_scan):
        url = match.group(0)
        # Add only if it wasn't part of an <a> tag's href attribute already
        if not any(url == item['href'] for item in extracted):
            extracted.append({'href': url, 'text': url})

    return extracted[:20]


def detect_javascript(content: str, patterns: List[str]) -> List[str]:
    """Detect JavaScript in content and return fragments, prioritizing full script tags."""
    found_fragments = set()
    
    if not patterns:
        return []
        
    # The first pattern is for <script> tags, with a capturing group for the content.
    script_pattern_str = patterns[0]
    script_pattern = re.compile(script_pattern_str, re.IGNORECASE | re.DOTALL)
    
    # 1. Extract content from all <script> tags.
    for match in script_pattern.finditer(content):
        if match.groups():
            script_content = match.group(1).strip()
            if script_content:
                found_fragments.add(script_content)

    # 2. Create a version of the content with <script> tags removed to find inline JS.
    content_without_scripts = script_pattern.sub(' ', content)
    
    # 3. Search for other inline JS patterns in the remaining content.
    other_patterns = patterns[1:]
    for pattern_str in other_patterns:
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
            for match in pattern.finditer(content_without_scripts):
                # For inline JS, extract a snippet for context.
                start = max(0, match.start() - 50)
                end = min(len(content_without_scripts), match.end() + 50)
                snippet = content_without_scripts[start:end].strip()
                if snippet:
                    found_fragments.add(snippet)
        except re.error:
            # Ignore invalid regex patterns in the constants
            continue
    
    return list(found_fragments) 