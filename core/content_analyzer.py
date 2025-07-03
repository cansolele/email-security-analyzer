"""
Content analysis module for email security analyzer
"""

import base64
import re
from typing import Dict, List, Any

from utils.constants import (HIGH_RISK_EXTENSIONS, MEDIUM_RISK_EXTENSIONS, JS_PATTERNS, 
                             MAX_CONTENT_DISPLAY, MAX_HTML_DISPLAY, DEFAULT_LANGUAGE, get_text)
from utils.email_utils import extract_urls, detect_javascript


class ContentAnalyzer:
    
    def __init__(self, language: str = DEFAULT_LANGUAGE):
        self.language = language
    
    def analyze_content(self, msg) -> Dict[str, Any]:
        """Analyze email content structure and parts"""
        analysis = {
            'parts': [],
            'total_size': 0,
            'attachments': [],
            'urls_found': [],
            'has_html': False,
            'has_javascript': False,
            'javascript_fragments': [],
            'base64_content_detected': False
        }
        
        if msg.is_multipart():
            for part in msg.walk():
                part_analysis = self._analyze_email_part(part)
                analysis['parts'].append(part_analysis)
                
                if part_analysis.get('size', 0) > 0:
                    analysis['total_size'] += part_analysis['size']
        else:
            part_analysis = self._analyze_email_part(msg)
            analysis['parts'].append(part_analysis)
            analysis['total_size'] = part_analysis.get('size', 0)
        
        for part in analysis['parts']:
            if part.get('is_attachment'):
                analysis['attachments'].append(part)
            if part.get('urls'):
                analysis['urls_found'].extend(part['urls'])
            if part.get('base64_encoded'):
                analysis['base64_content_detected'] = True
            if 'html' in part.get('content_type', '').lower():
                analysis['has_html'] = True
            if part.get('has_javascript'):
                analysis['has_javascript'] = True
                analysis['javascript_fragments'].extend(part.get('javascript_fragments', []))
        
        return analysis

    def _analyze_email_part(self, part) -> Dict[str, Any]:
        """Analyze individual email part"""
        part_info = {
            'content_type': part.get_content_type(),
            'encoding': part.get('Content-Transfer-Encoding', ''),
            'size': 0,
            'is_attachment': False,
            'filename': part.get_filename(),
            'urls': [],
            'suspicious_patterns': [],
            'base64_encoded': False,
            'has_javascript': False,
            'javascript_fragments': [],
            'warnings': []
        }
        
        try:
            payload = part.get_payload(decode=True)
            if payload:
                part_info['size'] = len(payload)
                
                if part_info['encoding'].lower() == 'base64':
                    part_info['base64_encoded'] = True
                
                try:
                    content = payload.decode('utf-8', errors='ignore')
                    
                    js_fragments = detect_javascript(content, JS_PATTERNS)
                    if js_fragments:
                        part_info['has_javascript'] = True
                        part_info['javascript_fragments'] = js_fragments
                    
                    part_info['urls'] = extract_urls(content)
                    
                except:
                    pass
        
        except:
            pass
        
        if part_info['filename']:
            part_info['is_attachment'] = True
            filename_lower = part_info['filename'].lower()
            
            for ext in HIGH_RISK_EXTENSIONS:
                if filename_lower.endswith(ext):
                    warning_text = get_text('dangerous_extension_warning', self.language).format(ext)
                    part_info['warnings'].append(warning_text)
                    break 
            
            if not part_info['warnings']: 
                for ext in MEDIUM_RISK_EXTENSIONS:
                    if filename_lower.endswith(ext):
                        warning_text = get_text('suspicious_extension_warning', self.language).format(ext)
                        part_info['warnings'].append(warning_text)
                        break
        
        return part_info

    def extract_email_content(self, msg) -> Dict[str, Any]:
        """Extract text and HTML content from email"""
        content = {
            'text_content': '',
            'html_content': '',
            'html_content_full': '',
            'has_text': False,
            'has_html': False
        }
        
        def extract_part_content(part):
            content_type = part.get_content_type()
            
            if content_type == 'text/plain':
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = None
                        for encoding in ['utf-8', 'cp1251', 'koi8-r', 'iso-8859-1']:
                            try:
                                text = payload.decode(encoding)
                                break
                            except:
                                continue
                        
                        if text and text.strip():
                            content['text_content'] = text[:MAX_CONTENT_DISPLAY]
                            content['has_text'] = True
                except Exception:
                    pass
                    
            elif content_type == 'text/html':
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_content = payload.decode('utf-8', errors='ignore')
                        if html_content.strip():
                            content['html_content_full'] = html_content
                            content['html_content'] = html_content[:MAX_HTML_DISPLAY]
                            content['has_html'] = True
                except Exception:
                    pass
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() != 'multipart':
                    extract_part_content(part)
        else:
            extract_part_content(msg)
        
        return content

    def decode_attachment_images(self, msg) -> Dict[str, Dict[str, Any]]:
        """Decode images from attachments and convert to Data URLs"""
        decoded_images = {}
        image_counter = 1
        
        def process_part(part):
            nonlocal image_counter
            
            content_type = part.get_content_type()
            if content_type and content_type.startswith('image/'):
                try:
                    filename = part.get_filename()
                    if not filename:
                        content_id = part.get('Content-ID')
                        if content_id:
                            filename = f"image_{content_id.strip('<>')}"
                        else:
                            filename = f"image_{image_counter}"
                            image_counter += 1
                    
                    payload = part.get_payload(decode=True)
                    if payload:
                        b64_data = base64.b64encode(payload).decode('ascii')
                        data_url = f"data:{content_type};base64,{b64_data}"
                        
                        clean_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
                        decoded_images[clean_filename] = {
                            'data_url': data_url,
                            'content_type': content_type,
                            'size': len(payload),
                            'content_id': part.get('Content-ID', '').strip('<>')
                        }
                        
                        print(get_text('decoded_image', self.language).format(clean_filename, len(payload)))
                        
                except Exception:
                    pass
        
        if msg.is_multipart():
            for part in msg.walk():
                process_part(part)
        else:
            process_part(msg)
        
        return decoded_images 