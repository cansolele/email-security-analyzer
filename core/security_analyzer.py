"""
Security analysis module for email security analyzer
"""

from typing import Dict, Any, List
import re

from utils.constants import (PHISHING_KEYWORDS, RISK_LEVELS, RISK_WEIGHTS, 
                             URL_SHORTENERS, SUSPICIOUS_URL_KEYWORDS, 
                             HIGH_RISK_EXTENSIONS, MEDIUM_RISK_EXTENSIONS,
                             DEFAULT_LANGUAGE, get_text, get_risk_level_name)
from utils.email_utils import extract_domain_from_header


class SecurityAnalyzer:
    
    def __init__(self, language: str = DEFAULT_LANGUAGE):
        self.language = language
    
    def analyze_security_headers(self, msg) -> Dict[str, Any]:
        """Analyze email security headers"""
        analysis = {
            'dkim_signature': msg.get('DKIM-Signature', ''),
            'authentication_results': msg.get('Authentication-Results', ''),
            'spam_status': msg.get('X-Spam-Status', ''),
            'virus_scanned': msg.get('X-Virus-Scanned', ''),
            'has_dkim': bool(msg.get('DKIM-Signature')),
            'dkim_valid': False
        }
        
        auth_results = analysis['authentication_results']
        if 'dkim=pass' in auth_results.lower():
            analysis['dkim_valid'] = True
        
        return analysis

    def analyze_threat_indicators(self, msg, basic_info: Dict[str, Any], 
                                content_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat indicators"""
        indicators = {
            'suspicious_domains': [],
            'suspicious_attachments': [],
            'phishing_indicators': [],
            'malware_indicators': [],
            'social_engineering': []
        }
        
        for attachment in content_analysis.get('attachments', []):
            filename = attachment.get('filename', '').lower()
            
            if any(filename.endswith(ext) for ext in HIGH_RISK_EXTENSIONS) or \
               any(filename.endswith(ext) for ext in MEDIUM_RISK_EXTENSIONS):
                indicators['suspicious_attachments'].append(filename)
        
        subject = basic_info.get('subject', '').lower()
        for category, keywords in PHISHING_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in subject:
                    indicators['phishing_indicators'].append(f"Подозрительное слово в теме: {keyword}")
        
        return indicators
    
    def assess_risk(self, threat_indicators: Dict[str, Any], 
                   security_headers: Dict[str, Any], 
                   content_analysis: Dict[str, Any],
                   basic_info: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall email risk"""
        risk_score = 0
        risk_factors = []
        
        if not security_headers.get('has_dkim', False):
            risk_score += RISK_WEIGHTS['NO_DKIM']
            risk_factors.append(get_text('missing_dkim', self.language))
        elif not security_headers.get('dkim_valid', False):
            risk_score += RISK_WEIGHTS['INVALID_DKIM']
            risk_factors.append(get_text('invalid_dkim', self.language))
        
        if content_analysis.get('has_javascript', False):
            risk_score += RISK_WEIGHTS['JAVASCRIPT']
            risk_factors.append(get_text('javascript_found', self.language))
        
        phishing_count = len(threat_indicators.get('phishing_indicators', []))
        if phishing_count > 0:
            risk_score += phishing_count * RISK_WEIGHTS['PHISHING_KEYWORD']
            risk_factors.append(get_text('phishing_indicators', self.language).format(phishing_count))

        for attachment in content_analysis.get('attachments', []):
            filename = attachment.get('filename', '').lower()
            if any(filename.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
                risk_score += RISK_WEIGHTS['HIGH_RISK_ATTACHMENT']
                risk_factors.append(get_text('high_risk_attachment', self.language).format(filename))
            elif any(filename.endswith(ext) for ext in MEDIUM_RISK_EXTENSIONS):
                risk_score += RISK_WEIGHTS['MEDIUM_RISK_ATTACHMENT']
                risk_factors.append(get_text('medium_risk_attachment', self.language).format(filename))

        risk_score += self._analyze_urls(content_analysis.get('urls_found', []), risk_factors)

        risk_level = get_text('risk_level_minimal', self.language)
        risk_color = "success"
        
        sorted_risk_levels = sorted(RISK_LEVELS.items(), key=lambda item: item[1]['threshold'])
        
        for level_name, level_info in sorted_risk_levels:
            if risk_score >= level_info['threshold']:
                risk_level = get_risk_level_name(level_info['name'], self.language)
                risk_color = level_info['color']
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_factors': risk_factors
        }
    
    def _is_domain_mismatch(self, href: str, text: str) -> bool:
        """Check if the visible link text domain differs from the actual href domain."""
        try:
            text_domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
            if not text_domain_match:
                return False
            
            text_domain = text_domain_match.group(1).lower().replace('www.', '')

            href_domain_match = re.search(r'https?:\/\/([^\/]+)', href)
            if not href_domain_match:
                return False
            
            href_domain = href_domain_match.group(1).lower().replace('www.', '')

            return text_domain not in href_domain
        except Exception:
            return False

    def _analyze_urls(self, urls: List[Dict[str, str]], risk_factors: List[str]) -> int:
        """Analyzes URLs for suspicious signs and returns the calculated risk score."""
        url_risk_score = 0
        for url_obj in urls:
            href = url_obj.get('href', '')
            text = url_obj.get('text', '')
            
            if not href:
                continue

            href_lower = href.lower()

            if href_lower.startswith('http://'):
                url_risk_score += RISK_WEIGHTS['INSECURE_LINK_HTTP']
                risk_factors.append(get_text('insecure_link_http', self.language).format(href))

            if self._is_domain_mismatch(href, text):
                url_risk_score += RISK_WEIGHTS['HYPERLINK_MISMATCH']
                risk_factors.append(get_text('hyperlink_mismatch', self.language).format(text, href))
            
            try:
                href_domain_match = re.search(r'https?:\/\/([^\/]+)', href_lower)
                if href_domain_match:
                    href_domain = href_domain_match.group(1).replace('www.', '')
                    if href_domain in URL_SHORTENERS:
                        url_risk_score += RISK_WEIGHTS['LINK_SHORTENER']
                        risk_factors.append(get_text('link_shortener', self.language).format(href))
            except Exception:
                pass 
            
            for keyword in SUSPICIOUS_URL_KEYWORDS:
                if keyword in href_lower:
                    url_risk_score += RISK_WEIGHTS['SUSPICIOUS_URL_KEYWORD']
                    risk_factors.append(get_text('suspicious_link_keyword', self.language).format(href))
                    break
        
        return url_risk_score 