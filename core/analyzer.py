"""
Main email security analyzer class
"""

import email
import os
import glob
from datetime import datetime
from typing import Dict, List, Any

from .content_analyzer import ContentAnalyzer
from .security_analyzer import SecurityAnalyzer
from .report_generator import ReportGenerator
from utils.email_utils import extract_basic_info, extract_all_headers, analyze_routing
from utils.constants import DEFAULT_LANGUAGE, get_text


class EmailSecurityAnalyzer:
    """Main email security analyzer class"""
    
    def __init__(self, language: str = DEFAULT_LANGUAGE):
        self.language = language
        self.content_analyzer = ContentAnalyzer(language)
        self.security_analyzer = SecurityAnalyzer(language)
        self.report_generator = ReportGenerator(language)

    def analyze_emails_in_folder(self, folder_path: str = "mails") -> List[Dict[str, Any]]:
        """Analyze all email files in specified folder"""
        if not os.path.exists(folder_path):
            print(get_text('folder_not_found', self.language).format(folder_path))
            return []
        
        email_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if not file.startswith('.') and not file.endswith('.html'):
                    email_files.append(os.path.join(root, file))
        
        email_files.sort()
        
        if not email_files:
            print(get_text('no_files_found', self.language).format(folder_path))
            return []
        
        print(get_text('files_found', self.language).format(len(email_files)))
        
        results = []
        for i, file_path in enumerate(email_files, 1):
            print(get_text('analyzing_file', self.language).format(i, len(email_files), os.path.basename(file_path)))
            analysis = self.analyze_single_email(file_path)
            if analysis:
                results.append(analysis)
        
        return results

    def analyze_single_email(self, file_path: str) -> Dict[str, Any]:
        """Analyze single email file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                msg = email.message_from_string(f.read())
            
            filename = os.path.basename(file_path)
            print(get_text('analyzing_email', self.language).format(filename))
            
            basic_info = extract_basic_info(msg)
            security_headers = self.security_analyzer.analyze_security_headers(msg)
            content_analysis = self.content_analyzer.analyze_content(msg)
            email_content = self.content_analyzer.extract_email_content(msg)
            decoded_images = self.content_analyzer.decode_attachment_images(msg)
            all_headers = extract_all_headers(msg)
            routing_analysis = analyze_routing(msg, self.language)
            
            threat_indicators = self.security_analyzer.analyze_threat_indicators(
                msg, basic_info, content_analysis
            )
            
            risk_assessment = self.security_analyzer.assess_risk(
                threat_indicators, security_headers, content_analysis, basic_info
            )
            
            return {
                'filename': filename,
                'analysis_timestamp': datetime.now().isoformat(),
                'basic_info': basic_info,
                'security_headers': security_headers,
                'content_analysis': content_analysis,
                'email_content': email_content,
                'decoded_images': decoded_images,
                'all_headers': all_headers,
                'routing_analysis': routing_analysis,
                'threat_indicators': threat_indicators,
                'risk_assessment': risk_assessment
            }
            
        except Exception as e:
            print(get_text('analysis_error', self.language).format(file_path, e))
            return None

    def generate_individual_reports(self, analyses: List[Dict[str, Any]]) -> List[str]:
        """Generate individual HTML reports for each email"""
        if not analyses:
            print(get_text('no_report_data', self.language))
            return []
        
        return self.report_generator.generate_individual_reports(analyses) 