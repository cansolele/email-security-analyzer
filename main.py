#!/usr/bin/env python3
"""
Email Security Analyzer
Batch analysis tool for email security assessment
"""

import sys
import argparse
from core.analyzer import EmailSecurityAnalyzer
from utils.constants import SUPPORTED_LANGUAGES, DEFAULT_LANGUAGE, get_text


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Email Security Analyzer - Batch analysis tool for email security assessment"
    )
    parser.add_argument(
        "folder", 
        nargs="?", 
        default="mails",
        help="Folder containing email files to analyze (default: mails)"
    )
    parser.add_argument(
        "--lang", 
        "-l",
        choices=SUPPORTED_LANGUAGES,
        default=DEFAULT_LANGUAGE,
        help=f"Interface language ({'/'.join(SUPPORTED_LANGUAGES)}, default: {DEFAULT_LANGUAGE})"
    )
    parser.add_argument(
        "--output", 
        "-o",
        help="Output filename for reports (default: auto-generated)"
    )
    
    args = parser.parse_args()
    
    lang = args.lang
    
    print(get_text('starting_analysis', lang))
    print(get_text('target_folder', lang).format(args.folder))
    
    analyzer = EmailSecurityAnalyzer(language=lang)
    
    analyses = analyzer.analyze_emails_in_folder(args.folder)
    
    if not analyses:
        print(get_text('no_emails_analyzed', lang))
        sys.exit(1)
    
    print(get_text('analysis_completed', lang).format(len(analyses)))
    
    individual_reports = analyzer.generate_individual_reports(analyses)
    
    if individual_reports:
        print(get_text('individual_reports_created', lang).format(len(individual_reports)))
        for report in individual_reports:
            print(get_text('report_file', lang).format(report))
    
    print(get_text('view_in_browser', lang))


if __name__ == "__main__":
    main() 