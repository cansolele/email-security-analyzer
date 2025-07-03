"""
Report generation module for email security analyzer
"""

import html
import os
from datetime import datetime
from typing import Dict, List, Any

from utils.constants import REPORT_CONFIG, DEFAULT_LANGUAGE, get_text


class ReportGenerator:
    
    def __init__(self, language: str = DEFAULT_LANGUAGE):
        self.language = language
    
    def generate_html_report(self, analyses: List[Dict[str, Any]], 
                           output_file: str = None) -> str:
        """Generate detailed HTML report"""
        
        if output_file is None:
            output_file = REPORT_CONFIG['main_file']
        
        risk_order = {"Высокий": 4, "Средний": 3, "Низкий": 2, "Минимальный": 1}
        analyses.sort(key=lambda x: risk_order.get(x['risk_assessment']['risk_level'], 0), reverse=True)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Детальный отчет анализа безопасности Email</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.25.0/themes/prism.min.css" rel="stylesheet">
    <style>
        .risk-high {{ background: linear-gradient(135deg, #dc3545, #c82333); }}
        .risk-medium {{ background: linear-gradient(135deg, #fd7e14, #e55100); }}
        .risk-low {{ background: linear-gradient(135deg, #20c997, #17a2b8); }}
        .risk-minimal {{ background: linear-gradient(135deg, #28a745, #20c997); }}
        .email-card {{ 
            border-left: 5px solid;
            transition: all 0.3s ease;
            margin-bottom: 2rem;
        }}
        .email-card:hover {{ 
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .risk-badge {{
            font-size: 0.85em;
            padding: 0.5em 1em;
            border-radius: 20px;
        }}
        .nav-item {{ margin-right: 10px; }}
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 0.375rem;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875em;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .header-table {{
            font-size: 0.875em;
        }}
        .routing-hop {{
            border-left: 3px solid #007bff;
            padding-left: 1rem;
            margin-bottom: 1rem;
        }}
        .attachment-item {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 0.375rem;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
        }}
        .section-divider {{
            border-top: 2px solid #e9ecef;
            margin: 2rem 0 1rem 0;
            padding-top: 1rem;
        }}
        .collapsible-content {{
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #dee2e6;
            border-radius: 0.375rem;
            padding: 1rem;
            background: #f8f9fa;
        }}
        .url-item {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 0.25rem;
            padding: 0.25rem 0.5rem;
            margin: 0.25rem;
            display: inline-block;
            font-size: 0.875em;
        }}
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <span class="navbar-brand">
                <i class="fas fa-shield-alt"></i> Детальный анализ безопасности Email
            </span>
            <span class="navbar-text">
                Анализ от {datetime.now().strftime('%d.%m.%Y %H:%M')}
            </span>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h2>Сводка анализа</h2>
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4>{len(analyses)}</h4>
                                        <span>Всего писем</span>
                                    </div>
                                    <div class="align-self-center">
                                        <i class="fas fa-envelope fa-2x"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"""

        risk_counts = {"Высокий": 0, "Средний": 0, "Низкий": 0, "Минимальный": 0}
        for analysis in analyses:
            risk_level = analysis['risk_assessment']['risk_level']
            risk_counts[risk_level] += 1

        risk_colors = {
            "Высокий": "danger",
            "Средний": "warning", 
            "Низкий": "info",
            "Минимальный": "success"
        }

        risk_icons = {
            "Высокий": "exclamation-triangle",
            "Средний": "exclamation-circle",
            "Низкий": "info-circle", 
            "Минимальный": "check-circle"
        }

        for risk_level, count in risk_counts.items():
            if count > 0:
                color = risk_colors[risk_level]
                icon = risk_icons[risk_level]
                html_content += f"""
                    <div class="col-md-3">
                        <div class="card bg-{color} text-white">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4>{count}</h4>
                                        <span>{risk_level}</span>
                                    </div>
                                    <div class="align-self-center">
                                        <i class="fas fa-{icon} fa-2x"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
"""

        html_content += """
                </div>
                
                <div class="card mb-4">
                    <div class="card-header">
                        <h5><i class="fas fa-list"></i> Быстрая навигация</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
"""

        for i, analysis in enumerate(analyses):
            risk_level = analysis['risk_assessment']['risk_level']
            risk_color = analysis['risk_assessment']['risk_color']
            filename = analysis['filename']
            subject = analysis['basic_info']['subject'][:50] + "..." if len(analysis['basic_info']['subject']) > 50 else analysis['basic_info']['subject']
            
            html_content += f"""
                            <div class="col-md-6 mb-2">
                                <a href="#email-{i}" class="text-decoration-none">
                                    <div class="d-flex align-items-center">
                                        <span class="badge bg-{risk_color} me-2">{risk_level}</span>
                                        <div>
                                            <strong>{filename}</strong><br>
                                            <small class="text-muted">{subject}</small>
                                        </div>
                                    </div>
                                </a>
                            </div>
"""

        html_content += """
                        </div>
                    </div>
                </div>
                
                <h3>Детальный анализ</h3>
"""

        for i, analysis in enumerate(analyses):
            html_content += self._generate_email_card(analysis, i)

        html_content += """
            </div>
        </div>
    </div>
    
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <p class="mb-0">{get_text('footer_text', self.language)}</p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.25.0/components/prism-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.25.0/plugins/autoloader/prism-autoloader.min.js"></script>
</body>
</html>
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Детальный HTML отчет сохранен: {output_file}")
        return output_file

    def _generate_email_card(self, analysis: Dict[str, Any], index: int) -> str:
        """Generate HTML card for single email analysis"""
        
        basic_info = analysis['basic_info']
        content_analysis = analysis['content_analysis']
        security_headers = analysis['security_headers']
        risk_assessment = analysis['risk_assessment']
        threat_indicators = analysis['threat_indicators']
        routing_analysis = analysis.get('routing_analysis', [])
        email_content = analysis.get('email_content', {})
        all_headers = analysis.get('all_headers', {})
        decoded_images = analysis.get('decoded_images', {})
        
        border_color = {"danger": "#dc3545", "warning": "#fd7e14", "info": "#17a2b8", "success": "#28a745"}.get(risk_assessment['risk_color'], "#6c757d")
        
        html_content = f"""
                <div class="card email-card" id="email-{index}" style="border-left-color: {border_color};">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="mb-1"><i class="fas fa-envelope"></i> {analysis['filename']}</h5>
                            <small class="text-muted">{get_text('analysis_from', self.language).format(datetime.fromisoformat(analysis['analysis_timestamp']).strftime('%d.%m.%Y %H:%M'))}</small>
                        </div>
                        <span class="badge bg-{risk_assessment['risk_color']} risk-badge">{risk_assessment['risk_level']} ({risk_assessment['risk_score']}/100)</span>
                    </div>
                    <div class="card-body">
                        <h6><i class="fas fa-info-circle"></i> {get_text('basic_information', self.language)}</h6>
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <table class="table table-sm header-table">
                                    <tr><td style="width: 80px;"><strong>{get_text('from', self.language)}:</strong></td><td style="word-break: break-all;">{basic_info['from']}</td></tr>
                                    <tr><td><strong>{get_text('to', self.language)}:</strong></td><td style="word-break: break-all;">{basic_info['to']}</td></tr>
                                    <tr><td><strong>{get_text('subject', self.language)}:</strong></td><td>{basic_info['subject']}</td></tr>
                                    <tr><td><strong>{get_text('date', self.language)}:</strong></td><td>{basic_info['date']}</td></tr>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <table class="table table-sm header-table">
                                    <tr><td><strong>{get_text('return_path', self.language)}:</strong></td><td>{basic_info['return_path']}</td></tr>
                                    <tr><td><strong>{get_text('message_id', self.language)}:</strong></td><td style="word-break: break-all; font-size: 0.75em;">{basic_info['message_id']}</td></tr>
                                    <tr><td><strong>{get_text('content_type', self.language)}:</strong></td><td>{basic_info['content_type']}</td></tr>
                                    <tr><td><strong>{get_text('size', self.language)}:</strong></td><td>{content_analysis['total_size']} {get_text('bytes', self.language)}</td></tr>
                                </table>
                            </div>
                        </div>
                        <div class="section-divider">
                            <h6><i class="fas fa-shield-alt"></i> {get_text('security_status', self.language)}</h6>
                            <div class="mb-3">"""
        if security_headers['has_dkim']:
            html_content += f'<span class="badge bg-{"success" if security_headers["dkim_valid"] else "warning"} me-2"><i class="fas fa-{"check" if security_headers["dkim_valid"] else "exclamation"}"></i> {get_text("dkim_valid" if security_headers["dkim_valid"] else "dkim_present", self.language)}</span>'
        else:
            html_content += f'<span class="badge bg-danger me-2"><i class="fas fa-times"></i> {get_text("dkim_missing", self.language)}</span>'
        if content_analysis['has_html']: html_content += f'<span class="badge bg-info me-2"><i class="fas fa-code"></i> {get_text("html_content", self.language)}</span>'
        if content_analysis['has_javascript']: html_content += f'<span class="badge bg-warning me-2"><i class="fas fa-exclamation-triangle"></i> {get_text("javascript_detected", self.language)}</span>'
        if content_analysis['attachments']: html_content += f'<span class="badge bg-secondary me-2"><i class="fas fa-paperclip"></i> {get_text("attachments", self.language)}: {len(content_analysis["attachments"])}</span>'
        if content_analysis['base64_content_detected']: html_content += f'<span class="badge bg-info me-2"><i class="fas fa-lock"></i> {get_text("base64_content", self.language)}</span>'
        
        html_content += f"""</div></div>
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <h6><i class="fas fa-exclamation-triangle"></i> {get_text('risk_factors', self.language)}</h6>"""
        if risk_assessment['risk_factors']:
            html_content += '<ul class="list-unstyled">'
            for factor in risk_assessment['risk_factors']: html_content += f'<li><small><i class="fas fa-caret-right text-danger"></i> {factor}</small></li>'
            html_content += '</ul>'
        else:
            html_content += f'<p class="text-success"><small><i class="fas fa-check"></i> {get_text("no_risk_factors", self.language)}</small></p>'
        
        html_content += f"""</div><div class="col-md-6"><h6><i class="fas fa-bug"></i> {get_text('threat_indicators', self.language)}</h6>"""
        if threat_indicators['phishing_indicators']:
            html_content += f'<div class="mb-2"><strong>{get_text("phishing", self.language)}:</strong><br>'
            for keyword in threat_indicators['phishing_indicators']: html_content += f'<span class="badge bg-warning me-1">{keyword}</span>'
            html_content += '</div>'
        if threat_indicators['malware_indicators']:
            html_content += f'<div class="mb-2"><strong>{get_text("malware", self.language)}:</strong><br>'
            for indicator in threat_indicators['malware_indicators']: html_content += f'<span class="badge bg-danger me-1">{indicator}</span><br>'
            html_content += '</div>'
        if not threat_indicators['phishing_indicators'] and not threat_indicators['malware_indicators']:
            html_content += f'<p class="text-success"><small><i class="fas fa-check"></i> {get_text("no_threats_detected", self.language)}</small></p>'
        html_content += """</div></div>"""

        if decoded_images:
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-image"></i> {get_text('decoded_images', self.language)}</h6><div class="row">"""
            for img_name, img_data in decoded_images.items():
                html_content += f"""<div class="col-md-6 mb-3"><div class="card"><img src="{img_data['data_url']}" class="card-img-top" style="max-height: 200px; object-fit: contain;" alt="{img_name}"><div class="card-body"><h6 class="card-title">{img_name}</h6><p class="card-text"><small class="text-muted">{img_data['content_type']} | {img_data['size']:,} {get_text('bytes', self.language)}</small></p></div></div></div>"""
            html_content += """</div></div>"""

        if content_analysis.get('has_javascript') and content_analysis.get('javascript_fragments'):
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-exclamation-triangle"></i> {get_text('javascript_fragments', self.language)}</h6><div class="alert alert-warning"><i class="fas fa-shield-alt"></i> {get_text('javascript_detected_warning', self.language)}</div>"""
            for i, fragment in enumerate(content_analysis['javascript_fragments'][:10], 1):
                html_content += f"""<div class="mb-3"><h6 class="text-warning">{get_text('fragment', self.language)} {i}:</h6><div class="code-block bg-light border border-warning"><small>{html.escape(fragment)}</small></div></div>"""
            if len(content_analysis['javascript_fragments']) > 10:
                html_content += f'<p class="text-muted"><i class="fas fa-info-circle"></i> {get_text("and_more_fragments", self.language).format(10, len(content_analysis["javascript_fragments"]))}</p>'
            html_content += '</div>'

        if content_analysis['attachments']:
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-paperclip"></i> {get_text('detailed_attachments', self.language)}</h6>"""
            for j, attachment in enumerate(content_analysis['attachments']):
                filename = attachment.get('filename', get_text('attachment_num', self.language).format(j+1))
                content_type = attachment.get('content_type', get_text('unknown', self.language))
                size = attachment.get('size', 0)
                encoding = attachment.get('encoding', '')
                warnings = attachment.get('warnings', [])
                html_content += f"""<div class="attachment-item {'border-warning' if warnings else 'border-success'}"><div class="d-flex justify-content-between align-items-start"><div><strong><i class="fas fa-file"></i> {filename}</strong><br><small class="text-muted">{get_text('content_type', self.language)}: {content_type} | {get_text('size', self.language)}: {size:,} {get_text('bytes', self.language)} | {get_text('encoding', self.language)}: {encoding}</small>"""
                if warnings:
                    html_content += '<br><div class="mt-1">'
                    for warning in warnings: html_content += f'<span class="badge bg-warning me-1"><i class="fas fa-exclamation-triangle"></i> {warning}</span>'
                    html_content += '</div>'
                html_content += """</div></div></div>"""
            html_content += '</div>'

        if content_analysis['urls_found']:
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-link"></i> {get_text('found_urls', self.language)}</h6><div class="mb-3">"""
            for url in content_analysis['urls_found'][:10]:
                html_content += f'<div class="url-item"><i class="fas fa-external-link-alt"></i> {url}</div>'
            if len(content_analysis['urls_found']) > 10:
                html_content += f'<small class="text-muted">{get_text("and_more_links", self.language).format(len(content_analysis["urls_found"]) - 10)}</small>'
            html_content += """</div></div>"""

        if routing_analysis:
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-route"></i> {get_text('routing_analysis', self.language)}</h6>"""
            for hop in routing_analysis:
                hop_num, from_host, by_host, ips, timestamp, warnings = hop['hop_number'], hop.get('from_host', get_text('unknown', self.language)), hop.get('by_host', get_text('unknown', self.language)), ', '.join(hop.get('ip_addresses', [])), hop.get('timestamp', ''), hop.get('warnings', [])
                html_content += f"""<div class="routing-hop"><strong>{get_text('hop', self.language)} {hop_num}:</strong> {from_host} → {by_host}<br><small class="text-muted">IP: {ips or get_text('not_specified', self.language)} | {get_text('time', self.language)}: {timestamp}"""
                if warnings:
                    html_content += '<br>'
                    for warning in warnings: html_content += f'<span class="badge bg-warning me-1">{warning}</span>'
                html_content += """</small></div>"""
            html_content += '</div>'

        if email_content and (email_content.get('has_text') or email_content.get('has_html')):
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-file-text"></i> {get_text('email_content', self.language)}</h6>"""
            if email_content.get('has_text'):
                text_content = email_content['text_content'][:1000] + ("..." if len(email_content['text_content']) > 1000 else "")
                try: text_content = text_content.encode().decode('unicode_escape') if '\\u' in text_content else text_content
                except: pass
                html_content += f"""<div class="mb-3"><strong>{get_text('text_version', self.language)}:</strong><div class="collapsible-content"><pre class="code-block">{html.escape(text_content)}</pre></div></div>"""
            if email_content.get('has_html'):
                html_snippet = email_content['html_content'][:1500] + ("..." if len(email_content['html_content']) > 1500 else "")
                html_content += f"""<div class="mb-3"><strong>{get_text('html_code', self.language)}:</strong><div class="collapsible-content"><pre class="code-block">{html.escape(html_snippet)}</pre></div></div>"""
                if email_content.get('html_content_full'):
                    html_content += f"""<div class="mb-3"><strong>{get_text('html_rendering', self.language)}:</strong><div class="email-content-frame">{email_content['html_content_full']}</div></div>"""
            html_content += '</div>'

        if all_headers:
            html_content += f"""<div class="section-divider"><h6><i class="fas fa-list"></i> {get_text('all_headers', self.language)}</h6><div class="collapsible-content"><table class="table table-sm header-table">"""
            for name, value in all_headers.items():
                html_content += f"""<tr><td style="width: 200px;"><strong>{name}:</strong></td><td style="word-break: break-all; font-size: 0.8em;">{value[:200] + "..." if len(value) > 200 else value}</td></tr>"""
            html_content += """</table></div></div>"""

        html_content += """</div></div>"""
        return html_content

    def generate_individual_reports(self, analyses: List[Dict[str, Any]]) -> List[str]:
        """Generate individual HTML reports for each email"""
        report_files = []
        
        reports_dir = REPORT_CONFIG['reports_dir']
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        for i, analysis in enumerate(analyses, 1):
            risk_level = analysis['risk_assessment']['risk_level'].lower()
            risk_level_en = {
                'высокий': 'high',
                'средний': 'medium', 
                'низкий': 'low',
                'минимальный': 'minimal',
                'high': 'high',
                'medium': 'medium', 
                'low': 'low',
                'minimal': 'minimal'
            }.get(risk_level, 'unknown')
            
            report_filename = f"{reports_dir}/{i}_{risk_level_en}.html"
            
            print(get_text('creating_report', self.language).format(report_filename))
            
            html_content = self._generate_single_email_report(analysis, i)
            
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            report_files.append(report_filename)
        
        return report_files

    def _generate_single_email_report(self, analysis: Dict[str, Any], email_index: int) -> str:
        """Generate HTML report for single email with full details"""
        
        risk_assessment = analysis['risk_assessment']
        
        risk_color_map = {
            "danger": "#dc3545",
            "warning": "#fd7e14", 
            "info": "#17a2b8",
            "success": "#28a745"
        }
        border_color = risk_color_map.get(risk_assessment['risk_color'], "#6c757d")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="{'ru' if self.language == 'ru' else 'en'}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{get_text('email_security_analysis', self.language)}: {analysis['filename']}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .risk-badge {{
            font-size: 1em;
            padding: 0.5em 1em;
            border-radius: 20px;
        }}
        .header-table {{
            font-size: 0.9em;
        }}
        .section-divider {{
            border-top: 2px solid #e9ecef;
            margin: 2rem 0 1rem 0;
            padding-top: 1rem;
        }}
        .routing-hop {{
            border-left: 3px solid #007bff;
            padding-left: 1rem;
            margin-bottom: 1rem;
        }}
        .attachment-item {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 0.375rem;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
        }}
        .url-item {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 0.25rem;
            padding: 0.25rem 0.5rem;
            margin: 0.25rem;
            display: inline-block;
            font-size: 0.875em;
        }}
        .email-content-frame {{
            border: 2px solid #dee2e6;
            border-radius: 0.375rem;
            background: white;
            padding: 1rem;
            margin: 1rem 0;
            max-height: 600px;
            overflow-y: auto;
        }}
        .decoded-image {{
            max-width: 100%;
            height: auto;
            border: 1px solid #dee2e6;
            border-radius: 0.375rem;
            margin: 0.5rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .image-gallery {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin: 1rem 0;
        }}
        .image-item {{
            text-align: center;
            max-width: 300px;
        }}
        .code-block {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 0.375rem;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875em;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark" style="background: linear-gradient(135deg, {border_color}, #6c757d);">
        <div class="container">
            <span class="navbar-brand">
                <i class="fas fa-envelope-open"></i> {get_text('email_security_analysis', self.language)}: {analysis['filename']}
            </span>
            <span class="badge bg-{risk_assessment['risk_color']} risk-badge">
                {risk_assessment['risk_level']} ({risk_assessment['risk_score']}/100)
            </span>
        </div>
    </nav>
    
    <div class="container mt-4">
        <div class="row mb-4">
            <div class="col-12">
                <div class="card" style="border-left: 5px solid {border_color};">
                    <div class="card-header">
                        <h5><i class="fas fa-info-circle"></i> {get_text('analysis_summary', self.language)}</h5>
                    </div>
                    <div class="card-body">
                        <p><strong>{get_text('file', self.language)}:</strong> {analysis['filename']}</p>
                        <p><strong>{get_text('analysis_time', self.language)}:</strong> {datetime.fromisoformat(analysis['analysis_timestamp']).strftime('%d.%m.%Y %H:%M:%S')}</p>
                        <p><strong>{get_text('risk_level', self.language)}:</strong> 
                            <span class="badge bg-{risk_assessment['risk_color']}">{risk_assessment['risk_level']}</span>
                            ({risk_assessment['risk_score']}/100 {get_text('points', self.language)})
                        </p>
                    </div>
                </div>
            </div>
        </div>

        {self._generate_email_card(analysis, 0)}
    </div>
    
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <p class="mb-0">{get_text('individual_footer', self.language)}</p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""
        
        return html_content 