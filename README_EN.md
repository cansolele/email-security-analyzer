# Email Security Analyzer

**Email Security Analyzer** is a powerful command-line tool designed for in-depth security analysis of `.eml` email files. It helps identify potential threats such as phishing, malicious attachments, and insecure links by providing detailed HTML reports for each analyzed email. The tool supports both English and Russian languages.

## Features

- **DKIM** validation and security headers analysis
- **Content analysis** - JavaScript, Base64 detection.
- **Advanced Link Analysis** - detects URL shorteners, insecure HTTP, and hyperlink text/destination mismatches.
- **Attachment Scanning** - differentiates between high-risk and medium-risk attachments (executables, archives, macro-enabled documents).
- **Threat Detection** - searches for phishing keywords in subject lines and URLs.
- **Interactive HTML reports** with detailed analysis for each email.
- **Risk assessment** with color-coding and a detailed score breakdown.

## Requirements

- Python 3.6+

## Installation

```bash
# Clone repository
git clone https://github.com/cansolele/email-security-analyzer
cd email-security-analyzer
```

## Usage

```bash
# Analyze emails in mails/ folder (Russian language)
python main.py --lang ru

# Analyze emails in mails/ folder (English language) 
python main.py --lang en

# Analyze emails in custom folder
python main.py /path/to/emails --lang en

# Help
python main.py --help
```

## Results

The program generates clear and interactive HTML reports for each analyzed email and saves them in the `reports/` folder. Each report includes an overall risk assessment, a detailed breakdown of all factors, and displays the email content when available.

Here are some example reports you can view directly in your browser:
- [Analysis of a high-risk email](reports/1_high.html)
- [Analysis of a phishing email](reports/2_medium.html)
- [Analysis of a safe email](reports/3_minimal.html)

## Risk Levels

| Level | Score | Description |
|-------|--------|-------------|
| 🔴 **High** | 50+ | Critical threats detected, such as executable attachments or clear phishing indicators. |
| 🟡 **Medium** | 25-49 | Significant risk factors present, like a missing DKIM signature or macro-enabled attachments. |
| 🔵 **Low** | 10-24 | Minor issues found, such as insecure links or an invalid DKIM signature. |
| 🟢 **Minimal** | 0-9 | The email is considered safe; no significant threats were found. |

<details>
<summary>Detailed Risk Score Calculation</summary>

The total risk score is calculated by summing the points for each detected risk factor. The higher the score, the higher the likelihood of a threat.

| Risk Factor | Score | Description |
|---|---|---|
| **Headers** | | |
| Missing DKIM Signature | +20 | The email lacks a digital signature, making it impossible to verify its authenticity. |
| Invalid DKIM Signature | +10 | A signature is present but failed validation. The email may have been altered in transit. |
| **Content** | | |
| JavaScript Detected | +15 | JavaScript can execute malicious actions within a browser. |
| Phishing Keywords in Subject | +5 (per keyword) | Found words commonly used in phishing attacks (e.g., "urgent," "password"). |
| **Attachments** | | |
| High-Risk Attachment | +25 (per attachment) | Executable files or scripts (`.exe`, `.bat`, `.js`) that pose a direct threat. |
| Medium-Risk Attachment | +10 (per attachment) | Archives or macro-enabled documents (`.zip`, `.docm`) that can hide malicious code. |
| **Links (URLs)** | | |
| Hyperlink Mismatch | +15 (per link) | The visible link text (e.g., `google.com`) does not match the actual destination URL, a classic phishing technique. |
| URL Shortener Used | +10 (per link) | The link is hidden behind a shortening service (e.g., `bit.ly`), obscuring the final destination. |
| Insecure Protocol (HTTP) | +5 (per link) | The link uses `http://` instead of `https://`, making data vulnerable to interception. |
| Suspicious Keyword in Link | +5 (per link) | The URL contains a word associated with fraudulent activity (e.g., `login`, `secure`). |

</details>

## Supported Formats

- Standard email files (RFC 5322)
- Maildir format
- Email client exports

## Project Structure

```
email-security-analyzer/
├── core/               # Core analysis modules
├── utils/              # Utility functions
├── mails/              # Email files folder for analysis
├── reports/            # Generated reports
└── main.py             # Entry point
```

## License

This project is distributed under the MIT License. See the `LICENSE` file for more information. 
