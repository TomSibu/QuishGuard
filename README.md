# QuishGuard - QR Code Phishing Prevention System

A web application that helps users detect and prevent **Quishing** (QR code phishing) attacks by analyzing URLs extracted from QR codes before visiting them.

![QuishGuard](https://img.shields.io/badge/Security-QR%20Phishing%20Prevention-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-red)

## 🛡️ Features

### Core Features
- **QR Code Scanning** - Scan QR codes using your device camera
- **Image Upload** - Upload QR code images for analysis
- **Manual URL Input** - Directly enter URLs for security analysis
- **Real-time Analysis** - Instant security assessment

### Security Checks
1. **URL Structure Analysis** - Detects suspicious patterns in URLs
2. **SSL Certificate Validation** - Verifies HTTPS and certificate validity
3. **Domain Age Check** - Identifies newly registered domains
4. **Typosquatting Detection** - Detects domains mimicking legitimate brands
5. **Suspicious Keywords** - Identifies phishing-related keywords
6. **VirusTotal Integration** - Checks against 70+ security vendors
7. **Google Safe Browsing** - Verifies against Google's threat database

### User Experience
- Beautiful, modern dark-themed UI
- Risk score visualization (0-100)
- Color-coded risk levels (Low/Medium/High)
- Detailed security reports
- Proceed/Block decision options

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd "e:\Honors Project"
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API Keys** (Optional but recommended)
   
   Set environment variables for enhanced security checks:
   ```bash
   # Windows PowerShell
   $env:VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
   $env:GOOGLE_SAFE_BROWSING_API_KEY = "your_google_api_key"
   
   # Linux/Mac
   export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
   export GOOGLE_SAFE_BROWSING_API_KEY="your_google_api_key"
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open your browser**
   Navigate to `http://localhost:5000`

## 📁 Project Structure

```
Honors Project/
├── app.py                 # Flask backend application
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── templates/
    └── index.html        # Frontend UI
```

## 🔑 API Keys Setup

### VirusTotal API (Free)
1. Create an account at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile → API Key
3. Copy your API key

### Google Safe Browsing API (Free)
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable "Safe Browsing API"
4. Create credentials → API Key
5. Copy your API key

## 🔒 Security Checks Explained

| Check | Description | Risk Indicators |
|-------|-------------|-----------------|
| URL Structure | Analyzes URL format | IP addresses, long URLs, @ symbols |
| SSL Certificate | Validates HTTPS | Expired, invalid, or missing certs |
| Domain Age | Checks domain registration | Domains < 30 days old |
| Typosquatting | Brand impersonation | Similar to google.com, paypal.com |
| Keywords | Phishing indicators | "verify", "suspend", "login" |
| VirusTotal | Multi-vendor scan | Flagged by security vendors |
| Safe Browsing | Google's database | Known phishing/malware sites |

## 🎨 Risk Levels

- 🟢 **Low Risk (0-29)**: URL appears safe
- 🟡 **Medium Risk (30-59)**: Proceed with caution
- 🔴 **High Risk (60-100)**: Do NOT proceed

## 🔧 Configuration

Edit `app.py` to customize:

```python
# Add more legitimate domains for typosquatting detection
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', ...
]

# Add more suspicious keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'suspend', ...
]
```

## 🚧 Future Enhancements

- [ ] Browser extension support
- [ ] Scan history with database
- [ ] User accounts and preferences
- [ ] API endpoint for developers
- [ ] Machine learning-based detection
- [ ] Email/PDF QR extraction
- [ ] Bulk scanning feature
- [ ] Redirect chain analysis

## 🐛 Troubleshooting

### Camera not working?
- Ensure browser has camera permissions
- Use HTTPS in production (required for camera access)
- Try uploading an image instead

### WHOIS lookup failing?
- Some domains block WHOIS queries
- Try again after a few seconds

### API checks skipped?
- Verify API keys are correctly set
- Check API quota limits

## 📝 License

This project is for educational purposes. Feel free to use and modify.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

## 📧 Contact

For questions or suggestions, please open an issue on the repository.

---

**Stay safe from QR phishing attacks! 🛡️**
