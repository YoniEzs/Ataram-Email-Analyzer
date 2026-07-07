# Ataram Email Analyzer

<div align="center">

![Ataram Logo](frontend/src/assets/favicon.svg)

**Advanced Email Security Analysis Platform**

Comprehensive email analysis tool for detecting phishing, malware, and malicious content

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0+-green.svg)](https://flask.palletsprojects.com/)

[Features](#features) •
[Quick Start](#quick-start) •
[Documentation](#documentation) •
[Deployment](#deployment) •
[API](#api-reference)

</div>

---

## 🎯 Features

### Email Analysis
- ✅ **SPF/DKIM/DMARC Validation** - Verify sender authentication
- ✅ **IP Reputation Checking** - Integration with AbuseIPDB
- ✅ **URL Analysis** - Detect shortened, suspicious, and phishing URLs
- ✅ **Attachment Scanning** - Identify malicious file types and executables
- ✅ **Content Analysis** - Phishing keyword and pattern detection
- ✅ **WHOIS Lookup** - Domain registration information
- ✅ **Header Analysis** - Domain mismatch detection
- ✅ **Risk Scoring** - Comprehensive threat assessment (0-100)

### Supported Formats
- 📧 `.eml` files (Standard email format)
- 📧 `.msg` files (Microsoft Outlook format)

### Platform
- 🌐 Modern web interface
- 🎨 Responsive design (mobile-friendly)
- 🔒 Privacy-focused (all analysis is local)
- ⚡ Fast analysis with real-time feedback
- ☁️ Cloud-ready (Cloudflare Pages + Render)

---

## 🚀 Quick Start

### Deploy to Production (Recommended)

**🎯 [Follow detailed deployment guide](CLOUDFLARE_RENDER_DEPLOYMENT.md)**

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git push
   ```

2. **Deploy Backend to Render** ([render.com](https://render.com))
   - Create Web Service from GitHub
   - Use `render.yaml` configuration
   - Add your API keys

3. **Deploy Frontend to Cloudflare Pages** ([dash.cloudflare.com](https://dash.cloudflare.com))
   - Create Pages project from GitHub
   - Build output: `frontend/src`
   - Add custom domain: `ataram.uk`

### Test Locally

#### Backend

1. **Install Python 3.11+**

2. **Setup backend**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Run backend**
   ```bash
   python run.py
   ```

#### Frontend

1. **Serve frontend**
   ```bash
   cd frontend/src
   # Using Python
   python -m http.server 3000

   # Or using Node.js
   npx http-server -p 3000
   ```

2. **Access** http://localhost:3000

---

## 📚 Documentation

### Project Structure

```
email-analyzer/
|-- backend/                      # Flask API backend
|   |-- app/
|   |   |-- api/                 # API endpoints
|   |   |-- services/            # Analysis services
|   |   |-- utils/               # Validation/extraction/cache utilities
|   |   |-- __init__.py          # App factory
|   |   `-- config.py            # Configuration
|   |-- tests/                   # Backend and contract tests
|   |-- run.py                   # Entry point
|   |-- requirements.txt         # Dependencies
|   |-- .env.example             # Environment template
|   `-- Dockerfile               # Docker config
|-- frontend/                    # Web interface
|   |-- src/
|   |   |-- index.html           # Main HTML
|   |   |-- css/                 # Stylesheets
|   |   |-- js/                  # JavaScript
|   |   `-- assets/              # Images/icons
|   |-- Dockerfile
|   |-- nginx.conf
|   `-- wrangler.toml
|-- render.yaml                  # Render deployment config
`-- README.md                    # This file
```

### Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────────┐
│   Browser   │ ◄─────► │   Frontend   │ ◄─────► │  Backend API    │
│  (Client)   │  HTTPS  │   (Nginx)    │   API   │    (Flask)      │
└─────────────┘         └──────────────┘         └─────────────────┘
                                                           │
                                                           ▼
                                        ┌──────────────────────────────┐
                                        │  External Services:          │
                                        │  • DNS (SPF/DKIM/DMARC)     │
                                        │  • AbuseIPDB (IP Reputation)│
                                        │  • WHOIS (Domain Info)      │
                                        └──────────────────────────────┘
```

---

## 🔧 Configuration

### Backend Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask secret key | - | Yes |
| `ABUSEIPDB_KEY` | AbuseIPDB API key | - | Optional |
| `PORT` | Backend port | 5000 | No |
| `CORS_ORIGINS` | Allowed CORS origins | localhost | No |
| `ENABLE_WHOIS` | Enable WHOIS lookups | true | No |
| `ENABLE_ABUSEIPDB` | Enable IP reputation | true | No |

### Frontend Configuration

Edit `frontend/src/js/config.js`:

```javascript
const CONFIG = {
    API_BASE_URL: 'https://api.ataram.uk',  // Your backend URL
    MAX_FILE_SIZE: 50 * 1024 * 1024        // 50MB
};
```

---

## 🌐 Deployment

### Cloudflare Pages + Render (Recommended)

**Free tier available for both platforms!**

#### Backend - Render
- ✅ Free SSL certificates
- ✅ Automatic deployments from GitHub
- ✅ Easy environment variable management
- ⚠️ Free tier sleeps after 15min inactivity

#### Frontend - Cloudflare Pages
- ✅ Unlimited bandwidth (free)
- ✅ Global CDN
- ✅ Instant deployments
- ✅ Custom domain support

**📖 Complete deployment guide**: [CLOUDFLARE_RENDER_DEPLOYMENT.md](CLOUDFLARE_RENDER_DEPLOYMENT.md)

### Quick Deployment Steps

1. **Deploy Backend** → [render.com](https://render.com)
   - Connect GitHub repo
   - Use `render.yaml` configuration
   - Set environment variables

2. **Deploy Frontend** → [dash.cloudflare.com](https://dash.cloudflare.com)
   - Create Pages project
   - Output directory: `frontend/src`
   - Connect custom domain

3. **Configure DNS**
   - `ataram.uk` → Cloudflare Pages
   - `api.ataram.uk` → Render backend

---

## 📡 API Reference

### POST `/api/analyze`

Analyze an email file.

**Request:**
- Content-Type: `multipart/form-data`
- Body:
  - `emailfile` (file): .eml or .msg file
  - `abuseipdb_key` (string, optional): AbuseIPDB API key

**Response:**
```json
{
  "timestamp": "2026-03-09T12:00:00",
  "risk_assessment": {
    "score": 75,
    "level": "high",
    "verdict": "SUSPICIOUS - Exercise extreme caution",
    "whitelist_applied": false
  },
  "headers": {
    "sender": "sender@example.com",
    "subject": "Email subject",
    "date": "Mon, 09 Mar 2026 09:00:00 +0000"
  },
  "authentication": {
    "spf": "v=spf1 ...",
    "dmarc": "v=DMARC1 ...",
    "auth_analysis": {
      "spf": "pass",
      "dkim": "pass",
      "dmarc": "pass"
    }
  },
  "routing_forensics": {
    "public_ips": ["93.184.216.34"],
    "hop_count": 5,
    "originating_ip": "93.184.216.34",
    "timezone_offset": "+0000"
  },
  "urls": {
    "total_count": 5,
    "suspicious_count": 2,
    "urls": []
  },
  "attachments": {
    "total_count": 1,
    "suspicious_count": 0,
    "attachments": []
  },
  "suspicions": [],
  "metadata": {
    "filename": "sample.eml",
    "analyzed_at": "2026-03-09T12:00:00",
    "version": "2.0"
  }
}
```

### GET `/health`

Check API health status.

**Response:**
```json
{
  "status": "healthy",
  "service": "Email Analyzer API"
}
```

---

## 🔒 Security

- All email analysis is performed server-side
- Email content is never stored permanently
- API keys are never exposed to the client
- CORS protection prevents unauthorized access
- File type validation prevents malicious uploads
- Rate limiting (when enabled) prevents abuse

---

## 🛠️ Development

### Running Tests

```bash
cd backend
pytest
pytest --cov=app tests/
```

### Code Quality

```bash
# Linting
flake8 app/
pylint app/

# Type checking
mypy app/
```

---

## 📝 License

Copyright © 2024 Ataram Security Platform

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📧 Contact

- Website: [ataram.uk](https://ataram.uk)
- GitHub: [@ataram](https://github.com/ataram)
- Email: support@ataram.uk

---

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation database
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- All open-source contributors

---

<div align="center">

**Built with ❤️ by the Ataram Security Team**

[⬆ Back to Top](#ataram-email-analyzer)

</div>
