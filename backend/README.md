# Ataram Email Analyzer - Backend API

RESTful API backend for email security analysis built with Flask.

## Features

- 🔍 Comprehensive email analysis
- 🛡️ SPF, DKIM, DMARC validation
- 🌐 DNS and WHOIS lookups
- 📊 IP reputation checking (AbuseIPDB)
- 🔗 URL and attachment analysis
- 📈 Risk scoring algorithm
- 🐳 Docker support
- ✅ Test suite with focused coverage on core analyzers and API contracts

## Technology Stack

- **Flask 3.0** - Web framework
- **Python 3.11+** - Programming language
- **dnspython** - DNS queries
- **python-whois** - WHOIS lookups
- **BeautifulSoup4** - HTML parsing
- **extract-msg** - MSG file parsing
- **Gunicorn** - Production WSGI server

## Quick Start

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate
# Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set your variables
SECRET_KEY=your-secret-key-here
ABUSEIPDB_KEY=your-api-key-here
```

### Run Development Server

```bash
python run.py
```

The API will be available at http://localhost:5000

### Run Production Server

```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 run:app
```

## API Endpoints

### POST /api/analyze

Analyze an email file.

**Request:**
```bash
curl -X POST http://localhost:5000/api/analyze \
  -F "emailfile=@email.eml" \
  -F "abuseipdb_key=your_key"
```

**Response example:**
```json
{
  "timestamp": "2026-03-09T12:00:00",
  "routing_forensics": {
    "public_ips": ["93.184.216.34"],
    "hop_count": 5,
    "originating_ip": "93.184.216.34",
    "timezone_offset": "+0000"
  },
  "risk_assessment": {
    "score": 75,
    "level": "high",
    "verdict": "SUSPICIOUS - Exercise extreme caution",
    "whitelist_applied": false
  },
  "metadata": {
    "filename": "sample.eml",
    "analyzed_at": "2026-03-09T12:00:00",
    "version": "2.0"
  }
}
```

`risk_assessment.whitelist_applied` is set to `true` when the sender domain is
in `WHITELIST_DOMAINS` and SPF passes. The whitelist only gives a small
discount to otherwise low-risk mail; it does not cap high or critical scores.

### GET /health

Health check endpoint.

```bash
curl http://localhost:5000/health
```

## Project Structure

```
backend/
├── app/
│   ├── __init__.py              # App factory
│   ├── config.py                # Configuration
│   ├── api/
│   │   └── analysis.py          # API endpoints
│   ├── services/
│   │   ├── email_parser.py      # Email parsing
│   │   ├── email_analyzer.py    # Analysis orchestration
│   │   ├── dns_checker.py       # DNS queries
│   │   ├── whois_service.py     # WHOIS lookups
│   │   ├── ip_reputation.py     # IP checks
│   │   ├── url_analyzer.py      # URL analysis
│   │   ├── content_analyzer.py  # Content analysis
│   │   └── attachment_analyzer.py # Attachment checks
│   └── utils/
│       ├── validators.py        # Input validation
│       └── extractors.py        # Data extraction
├── tests/                       # Test suite
├── logs/                        # Log files
├── run.py                       # Entry point
├── requirements.txt             # Dependencies
└── Dockerfile                   # Docker config
```

## Service Layer

### EmailParserService

Parses .eml and .msg email files.

```python
from app.services.email_parser import EmailParserService

parser = EmailParserService()
result = parser.parse_email(file_data, filename)
```

### EmailAnalyzerService

Main analysis orchestrator.

```python
from app.services.email_analyzer import EmailAnalyzerService

analyzer = EmailAnalyzerService(abuseipdb_key="your_key")
analysis = analyzer.analyze(parsed_data)
```

### DNSCheckerService

DNS record lookups (SPF, DMARC, DKIM).

```python
from app.services.dns_checker import DNSCheckerService

dns = DNSCheckerService()
spf = dns.check_spf("example.com")
dmarc = dns.check_dmarc("example.com")
```

### URLAnalyzerService

Analyzes URLs for suspicious characteristics.

```python
from app.services.url_analyzer import URLAnalyzerService

analyzer = URLAnalyzerService()
result = analyzer.analyze_urls(urls, sender_domain)
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment (development/production) | development |
| `HOST` | Server host | 0.0.0.0 |
| `PORT` | Server port | 5000 |
| `SECRET_KEY` | Flask secret key | Required |
| `ABUSEIPDB_KEY` | AbuseIPDB API key | Optional |
| `CORS_ORIGINS` | Allowed origins | localhost |
| `ENABLE_WHOIS` | Enable WHOIS lookups | true |
| `ENABLE_ABUSEIPDB` | Enable IP reputation | true |
| `DNS_TIMEOUT` | DNS query timeout (seconds) | 5 |
| `WHOIS_TIMEOUT` | WHOIS timeout (seconds) | 10 |
| `WHITELIST_DOMAINS` | Comma-separated trusted domains for a low-risk score discount | Empty |
| `LOG_LEVEL` | Logging level | INFO |

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=app tests/

# Generate HTML coverage report
pytest --cov=app --cov-report=html tests/
```

## Docker

### Build Image

```bash
docker build -t email-analyzer-backend .
```

### Run Container

```bash
docker run -d \
  -p 5000:5000 \
  -e SECRET_KEY=your-secret \
  -e ABUSEIPDB_KEY=your-key \
  email-analyzer-backend
```

## Security

- Input validation on all endpoints
- File type and size restrictions
- CORS protection
- Rate limiting support
- Secure password storage for API keys
- No permanent data storage

## Performance

- Async DNS queries
- Connection pooling for HTTP requests
- Timeout protection
- Resource limits
- Efficient parsing algorithms

## Monitoring

### Logs

Logs are stored in `logs/email_analyzer.log` with rotation:

```python
# Access logs in your code
from flask import current_app
current_app.logger.info('Message')
```

### Health Check

```bash
curl http://localhost:5000/health
```

## Troubleshooting

### Issue: DNS queries failing

**Solution:** Check DNS server accessibility and timeout settings.

### Issue: WHOIS lookups slow

**Solution:** Disable WHOIS with `ENABLE_WHOIS=false` or increase timeout.

### Issue: High memory usage

**Solution:** Reduce number of workers or implement rate limiting.

## Contributing

1. Follow PEP 8 style guide
2. Write tests for new features
3. Update documentation
4. Submit pull request

## License

MIT License - see LICENSE file

## Support

- Issues: GitHub Issues
- Email: support@ataram.uk
