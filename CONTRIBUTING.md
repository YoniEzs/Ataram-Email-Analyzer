# Contributing to Ataram Email Analyzer

Thank you for your interest in contributing to Ataram Email Analyzer!

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs
- Include detailed steps to reproduce
- Provide email sample files if possible (sanitized)
- Include your environment details

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests: `pytest` (backend)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

**Backend (Python):**
- Follow PEP 8
- Use type hints where appropriate
- Add docstrings to functions
- Write tests for new features

**Frontend (JavaScript):**
- Use ES6+ features
- Keep functions small and focused
- Comment complex logic
- Test in multiple browsers

### Development Setup

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests
pytest

# Frontend
cd frontend/src
python -m http.server 3000
```

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, etc.)
- Reference issue numbers when applicable

Examples:
- `Add URL shortener detection`
- `Fix SPF record parsing bug (#123)`
- `Update documentation for deployment`

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Help maintain a positive community

## Questions?

Feel free to open an issue for questions or reach out to support@ataram.uk

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
