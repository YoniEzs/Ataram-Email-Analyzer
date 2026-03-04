# Quick Start Guide - Ataram Email Analyzer

Get your email analyzer running in 5 minutes! 🚀

## Option 1: Deploy to Production (Recommended)

### Prerequisites
- GitHub account
- Cloudflare account (free)
- Render account (free)

### Steps

1. **Push to GitHub**
   ```bash
   cd Ataram-Email-Analyzer
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/ataram-email-analyzer.git
   git push -u origin main
   ```

2. **Deploy Backend to Render**
   - Go to [render.com](https://render.com)
   - New → Web Service
   - Connect your GitHub repo
   - Use settings from `render.yaml`
   - Add environment variables (especially `ABUSEIPDB_KEY`)
   - Deploy!
   - You'll get URL like: `https://your-app.onrender.com`

3. **Update Frontend API URL**
   ```bash
   # Edit frontend/src/js/config.js
   # Change API_BASE_URL to your Render URL
   ```

4. **Deploy Frontend to Cloudflare Pages**
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
   - Pages → Create project
   - Connect GitHub repo
   - Build output: `frontend/src`
   - Deploy!

5. **Configure Custom Domain**
   - In Cloudflare Pages: Add custom domain `ataram.uk`
   - DNS will be auto-configured

📖 **Detailed guide**: See [CLOUDFLARE_RENDER_DEPLOYMENT.md](CLOUDFLARE_RENDER_DEPLOYMENT.md)

---

## Option 2: Test Locally

### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Edit .env and add your API keys

# Run server
python run.py
```

Backend will be at: http://localhost:5000

### Frontend

```bash
cd frontend/src

# Serve with Python
python -m http.server 3000

# OR with Node.js
npx http-server -p 3000
```

Frontend will be at: http://localhost:3000

---

## Configuration

### Required Environment Variables

**Backend (.env):**
```env
SECRET_KEY=generate_random_key_here
ABUSEIPDB_KEY=your_api_key  # Optional but recommended
```

Generate SECRET_KEY:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Frontend (frontend/src/js/config.js):**
```javascript
API_BASE_URL: 'http://localhost:5000'  // For local testing
// or
API_BASE_URL: 'https://your-app.onrender.com'  // For production
```

---

## Getting API Keys

### AbuseIPDB (Free)
1. Sign up at [abuseipdb.com](https://www.abuseipdb.com)
2. Go to Account → API
3. Copy your API key
4. Add to `.env` or Render environment variables

---

## Testing

Upload a test email:
1. Go to http://localhost:3000 (or your deployed URL)
2. Drag and drop a `.eml` or `.msg` file
3. View the analysis results

---

## Troubleshooting

### Backend won't start
- Check Python version: `python --version` (need 3.11+)
- Verify all dependencies installed: `pip install -r requirements.txt`
- Check `.env` file exists

### Frontend can't connect to API
- Verify backend is running
- Check `API_BASE_URL` in `frontend/src/js/config.js`
- Check browser console for CORS errors

### CORS errors in browser
- Add frontend URL to backend `CORS_ORIGINS` in `.env`
- Restart backend server

---

## Next Steps

1. ✅ Deploy to production (Cloudflare + Render)
2. ✅ Configure custom domain `ataram.uk`
3. ✅ Set up uptime monitoring
4. ✅ Add your AbuseIPDB API key for IP reputation
5. ✅ Test with real phishing emails

---

## Need Help?

- 📖 Full deployment guide: [CLOUDFLARE_RENDER_DEPLOYMENT.md](CLOUDFLARE_RENDER_DEPLOYMENT.md)
- 📚 Project documentation: [README.md](README.md)
- 🐛 Report issues: GitHub Issues
- 💬 Questions: support@ataram.uk

---

**Ready to analyze emails! 🎉**
