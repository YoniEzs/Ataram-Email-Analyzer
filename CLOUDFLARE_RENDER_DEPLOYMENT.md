# Deployment Guide: Cloudflare Pages + Render

Complete guide for deploying Ataram Email Analyzer using **Cloudflare Pages** (frontend) and **Render** (backend).

## 🎯 Architecture

```
┌─────────────────┐
│  ataram.uk      │  ◄── Cloudflare Pages (Frontend)
│  (Frontend)     │
└────────┬────────┘
         │
         │ HTTPS/API
         ▼
┌─────────────────┐
│ api.ataram.uk   │  ◄── Render Web Service (Backend)
│ (Backend API)   │
└─────────────────┘
```

---

## 📋 Prerequisites

1. **GitHub Account** - To host your repository
2. **Cloudflare Account** - For frontend hosting (free)
3. **Render Account** - For backend hosting (free tier available)
4. **Domain** - ataram.uk (configured in Cloudflare)
5. **AbuseIPDB API Key** - Optional but recommended

---

## Part 1: Backend Deployment on Render

### Step 1: Push to GitHub

```bash
cd "C:\Email analyzer Ataram\Ataram-Email-Analyzer"

# Initialize git
git init

# Add all files
git add .

# First commit
git commit -m "Initial commit: Ataram Email Analyzer"

# Add remote (create repo on GitHub first)
git remote add origin https://github.com/YOUR_USERNAME/ataram-email-analyzer.git

# Push
git push -u origin main
```

### Step 2: Deploy to Render

1. **Sign up at [render.com](https://render.com)**

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select `ataram-email-analyzer`

3. **Configure Service**
   ```
   Name: ataram-email-analyzer-api
   Region: Frankfurt (or closest to you)
   Branch: main
   Root Directory: backend
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 run:app
   Plan: Free (or Starter for production)
   ```

4. **Environment Variables** (Add these in Render dashboard)
   ```
   FLASK_ENV=production
   SECRET_KEY=<click "Generate" button>
   ABUSEIPDB_KEY=your_abuseipdb_api_key
   CORS_ORIGINS=https://ataram.uk,https://www.ataram.uk
   ENABLE_WHOIS=true
   ENABLE_ABUSEIPDB=true
   ```

5. **Click "Create Web Service"**

6. **Wait for deployment** (2-3 minutes)
   - You'll get a URL like: `https://ataram-email-analyzer-api.onrender.com`

7. **Test the API**
   ```bash
   curl https://ataram-email-analyzer-api.onrender.com/health
   ```

### Step 3: Add Custom Domain (Optional)

1. In Render dashboard, go to your service
2. Click "Settings" → "Custom Domains"
3. Add `api.ataram.uk`
4. You'll get a CNAME value
5. Add to Cloudflare DNS (see below)

---

## Part 2: Frontend Deployment on Cloudflare Pages

### Step 1: Update API URL

Before deploying, update the frontend to use your Render backend URL:

```bash
# Edit frontend/src/js/config.js
```

Change:
```javascript
const CONFIG = {
    API_BASE_URL: 'https://ataram-email-analyzer-api.onrender.com',
    // Or if using custom domain:
    // API_BASE_URL: 'https://api.ataram.uk',
    // ...
};
```

Commit and push:
```bash
git add frontend/src/js/config.js
git commit -m "Update API URL for production"
git push
```

### Step 2: Deploy to Cloudflare Pages

1. **Go to [Cloudflare Dashboard](https://dash.cloudflare.com)**

2. **Navigate to Pages**
   - Click "Workers & Pages" → "Create application" → "Pages"
   - Click "Connect to Git"

3. **Connect Repository**
   - Select your GitHub repository: `ataram-email-analyzer`
   - Click "Begin setup"

4. **Configure Build**
   ```
   Project name: ataram-email-analyzer
   Production branch: main
   Build command: (leave empty)
   Build output directory: frontend/src
   ```

5. **Click "Save and Deploy"**

6. **Wait for deployment** (1-2 minutes)
   - You'll get a URL like: `https://ataram-email-analyzer.pages.dev`

7. **Test the frontend**
   - Visit the URL
   - Try uploading an email file

### Step 3: Add Custom Domain

1. **In Cloudflare Pages**, go to your project
2. Click "Custom domains"
3. Click "Set up a custom domain"
4. Enter `ataram.uk`
5. Click "Continue"
6. Cloudflare will automatically configure DNS (since your domain is on Cloudflare)

7. **Add www subdomain**
   - Click "Add a custom domain" again
   - Enter `www.ataram.uk`
   - Click "Activate domain"

---

## Part 3: DNS Configuration

### In Cloudflare DNS

Add these records for `ataram.uk`:

```
Type    Name    Content                                     Proxy
────────────────────────────────────────────────────────────────
CNAME   @       ataram-email-analyzer.pages.dev            ✓ Proxied
CNAME   www     ataram-email-analyzer.pages.dev            ✓ Proxied
CNAME   api     ataram-email-analyzer-api.onrender.com     ✓ Proxied
```

**Note:** If using Render custom domain, they'll provide the exact CNAME value.

### SSL/TLS Settings

1. In Cloudflare dashboard → SSL/TLS
2. Set encryption mode to **"Full"** or **"Full (strict)"**
3. Enable "Always Use HTTPS"
4. Enable "Automatic HTTPS Rewrites"

---

## Part 4: Update CORS Settings

After deploying, update backend CORS in Render:

1. Go to Render dashboard → Your service → Environment
2. Update `CORS_ORIGINS`:
   ```
   CORS_ORIGINS=https://ataram.uk,https://www.ataram.uk,https://ataram-email-analyzer.pages.dev
   ```
3. Service will auto-redeploy

---

## 🎉 Deployment Complete!

Your application is now live at:
- **Frontend**: https://ataram.uk
- **Backend API**: https://api.ataram.uk (or Render URL)

---

## 📊 Free Tier Limits

### Render (Backend)
- ✅ Free SSL
- ✅ Automatic deployments
- ⚠️ Spins down after 15 min of inactivity (cold starts ~30s)
- ⚠️ 750 hours/month free
- 💡 Upgrade to Starter ($7/mo) for always-on

### Cloudflare Pages (Frontend)
- ✅ Unlimited bandwidth
- ✅ Unlimited requests
- ✅ Free SSL
- ✅ Global CDN
- ✅ 500 builds/month
- ✅ No cold starts

---

## 🚀 Performance Tips

### 1. Keep Render Backend Warm (Free Tier)

Create a cron job to ping your API every 10 minutes:

**Using UptimeRobot** (free):
1. Sign up at [uptimerobot.com](https://uptimerobot.com)
2. Add monitor:
   - Type: HTTP(s)
   - URL: `https://ataram-email-analyzer-api.onrender.com/health`
   - Interval: 5 minutes

**Using GitHub Actions**:

Create `.github/workflows/keep-warm.yml`:
```yaml
name: Keep Render Warm

on:
  schedule:
    - cron: '*/10 * * * *'  # Every 10 minutes

jobs:
  ping:
    runs-on: ubuntu-latest
    steps:
      - name: Ping backend
        run: curl https://ataram-email-analyzer-api.onrender.com/health
```

### 2. Cloudflare Optimizations

In Cloudflare dashboard:
1. **Speed** → Enable "Auto Minify" (HTML, CSS, JS)
2. **Speed** → Enable "Brotli" compression
3. **Caching** → Set Browser Cache TTL to "1 year"

---

## 🔧 Troubleshooting

### Backend Issues

**Build fails on Render:**
```bash
# Check Python version in backend/runtime.txt
cat backend/runtime.txt
# Should be: python-3.11.0
```

**API returns 500 error:**
- Check Render logs: Dashboard → Logs
- Verify environment variables are set
- Test locally first

**CORS errors:**
- Verify `CORS_ORIGINS` includes your frontend URL
- Check Cloudflare proxy settings (should be enabled)

### Frontend Issues

**Can't connect to API:**
- Verify `API_BASE_URL` in `frontend/src/js/config.js`
- Check browser console for errors
- Test API directly: `curl https://api.ataram.uk/health`

**Cloudflare build fails:**
- Ensure "Build output directory" is `frontend/src`
- Leave "Build command" empty

---

## 🔄 Continuous Deployment

Both platforms auto-deploy on git push:

```bash
# Make changes
git add .
git commit -m "Your changes"
git push

# Render will auto-deploy backend
# Cloudflare Pages will auto-deploy frontend
```

---

## 💰 Upgrade Path

### When to Upgrade Render:

**Consider Starter ($7/mo) if:**
- Cold starts are annoying users
- You need guaranteed uptime
- Traffic exceeds free tier hours

**Consider Professional ($25/mo) if:**
- Need more than 2 workers
- Need custom health checks
- High traffic volume

### Cloudflare Pages:

Free tier is usually enough, but Workers can add:
- Rate limiting
- Advanced caching
- Authentication

---

## 📞 Support

**Render Issues:**
- Docs: https://render.com/docs
- Community: https://community.render.com

**Cloudflare Pages:**
- Docs: https://developers.cloudflare.com/pages
- Discord: https://discord.gg/cloudflaredev

**Application Issues:**
- GitHub Issues: Create issue in your repo

---

## ✅ Deployment Checklist

- [ ] GitHub repository created and pushed
- [ ] Render web service deployed
- [ ] Backend environment variables set
- [ ] Backend health check passing
- [ ] Frontend API URL updated
- [ ] Cloudflare Pages deployed
- [ ] Custom domain configured
- [ ] DNS records added
- [ ] SSL certificates active
- [ ] CORS properly configured
- [ ] Test email upload working
- [ ] UptimeRobot monitor added (optional)

---

## 🎊 You're Live!

Your email analyzer is now:
- ✅ Globally distributed via Cloudflare CDN
- ✅ Automatically deployed on every push
- ✅ SSL secured
- ✅ Free to run (with minor limitations)
- ✅ Production-ready at ataram.uk

**Start analyzing emails! 🚀**
