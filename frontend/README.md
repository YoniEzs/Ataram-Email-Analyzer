# Ataram Email Analyzer - Frontend

Modern, responsive web interface for the Ataram Email Security Analysis platform.

## Features

- 🎨 Modern, dark-themed UI
- 📱 Fully responsive design
- 🎯 Drag-and-drop file upload
- 📊 Comprehensive results visualization
- ⚡ Real-time analysis feedback
- 🔒 Client-side security validation

## Technology Stack

- **HTML5** - Semantic markup
- **CSS3** - Modern styling with CSS variables
- **Vanilla JavaScript** - No framework dependencies
- **Fetch API** - Backend communication

## Project Structure

```
frontend/
├── src/
│   ├── index.html          # Main HTML file
│   ├── css/
│   │   ├── styles.css      # Main styles
│   │   └── results.css     # Results display styles
│   ├── js/
│   │   ├── app.js          # Application initialization
│   │   ├── config.js       # Configuration
│   │   ├── api.js          # API communication
│   │   ├── ui.js           # UI controller
│   │   └── results.js      # Results renderer
│   └── assets/
│       └── favicon.svg     # Favicon
└── public/                 # (For deployment)
```

## Configuration

Edit `src/js/config.js` to configure the backend API endpoint:

```javascript
const CONFIG = {
    API_BASE_URL: 'https://api.ataram.uk',  // Your backend URL
    // ...
};
```

## Development

### Local Development

1. Simply open `src/index.html` in your browser
2. Or use a local server:

```bash
# Python
python -m http.server 8000 --directory src

# Node.js (http-server)
npx http-server src -p 8000

# PHP
php -S localhost:8000 -t src
```

3. Open http://localhost:8000 in your browser

### Backend Connection

Make sure the backend API is running and accessible. Update `API_BASE_URL` in `config.js` to point to your backend.

For local development with backend on `localhost:5000`:
- Frontend will auto-detect localhost and use `http://localhost:5000`

## Deployment

### Static Hosting

Deploy to any static hosting service:

**Netlify:**
```bash
# Deploy src/ directory
netlify deploy --dir=src --prod
```

**Vercel:**
```bash
# Deploy src/ directory
vercel --prod src
```

**GitHub Pages:**
```bash
# Copy src/ contents to gh-pages branch or docs/ folder
```

**Nginx:**
```nginx
server {
    listen 80;
    server_name ataram.uk;
    root /var/www/email-analyzer/frontend/src;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

### With SSL (Recommended)

```nginx
server {
    listen 443 ssl http2;
    server_name ataram.uk;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    root /var/www/email-analyzer/frontend/src;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
```

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

## Security Considerations

- All file validation is performed client-side before upload
- API key is sent via POST request (never in URL)
- CORS must be properly configured on backend
- Use HTTPS in production

## Customization

### Theming

Modify CSS variables in `src/css/styles.css`:

```css
:root {
    --color-primary: #3b82f6;
    --bg-primary: #0f172a;
    /* ... */
}
```

### Branding

- Replace `src/assets/favicon.svg` with your logo
- Update header title in `index.html`
- Modify footer content

## License

Copyright © 2024 Ataram Security Platform

## Support

For issues and questions:
- GitHub: https://github.com/ataram/email-analyzer
- Website: https://ataram.uk
